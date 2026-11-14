import { randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { REPORT_SCHEMA, type DetectorCoverage, type Finding, type Indicator, type Mitigation, type Report, type Stage } from "../../contracts/src/index.ts";
import { analyzeMessage, analyzeUrlLexical, indicatorTag, normalizeTarget, type RawIndicator } from "../../fraud-scan/src/index.ts";
import { finding } from "../../fraud-scan/src/rules.ts";
import { POLICY_VERSION, actionsFor, evaluateFraudScan, evaluateRepositoryScan, type RepositoryFinding } from "../../policy/src/index.ts";
import { scanFiles, type SourceFile } from "../../repo-scan/src/index.ts";
import { buildThreatAssessment } from "./threat-model.ts";

/** Everything a scan may know about the caller's workspace. Scanners never see other workspaces. */
export type WorkspaceContext = {
  workspace: string;
  indicatorKey: Uint8Array;
  keyVersion: string;
  /** Earlier sightings and blocklist membership for these tags, within this workspace only. */
  lookup(tags: string[]): Promise<{ seen: Map<string, number>; blocked: Set<string> }>;
  /** Count one sighting of each tag. */
  record(tags: string[]): Promise<void>;
};

/** In-memory context for the CLI, tests and the public demo. */
export function memoryContext(workspace: string, indicatorKey: Uint8Array): WorkspaceContext {
  const seen = new Map<string, number>();
  return {
    workspace,
    indicatorKey,
    keyVersion: "k1",
    async lookup(tags) {
      return { seen: new Map(tags.map((tag) => [tag, seen.get(tag) ?? 0])), blocked: new Set() };
    },
    async record(tags) {
      for (const tag of new Set(tags)) seen.set(tag, (seen.get(tag) ?? 0) + 1);
    },
  };
}

export function newReportId(): string {
  return `rpt_${randomBytes(9).toString("base64url")}`;
}

class Timer {
  stages: Stage[] = [];
  #start = performance.now();
  mark(name: string, status: Stage["status"] = "done") {
    const now = performance.now();
    this.stages.push({ name, ms: Math.round((now - this.#start) * 100) / 100, status });
    this.#start = now;
  }
}

function mitigations(kind: Report["kind"], verdict: Report["verdict"]): Mitigation[] {
  return actionsFor(kind, verdict as never).map((item, index) => ({
    id: `M${index + 1}`,
    ...item,
    status: item.mode === "automatic" ? "applied" : "recommended",
  }));
}

export function runRepositoryScan(files: readonly SourceFile[], label: string, ctx: WorkspaceContext): Report {
  const timer = new Timer();
  timer.mark("intake");
  const output = scanFiles(files);
  timer.mark("detect");
  const complete = output.coverage.every((item) => !item.required || item.status === "ran");
  const verdict = evaluateRepositoryScan(output.findings as unknown as RepositoryFinding[], complete ? "complete" : "incomplete");
  timer.mark("policy");
  const blockers = output.findings.filter((item) => item.category === "secret" && (item.severity === "high" || item.severity === "critical")).length;
  const summary = verdict === "block"
    ? `Blocked: ${blockers} high-severity credential finding(s) in ${output.files} files.`
    : verdict === "incomplete"
      ? `Incomplete: ${output.skipped} file(s) were skipped, so a pass cannot be confirmed.`
      : `Passed: no blocking credentials in ${output.files} files. ${output.findings.length} advisory finding(s).`;
  const threatAssessment = buildThreatAssessment({ kind: "repository", verdict, findings: output.findings, coverage: output.coverage });
  return {
    schema: REPORT_SCHEMA,
    id: newReportId(),
    workspace: ctx.workspace,
    kind: "repository",
    createdAt: new Date().toISOString(),
    scope: { kind: "repository", files: output.files, bytes: output.bytes, skipped: output.skipped, label: label.slice(0, 120) },
    policyVersion: POLICY_VERSION,
    verdict,
    coverage: output.coverage,
    complete,
    findings: output.findings,
    threatAssessment,
    indicators: [],
    mitigations: mitigations("repository", verdict),
    stages: timer.stages,
    summary,
  };
}

/** Convert raw indicators to keyed tags, correlate them inside the workspace, then drop the raw values. */
async function protectIndicators(raw: readonly RawIndicator[], ctx: WorkspaceContext): Promise<{ indicators: Indicator[]; findings: Finding[] }> {
  const indicators: Indicator[] = [];
  const findings: Finding[] = [];
  const items = raw.slice(0, 50).map((item) => ({ item, tag: indicatorTag(ctx.indicatorKey, ctx.keyVersion, item.type, item.normalized) }));
  const tags = items.map((entry) => entry.tag);
  const history = await ctx.lookup(tags);
  await ctx.record(tags);
  for (const { item, tag } of items) {
    const blocked = history.blocked.has(tag);
    const seenBefore = history.seen.get(tag) ?? 0;
    indicators.push({ type: item.type, display: item.display, tag, keyVersion: ctx.keyVersion, seenBefore, blocked });
    if (blocked) {
      findings.push(finding({ ruleId: "intelligence.workspace_blocklist", category: "intelligence", severity: "high", confidence: "high",
        title: `Blocked ${item.type.replace("_", " ")} reappeared`, description: `${item.display} matches an indicator an analyst blocked in this workspace.`,
        impact: "The same infrastructure is being reused against your users.", remediation: "Review this report, keep the indicator blocked, and notify affected recipients through a trusted channel.",
        evidence: [{ label: "Indicator", value: item.display }, { label: "Tag", value: tag }] }));
    } else if (seenBefore >= 2 && item.type !== "amount") {
      findings.push(finding({ ruleId: "intelligence.repeated_indicator", category: "intelligence", severity: "info", confidence: "medium",
        title: `${item.type.replace("_", " ")} seen in ${seenBefore} earlier reports`, description: `${item.display} appeared in ${seenBefore} earlier reports in this workspace.`,
        impact: "Repetition can indicate a campaign. Combined with other findings, it supports blocking the indicator.", remediation: "Review the earlier reports and consider blocking the indicator.",
        evidence: [{ label: "Indicator", value: item.display }, { label: "Tag", value: tag }] }));
    }
  }
  return { indicators, findings };
}

const FRAUD_SUMMARY: Record<string, string> = {
  high_risk: "High risk: the content matches a fraud pattern. Review the evidence and check mitigation outcomes.",
  suspicious: "Suspicious: some signals need a person to verify independently.",
  low_risk: "Low risk: no fraud pattern found in the checks that ran.",
  inconclusive: "Inconclusive: required checks could not run.",
};

export async function runMessageScan(input: { text: string; sender?: string; subject?: string }, ctx: WorkspaceContext): Promise<Report> {
  const timer = new Timer();
  timer.mark("intake");
  const analysis = analyzeMessage(input);
  timer.mark("detect");
  const protectedIndicators = await protectIndicators(analysis.indicators, ctx);
  timer.mark("correlate");
  const findings = [...analysis.findings, ...protectedIndicators.findings];
  const coverage: DetectorCoverage[] = [
    { detector: "social_engineering_cues", status: "ran", detail: `${analysis.cues.length} cue type(s) matched; protective wording ${analysis.protectiveLanguage.length ? "present" : "absent"}.`, required: true },
    { detector: "indicator_extraction", status: "ran", detail: `${protectedIndicators.indicators.length} indicator(s) keyed with HMAC-SHA-256 (${ctx.keyVersion}).`, required: true },
    { detector: "link_lexical", status: "ran", detail: "Links are analysed without being opened.", required: true },
    { detector: "identity_consistency", status: input.sender ? "ran" : "skipped", detail: input.sender ? `Sender domain ${analysis.senderDomain ?? "unparsed"} compared with claimed brands.` : "No sender supplied.", required: false },
    { detector: "workspace_correlation", status: "ran", detail: "Indicator tags matched against this workspace's history and blocklist.", required: true },
  ];
  const verdict = evaluateFraudScan(findings, "complete");
  timer.mark("policy");
  const threatAssessment = buildThreatAssessment({ kind: "message", verdict, findings, coverage });
  return {
    schema: REPORT_SCHEMA,
    id: newReportId(),
    workspace: ctx.workspace,
    kind: "message",
    createdAt: new Date().toISOString(),
    scope: { kind: "message", characters: Math.min(input.text.length + (input.subject?.length ?? 0), 20_000), sender: analysis.senderDomain },
    policyVersion: POLICY_VERSION,
    verdict,
    coverage,
    complete: true,
    findings: sortFindings(findings),
    threatAssessment,
    indicators: protectedIndicators.indicators,
    mitigations: mitigations("message", verdict),
    stages: timer.stages,
    summary: FRAUD_SUMMARY[verdict] ?? verdict,
  };
}

export class ScanInputError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export async function runUrlScan(rawUrl: string, ctx: WorkspaceContext, options: { domainAge?: (domain: string) => Promise<Finding | null> } = {}): Promise<Report> {
  const timer = new Timer();
  const normalized = normalizeTarget(rawUrl);
  if (!normalized.ok) throw new ScanInputError(normalized.code, normalized.message);
  timer.mark("normalize");
  const u = normalized.value;
  const lexical = analyzeUrlLexical(u);
  timer.mark("detect");
  const raw: RawIndicator[] = [{ type: "url", display: u.normalized.slice(0, 120), normalized: u.normalized }];
  if (u.registrableDomain) raw.push({ type: "domain", display: u.registrableDomain, normalized: u.registrableDomain });
  if (u.isIp) raw.push({ type: "ipv4", display: u.hostname, normalized: u.hostname });
  const protectedIndicators = await protectIndicators(raw, ctx);
  timer.mark("correlate");
  const findings = [...lexical, ...protectedIndicators.findings];
  // Optional passive domain intelligence: query the domain's registration age, never the page itself.
  let domainAgeRan = false;
  if (options.domainAge && u.registrableDomain && !u.isIp) {
    const aged = await options.domainAge(u.registrableDomain).catch(() => null);
    domainAgeRan = true;
    if (aged) findings.push(aged);
    timer.mark("intel");
  }
  const coverage: DetectorCoverage[] = [
    { detector: "url_normalization", status: "ran", detail: "Refanged, credentials stripped, IDN decoded.", required: true },
    { detector: "link_lexical", status: "ran", detail: "Brand, homograph, redirect, shortener and hosting rules.", required: true },
    { detector: "workspace_correlation", status: "ran", detail: "Tags matched against this workspace's history and blocklist.", required: true },
    { detector: "domain_age", status: domainAgeRan ? "ran" : "skipped", detail: domainAgeRan ? "Registration age checked via RDAP; the link itself is never opened." : "Passive domain-age intelligence is off on this server.", required: false },
    { detector: "page_inspection", status: "skipped", detail: "TLS and page content are never inspected. SignalWard does not open the link.", required: false },
  ];
  const verdict = evaluateFraudScan(findings, "complete");
  timer.mark("policy");
  const threatAssessment = buildThreatAssessment({ kind: "url", verdict, findings, coverage });
  return {
    schema: REPORT_SCHEMA,
    id: newReportId(),
    workspace: ctx.workspace,
    kind: "url",
    createdAt: new Date().toISOString(),
    scope: { kind: "url", normalized: u.normalized.slice(0, 2048), registrableDomain: u.registrableDomain },
    policyVersion: POLICY_VERSION,
    verdict,
    coverage,
    complete: true,
    findings: sortFindings(findings),
    threatAssessment,
    indicators: protectedIndicators.indicators,
    mitigations: mitigations("url", verdict),
    stages: timer.stages,
    summary: FRAUD_SUMMARY[verdict] ?? verdict,
  };
}

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
function sortFindings(findings: Finding[]): Finding[] {
  const unique = new Map(findings.map((item) => [item.id, item]));
  return [...unique.values()].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}

/** Primary action recorded in the receipt: the first automatic mitigation, or the first recommendation. */
export function primaryAction(report: Report): string {
  return (report.mitigations.find((item) => item.mode === "automatic") ?? report.mitigations[0])?.action ?? "none";
}

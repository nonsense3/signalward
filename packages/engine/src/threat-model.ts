import type { DetectorCoverage, Finding, Report, ThreatAssessment, ThreatScenario } from "../../contracts/src/index.ts";

type ScenarioTemplate = Pick<ThreatScenario, "actor" | "targetAsset" | "attackPath" | "preconditions" | "impact" | "residualRisk">;

function template(kind: Report["kind"], finding: Finding): ScenarioTemplate {
  const id = finding.ruleId.toLowerCase();
  if (finding.category === "secret") return {
    actor: "External attacker or repository reader",
    targetAsset: "Credential and the systems it authorizes",
    attackPath: "Obtain a committed credential, then use it to access or alter the associated service and data.",
    preconditions: "The detected value is a live credential and the repository is accessible to the attacker.",
    impact: "critical",
    residualRisk: "Detection does not revoke the credential or remove its copies from repository history. Rotate it and audit use.",
  };
  if (finding.category === "dependency") return {
    actor: "Malicious package publisher or supply-chain attacker",
    targetAsset: "Application runtime, build workers, and secrets available to them",
    attackPath: "Exploit or execute an affected dependency during installation or runtime to run code in the project context.",
    preconditions: "The project installs or executes the affected package version in a reachable context.",
    impact: "high",
    residualRisk: "The advisory database is a pinned subset and may miss vulnerabilities. Upgrade and validate against current vendor advisories.",
  };
  if (finding.category === "configuration") return {
    actor: "Untrusted contributor or attacker controlling an external build input",
    targetAsset: "CI runner, repository write permissions, deployment credentials, and build secrets",
    attackPath: "Supply crafted event content or code that reaches a privileged workflow step and executes with its token or secrets.",
    preconditions: "The flagged workflow is reachable by an untrusted event and grants the affected step meaningful privileges.",
    impact: "high",
    residualRisk: "Static workflow analysis cannot establish runtime reachability or effective permissions for every expression. Review the workflow and reduce token scope.",
  };
  if (id.includes("credential") || id.includes("otp") || id.includes("password") || id.includes("secret")) return {
    actor: "Impersonator or social engineer",
    targetAsset: "Recipient credentials, one-time codes, or account recovery factors",
    attackPath: "Persuade a recipient to disclose an authentication factor through a deceptive message or linked page.",
    preconditions: "A recipient trusts the sender or follows the requested action without independent verification.",
    impact: "high",
    residualRisk: "Text rules can miss novel wording and cannot prevent disclosure. Verify through a known-good channel; never share codes.",
  };
  if (finding.category === "redirect") return {
    actor: "Phisher abusing a redirector or shortened link",
    targetAsset: "Recipient browser session and credentials",
    attackPath: "Use a trusted-looking or opaque link to redirect the recipient to attacker-controlled content.",
    preconditions: "The recipient follows the link and the redirect destination remains attacker-controlled.",
    impact: "high",
    residualRisk: "The submitted URL is not opened, so the final destination and current behavior are not confirmed. Verify destination through a trusted channel.",
  };
  if (finding.category === "phishing" || finding.category === "domain") return {
    actor: "Phisher or brand impersonator",
    targetAsset: "Recipient trust, credentials, payment, or personal information",
    attackPath: "Use deceptive language, domain resemblance, or a misleading hostname to induce a sensitive action.",
    preconditions: "The recipient relies on the claimed brand or visible link text instead of independently checking the destination.",
    impact: "high",
    residualRisk: "Lexical and brand rules are heuristic; no live DNS, TLS, page, or sender-authentication checks run. Confirm with the organization directly.",
  };
  if (finding.category === "intelligence") return {
    actor: "Repeat fraud operator reusing known infrastructure",
    targetAsset: "Workspace users and their financial or account data",
    attackPath: "Reuse an indicator previously observed or blocked in this workspace to reach another user.",
    preconditions: "The indicator was captured earlier in the same workspace and remains associated with the campaign.",
    impact: "medium",
    residualRisk: "Correlation is workspace-local and depends on prior sightings; it does not establish global reputation or attribution.",
  };
  return kind === "repository" ? {
    actor: "Attacker exploiting an unreviewed code or configuration weakness",
    targetAsset: "Repository, build pipeline, or deployed application",
    attackPath: "Exploit the reported weakness after code is merged or deployed.",
    preconditions: "The finding is exploitable in the target environment and reaches a sensitive asset.",
    impact: "medium",
    residualRisk: "Static analysis cannot prove exploitability or runtime exposure. Validate the finding in context and apply its remediation.",
  } : {
    actor: "Fraud operator targeting a recipient",
    targetAsset: "Recipient identity, account, payment, or personal information",
    attackPath: "Use deceptive content or infrastructure to persuade the recipient to disclose data or transfer value.",
    preconditions: "The recipient interacts with the content and the request is actionable.",
    impact: "medium",
    residualRisk: "Heuristic analysis cannot establish sender intent or destination behavior. Verify important requests independently.",
  };
}

function controlsFor(finding: Finding, coverage: readonly DetectorCoverage[]): string[] {
  const controls = new Set<string>();
  const rule = finding.ruleId.toLowerCase();
  if (rule.startsWith("secret.")) controls.add("Repository secret-pattern scanning");
  if (rule.startsWith("dependency.")) controls.add("Pinned dependency advisory matching");
  if (rule.startsWith("ci.")) controls.add("Static CI/CD workflow checks");
  if (rule.startsWith("url.") || finding.category === "domain" || finding.category === "redirect") controls.add("URL normalization and lexical analysis without fetching the target");
  if (["message", "phishing", "intelligence"].includes(finding.category)) controls.add("Deterministic message rules and workspace-scoped indicator correlation");
  for (const item of coverage) {
    if (item.status !== "ran") controls.add(`${item.detector.replace(/_/g, " ")} coverage is ${item.status}: ${item.detail}`);
  }
  return [...controls];
}

function signalFor(finding: Finding): ThreatScenario["signal"] {
  if (finding.severity === "critical" || finding.severity === "high" && finding.confidence !== "low") return "high";
  if (finding.severity === "high" || finding.severity === "medium") return "medium";
  if (finding.severity === "low") return "low";
  return "none";
}

export function buildThreatAssessment(input: {
  kind: Report["kind"];
  verdict: Report["verdict"];
  findings: readonly Finding[];
  coverage: readonly DetectorCoverage[];
}): ThreatAssessment {
  const { kind, verdict, findings, coverage } = input;
  const relevant = [...findings].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return rank[a.severity] - rank[b.severity];
  }).slice(0, 12);
  const limitations = coverage.filter((item) => item.status !== "ran").map((item) => `${item.detector.replace(/_/g, " ")}: ${item.detail}`);
  if (!limitations.length) limitations.push("No skipped required detector was reported; rule-based analysis still cannot prove that unobserved threats are absent.");
  const scenarios: ThreatScenario[] = relevant.map((finding, index) => {
    const details = template(kind, finding);
    return {
      id: `T${index + 1}`,
      ...details,
      signal: signalFor(finding),
      confidence: finding.confidence,
      controls: controlsFor(finding, coverage),
      findingIds: [finding.id],
    };
  });
  if (!scenarios.length) {
    const sample: Finding = {
      id: "unobserved", ruleId: "baseline.unobserved", category: kind === "repository" ? "configuration" : "phishing",
      severity: "info", confidence: "low", title: "No matching finding", description: "No scenario matched the configured rules.",
      impact: "A rule-based scan cannot establish that the input is safe.", remediation: "Review coverage and verify high-impact actions independently.", evidence: [],
    };
    const details = template(kind, sample);
    scenarios.push({
      id: "T1", ...details, signal: "none", confidence: "low", findingIds: [],
      controls: ["Configured deterministic rules ran", "No matching finding was produced"],
    });
  }
  return {
    method: "deterministic-scenarios-v1",
    scope: `${kind} scan; verdict ${verdict}; scenarios are derived from up to ${relevant.length} highest-severity findings. Signal strength is evidence strength, not a probability estimate.`,
    coverageLimitations: limitations,
    scenarios,
  };
}

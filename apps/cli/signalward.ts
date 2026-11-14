#!/usr/bin/env node
/**
 * SignalWard CLI. Uses the same engine, policy and receipts as the web API.
 *   node apps/cli/signalward.ts scan <path> [--json] [--out <dir>]
 *   node apps/cli/signalward.ts url <link> [--json]
 *   node apps/cli/signalward.ts verify <receipt.json> [--report <report.json>] [--keys <keys.json>]
 *   node apps/cli/signalward.ts keys       print fresh values for SignalWard secrets
 *   node apps/cli/signalward.ts keys rotate # rotate receipt key and retain old public keys
 *   node apps/cli/signalward.ts keys rotate-indicators # rotate indicator key with overlap history
 *   node apps/cli/signalward.ts doctor     validate .env and test Supabase and Gemini connectivity
 * Exit codes: 0 pass or valid, 1 block or invalid, 2 incomplete, usage or runtime error.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { watch as watchFs, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Report } from "../../packages/contracts/src/index.ts";
import { ScanInputError, memoryContext, primaryAction, runRepositoryScan, runUrlScan } from "../../packages/engine/src/index.ts";
import { issueReceipt, loadSigningKey, parseTrustedKeyHistory, trustedKeySet, verifyReceipt, type TrustedKey } from "../../packages/receipts/src/index.ts";
import { isIgnoredPath, readDirectory } from "../../packages/repo-scan/src/index.ts";
import { fetchRepository } from "../../packages/repo-fetch/src/index.ts";
import { domainAgeFinding } from "../../packages/url-intel/src/index.ts";
import { ConfigError, loadEnvFile, readConfig } from "../web/src/env.ts";
import { parseIndicatorKeyHistory, parseReportEncryptionKeyHistory, resolveSecret } from "../web/src/security.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));
const env = loadEnvFile(join(root, ".env"));
const stateDir = env.SIGNALWARD_STATE_DIR || join(root, ".signalward");
const urlIntel = env.URL_INTEL !== "off";
const args = process.argv.slice(2);
const command = args[0];
const flag = (name: string) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const has = (name: string) => args.includes(name);
const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string) => (color ? `\u001b[${code}m${text}\u001b[0m` : text);
const SEVERITY_COLOR: Record<string, string> = { critical: "91", high: "31", medium: "33", low: "35", info: "90" };
const signingKey = () => loadSigningKey(stateDir, env.SIGNALWARD_SIGNING_KEY ? { SIGNALWARD_SIGNING_KEY: env.SIGNALWARD_SIGNING_KEY } : {});
const previousSigningKeys = () => parseTrustedKeyHistory(env.SIGNALWARD_PREVIOUS_SIGNING_KEYS);

function printReport(report: Report) {
  console.log(`${paint("1", "SignalWard")} ${report.kind} ${report.id}  ${report.policyVersion}`);
  for (const item of report.coverage) console.log(`  ${paint("90", item.status.padEnd(8))} ${item.detector.padEnd(24)} ${paint("90", item.detail)}`);
  console.log("");
  for (const finding of report.findings) {
    const where = finding.location ? `${finding.location.path}:${finding.location.line}` : finding.category;
    console.log(`  ${paint(SEVERITY_COLOR[finding.severity] ?? "0", finding.severity.toUpperCase().padEnd(9))}${finding.title}`);
    console.log(`  ${" ".repeat(9)}${paint("90", `${where}  ${finding.id}`)}`);
    if (finding.evidence[0]) console.log(`  ${" ".repeat(9)}${paint("90", finding.evidence[0].value)}`);
  }
  if (!report.findings.length) console.log("  No findings.");
  console.log(`\n  ${paint("1", report.verdict.toUpperCase())}  ${report.summary}`);
  for (const mitigation of report.mitigations) console.log(`  ${paint("90", `[${mitigation.status ?? mitigation.mode}]`)} ${mitigation.action}: ${mitigation.detail}`);
}

function emit(report: Report): void {
  const key = signingKey();
  const receipt = issueReceipt(report, primaryAction(report), key);
  const out = flag("--out");
  if (out) {
    mkdirSync(out, { recursive: true });
    writeFileSync(join(out, `${report.id}.report.json`), JSON.stringify(report, null, 2));
    writeFileSync(join(out, `${report.id}.receipt.json`), JSON.stringify(receipt, null, 2));
    writeFileSync(join(out, "signalward-keys.json"), JSON.stringify(trustedKeySet(key, previousSigningKeys()), null, 2));
  }
  if (has("--json")) console.log(JSON.stringify({ report, receipt }, null, 2));
  else {
    printReport(report);
    console.log(`  ${paint("90", `receipt signed by ${key.keyId}${out ? `, written to ${out}` : ""}`)}`);
  }
}

async function doctor(): Promise<number> {
  let config;
  try {
    config = readConfig(env, { stateDir });
  } catch (error) {
    if (error instanceof ConfigError) {
      console.log(paint("31", "Configuration has problems:"));
      for (const problem of error.problems) console.log(`  ${paint("31", "✕")} ${problem}`);
      return 1;
    }
    throw error;
  }
  const line = (ok: boolean | null, label: string, detail: string) => console.log(`  ${ok === null ? paint("33", "•") : ok ? paint("32", "✓") : paint("31", "✕")} ${label.padEnd(16)} ${detail}`);
  console.log(paint("1", "SignalWard configuration"));
  line(true, "environment", `${config.nodeEnv}, ${config.host}:${config.port ?? "3000 (auto)"}`);
  for (const [name, value] of Object.entries(config.secrets)) line(value ? true : null, `${name} secret`, value ? "set" : "empty, development value under .signalward/");
  if (config.auth.supabase) {
    try {
      const response = await fetch(new URL("/auth/v1/settings", config.auth.supabase.url), { headers: { apikey: config.auth.supabase.anonKey }, signal: AbortSignal.timeout(8000) });
      line(response.ok, "supabase auth", response.ok ? `reachable at ${new URL(config.auth.supabase.url).host}` : `HTTP ${response.status}; check SUPABASE_ANON_KEY`);
      const tables = await fetch(new URL("/rest/v1/reports?select=id,payload_encrypted&limit=0", config.auth.supabase.url), { headers: { apikey: config.auth.supabase.anonKey }, signal: AbortSignal.timeout(8000) });
      const body = tables.ok ? null : ((await tables.json().catch(() => ({}))) as { code?: string });
      const missing = body?.code === "42P01" || body?.code === "PGRST205";
      line(!missing && tables.ok, "supabase tables", missing ? "missing; run every migration in supabase/migrations/" : !tables.ok ? "schema outdated; run every migration in supabase/migrations/" : "present");
    } catch {
      line(false, "supabase auth", "unreachable; check SUPABASE_URL and your network");
    }
  } else line(null, "auth", "local accounts (Supabase not configured)");
  if (config.ai.apiKey) {
    try {
      const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${config.ai.model}`, { headers: { "x-goog-api-key": config.ai.apiKey }, signal: AbortSignal.timeout(8000) });
      line(response.ok, "summaries", response.ok ? `${config.ai.model} available` : `HTTP ${response.status}; check GEMINI_API_KEY and GEMINI_MODEL`);
    } catch {
      line(false, "summaries", "model endpoint unreachable");
    }
  } else line(null, "summaries", "rules only (GEMINI_API_KEY empty)");
  for (const warning of config.warnings) console.log(`  ${paint("90", `note: ${warning}`)}`);
  return 0;
}

async function watchRepository(rootDir: string): Promise<number> {
  let scanning = false;
  let rerun = false;
  let timer: NodeJS.Timeout | null = null;
  let watcher: ReturnType<typeof watchFs>;
  const schedule = () => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => void scan(), 500);
  };
  const scan = async () => {
    if (scanning) {
      rerun = true;
      return;
    }
    scanning = true;
    try {
      const { files, skipped } = await readDirectory(rootDir);
      const report = runRepositoryScan(files, basename(rootDir), memoryContext("local_cli", randomBytes(32)));
      if (skipped && report.scope.kind === "repository") report.scope.skipped += skipped;
      console.log(`\n[${new Date().toLocaleTimeString()}] Repository scan result:`);
      emit(report);
    } catch (error) {
      console.error(`SignalWard watch scan failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      scanning = false;
      if (rerun) {
        rerun = false;
        schedule();
      }
    }
  };

  watcher = watchFs(rootDir, { recursive: true }, (_event, filename) => {
    const changed = filename === null ? "" : String(filename).replace(/\\/g, "/");
    if (changed && isIgnoredPath(changed)) return;
    schedule();
  });
  watcher.on("error", (error) => console.error(`SignalWard watcher error: ${error.message}`));
  console.log(`Watching ${rootDir} for repository changes. Press Ctrl+C to stop.`);
  await scan();
  return new Promise((resolve) => {
    const stop = () => {
      if (timer) clearTimeout(timer);
      watcher.close();
      process.off("SIGTERM", stop);
      resolve(0);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
  });
}

/**
 * Minimal Model Context Protocol server over stdio (newline-delimited JSON-RPC 2.0). It exposes the
 * same scanners to an MCP-capable terminal or agent. Protocol messages go to stdout; logs to stderr.
 */
function mcpServe(): Promise<number> {
  const key = signingKey();
  const send = (message: unknown) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const note = (text: string) => process.stderr.write(`[signalward-mcp] ${text}\n`);
  const tools = [
    { name: "scan_url", description: "Analyse a link or domain without opening it. Returns a signed verdict.", inputSchema: { type: "object", properties: { url: { type: "string", description: "Link or domain to inspect." } }, required: ["url"] } },
    { name: "scan_repository", description: "Scan a Git repository by URL for secrets, vulnerable dependencies and risky CI.", inputSchema: { type: "object", properties: { url: { type: "string", description: "github.com/owner/repo or a full URL." }, ref: { type: "string", description: "Branch or tag (optional)." }, token: { type: "string", description: "GitHub token for a private repo (optional)." } }, required: ["url"] } },
    { name: "verify_receipt", description: "Verify a SignalWard receipt against the trusted key set.", inputSchema: { type: "object", properties: { receipt: { type: "object" }, report: { type: "object" } }, required: ["receipt"] } },
  ];

  function summarise(report: Report): string {
    const receipt = issueReceipt(report, primaryAction(report), key);
    return JSON.stringify({
      id: report.id, kind: report.kind, verdict: report.verdict, summary: report.summary,
      findings: report.findings.map((item) => ({ severity: item.severity, ruleId: item.ruleId, title: item.title, location: item.location ?? null })),
      indicators: report.indicators.map((item) => ({ type: item.type, display: item.display })),
      receipt: { digest: receipt.payload.reportDigest, keyId: receipt.payload.keyId, signature: receipt.signature },
    }, null, 2);
  }

  async function callTool(name: string, input: Record<string, unknown>): Promise<string> {
    const ctx = memoryContext("mcp", randomBytes(32));
    if (name === "scan_url") {
      return summarise(await runUrlScan(String(input.url ?? ""), ctx, urlIntel ? { domainAge: (domain) => domainAgeFinding(domain) } : {}));
    }
    if (name === "scan_repository") {
      const fetched = await fetchRepository(String(input.url ?? ""), { ...(input.ref ? { ref: String(input.ref) } : {}), ...(input.token ? { token: String(input.token) } : {}) });
      return summarise(runRepositoryScan(fetched.files, fetched.label, ctx));
    }
    if (name === "verify_receipt") {
      return JSON.stringify(verifyReceipt(input.receipt, trustedKeySet(key, previousSigningKeys()).keys, input.report), null, 2);
    }
    throw new Error(`Unknown tool: ${name}`);
  }

  async function handle(message: { id?: unknown; method?: string; params?: Record<string, unknown> }): Promise<void> {
    const { id, method, params } = message;
    if (method === "initialize") {
      return send({ jsonrpc: "2.0", id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "signalward", version: "0.2.0" } } });
    }
    if (method === "tools/list") return send({ jsonrpc: "2.0", id, result: { tools } });
    if (method === "ping") return send({ jsonrpc: "2.0", id, result: {} });
    if (method === "notifications/initialized" || method?.startsWith("notifications/")) return;
    if (method === "tools/call") {
      const name = String(params?.name ?? "");
      const input = (params?.arguments as Record<string, unknown>) ?? {};
      try {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: await callTool(name, input) }] } });
      } catch (error) {
        send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text: `Error: ${error instanceof Error ? error.message : String(error)}` }], isError: true } });
      }
      return;
    }
    if (id !== undefined && id !== null) send({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
  }

  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    let index: number;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index).trim();
      buffer = buffer.slice(index + 1);
      if (!line) continue;
      try {
        void handle(JSON.parse(line));
      } catch {
        note("ignored a malformed JSON-RPC line");
      }
    }
  });
  note(`ready on stdio with ${tools.length} tools (signing key ${key.keyId})`);
  return new Promise(() => {}); // run until the client closes the pipe
}

async function main(): Promise<number> {
  if (command === "scan") {
    const target = args[1] && !args[1].startsWith("--") ? args[1] : ".";
    const ctx = memoryContext("local_cli", randomBytes(32));
    let report: Report;
    if (/^https?:\/\//i.test(target) || /^[\w.-]+\/[\w.-]+$/.test(target)) {
      const token = flag("--token") ?? env.GITHUB_TOKEN ?? env.SIGNALWARD_GITHUB_TOKEN;
      const fetched = await fetchRepository(target, { ...(flag("--ref") ? { ref: flag("--ref")! } : {}), ...(token ? { token } : {}) });
      report = runRepositoryScan(fetched.files, fetched.label, ctx);
    } else {
      const rootDir = resolve(target);
      const { files, skipped } = await readDirectory(rootDir);
      report = runRepositoryScan(files, basename(rootDir), ctx);
      if (skipped && report.scope.kind === "repository") report.scope.skipped += skipped;
    }
    emit(report);
    return report.verdict === "pass" ? 0 : report.verdict === "block" ? 1 : 2;
  }
  if (command === "watch") {
    const target = args[1] && !args[1].startsWith("--") ? args[1] : ".";
    return watchRepository(resolve(target));
  }
  if (command === "url") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a link: signalward url <link>");
    const report = await runUrlScan(args[1], memoryContext("local_cli", randomBytes(32)), urlIntel ? { domainAge: (domain) => domainAgeFinding(domain) } : {});
    emit(report);
    return report.verdict === "high_risk" ? 1 : report.verdict === "low_risk" ? 0 : 2;
  }
  if (command === "mcp") return mcpServe();
  if (command === "verify") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a receipt: signalward verify <receipt.json>");
    const receipt = JSON.parse(readFileSync(args[1], "utf8"));
    const reportPath = flag("--report");
    const keysPath = flag("--keys");
    const keys: TrustedKey[] = keysPath ? JSON.parse(readFileSync(keysPath, "utf8")).keys : trustedKeySet(signingKey(), previousSigningKeys()).keys;
    const result = verifyReceipt(receipt, keys, reportPath ? JSON.parse(readFileSync(reportPath, "utf8")) : undefined);
    for (const check of result.checks) console.log(`  ${check.ok ? paint("32", "✓") : paint("31", "✕")} ${check.check.padEnd(14)} ${check.detail}`);
    console.log(result.valid ? paint("32", "\n  Receipt is valid.") : paint("31", "\n  Receipt is NOT valid."));
    return result.valid ? 0 : 1;
  }
  if (command === "keys") {
    if (args[1] === "rotate-reports") {
      const currentKey = env.SIGNALWARD_REPORT_ENCRYPTION_KEY
        ? Buffer.from(env.SIGNALWARD_REPORT_ENCRYPTION_KEY, "base64")
        : resolveSecret(null, stateDir, "report-encryption-key");
      if (currentKey.length !== 32) throw new Error("The active report-encryption key must be exactly 32 bytes.");
      const retained = parseReportEncryptionKeyHistory(env.SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS);
      if (retained.some((key) => key.equals(currentKey))) throw new Error("The active report-encryption key is already present in previous-key history.");
      if (retained.length >= 3) throw new Error("Three previous report-encryption keys are already retained. Retire an old key only after every report encrypted with it has been re-encrypted or deleted.");
      const history = Buffer.from(JSON.stringify({ keys: [currentKey, ...retained].map((key) => key.toString("base64")) })).toString("base64url");
      console.log("# Deploy both values together. Previous keys are secrets and must stay in your secret manager.");
      console.log("# Keep each old key until reports encrypted with it have been re-encrypted or deleted.");
      console.log(`SIGNALWARD_REPORT_ENCRYPTION_KEY=${randomBytes(32).toString("base64")}`);
      console.log(`SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS=${history}`);
      return 0;
    }
    if (args[1] === "rotate-indicators") {
      const currentVersion = env.SIGNALWARD_INDICATOR_KEY_VERSION || "k1";
      if (!/^k\d{1,6}$/.test(currentVersion)) throw new Error("SIGNALWARD_INDICATOR_KEY_VERSION must look like k1.");
      const currentKey = env.SIGNALWARD_INDICATOR_KEY
        ? Buffer.from(env.SIGNALWARD_INDICATOR_KEY, "base64")
        : resolveSecret(null, stateDir, "indicator-master");
      if (currentKey.length !== 32) throw new Error("The active indicator key must be exactly 32 bytes.");
      const retained = parseIndicatorKeyHistory(env.SIGNALWARD_PREVIOUS_INDICATOR_KEYS).filter((item) => item.version !== currentVersion);
      if (retained.length >= 3) throw new Error("Three previous indicator keys are already retained. Retire a previous key only after its historical sightings and blocklist entries are no longer needed.");
      const versions = [currentVersion, ...retained.map((item) => item.version)].map((version) => Number(version.slice(1)));
      const nextVersion = `k${Math.max(...versions) + 1}`;
      if (!/^k\d{1,6}$/.test(nextVersion)) throw new Error("Indicator key version space is exhausted; retire old version labels before rotating.");
      const previous = [{ version: currentVersion, key: currentKey }, ...retained];
      const history = Buffer.from(JSON.stringify({ keys: previous.map(({ version, key }) => ({ version, key: key.toString("base64") })) })).toString("base64url");
      console.log("# Deploy all three values together. Previous keys are secrets and must stay in your secret manager.");
      console.log("# Keep previous keys configured so old sightings and blocklist tags continue to match.");
      console.log(`SIGNALWARD_INDICATOR_KEY=${randomBytes(32).toString("base64")}`);
      console.log(`SIGNALWARD_INDICATOR_KEY_VERSION=${nextVersion}`);
      console.log(`SIGNALWARD_PREVIOUS_INDICATOR_KEYS=${history}`);
      return 0;
    }
    if (args[1] === "rotate") {
      const current = trustedKeySet(signingKey()).keys[0]!;
      const previous = [current, ...previousSigningKeys().filter((key) => key.kid !== current.kid)];
      if (previous.length > 32) throw new Error("Key history already contains 32 keys. Archive retired public keys before rotating again.");
      const { privateKey } = generateKeyPairSync("ed25519");
      const history = Buffer.from(JSON.stringify({ keys: previous })).toString("base64url");
      console.log("# Replace SIGNALWARD_SIGNING_KEY with the new private key and retain the old public keys below.");
      console.log("# Keep SIGNALWARD_PREVIOUS_SIGNING_KEYS configured until receipts signed by those keys no longer need verification.");
      console.log(`SIGNALWARD_SIGNING_KEY=${privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")}`);
      console.log(`SIGNALWARD_PREVIOUS_SIGNING_KEYS=${history}`);
      return 0;
    }
    const { privateKey } = generateKeyPairSync("ed25519");
    console.log("# Paste into .env. Store production values in your secret manager, not in Git.");
    console.log(`SIGNALWARD_SESSION_SECRET=${randomBytes(32).toString("base64")}`);
    console.log(`SIGNALWARD_INDICATOR_KEY=${randomBytes(32).toString("base64")}`);
    console.log(`SIGNALWARD_REPORT_ENCRYPTION_KEY=${randomBytes(32).toString("base64")}`);
    console.log(`SIGNALWARD_SIGNING_KEY=${privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")}`);
    return 0;
  }
  if (command === "doctor") return doctor();
  console.error("Usage:\n  signalward scan <path|repo-url> [--ref <branch>] [--token <gh>] [--json] [--out <dir>]\n  signalward watch <path>\n  signalward url <link>\n  signalward verify <receipt.json> [--report <report.json>] [--keys <keys.json>]\n  signalward mcp\n  signalward keys [rotate|rotate-indicators|rotate-reports]\n  signalward doctor");
  return 2;
}

main().then(
  (code) => { process.exitCode = code; },
  (error) => {
    console.error(`signalward: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  },
);

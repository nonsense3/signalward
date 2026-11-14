#!/usr/bin/env node
/**
 * SignalWard CLI. Uses the same engine, policy and receipts as the web API.
 *   node apps/cli/signalward.ts scan <path> [--json] [--out <dir>]
 *   node apps/cli/signalward.ts url <link> [--json]
 *   node apps/cli/signalward.ts verify <receipt.json> [--report <report.json>] [--keys <keys.json>]
 *   node apps/cli/signalward.ts keys       print fresh values for the three SignalWard secrets
 *   node apps/cli/signalward.ts doctor     validate .env and test Supabase and Gemini connectivity
 * Exit codes: 0 pass or valid, 1 block or invalid, 2 incomplete, usage or runtime error.
 */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Report } from "../../packages/contracts/src/index.ts";
import { ScanInputError, memoryContext, primaryAction, runRepositoryScan, runUrlScan } from "../../packages/engine/src/index.ts";
import { issueReceipt, loadSigningKey, trustedKeySet, verifyReceipt, type TrustedKey } from "../../packages/receipts/src/index.ts";
import { readDirectory } from "../../packages/repo-scan/src/index.ts";
import { ConfigError, loadEnvFile, readConfig } from "../web/src/env.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));
const env = loadEnvFile(join(root, ".env"));
const stateDir = env.SIGNALWARD_STATE_DIR || join(root, ".signalward");
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
    writeFileSync(join(out, "signalward-keys.json"), JSON.stringify(trustedKeySet(key), null, 2));
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
      const tables = await fetch(new URL("/rest/v1/reports?select=id&limit=0", config.auth.supabase.url), { headers: { apikey: config.auth.supabase.anonKey }, signal: AbortSignal.timeout(8000) });
      const body = tables.ok ? null : ((await tables.json().catch(() => ({}))) as { code?: string });
      const missing = body?.code === "42P01" || body?.code === "PGRST205";
      line(!missing, "supabase tables", missing ? "missing; run supabase/migrations/20261114000000_signalward.sql" : "present");
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

async function main(): Promise<number> {
  if (command === "scan") {
    const target = args[1] && !args[1].startsWith("--") ? args[1] : ".";
    const rootDir = resolve(target);
    const { files, skipped } = await readDirectory(rootDir);
    const report = runRepositoryScan(files, basename(rootDir), memoryContext("local_cli", randomBytes(32)));
    if (skipped && report.scope.kind === "repository") report.scope.skipped += skipped;
    emit(report);
    return report.verdict === "pass" ? 0 : report.verdict === "block" ? 1 : 2;
  }
  if (command === "url") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a link: signalward url <link>");
    const report = await runUrlScan(args[1], memoryContext("local_cli", randomBytes(32)));
    emit(report);
    return report.verdict === "high_risk" ? 1 : report.verdict === "low_risk" ? 0 : 2;
  }
  if (command === "verify") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a receipt: signalward verify <receipt.json>");
    const receipt = JSON.parse(readFileSync(args[1], "utf8"));
    const reportPath = flag("--report");
    const keysPath = flag("--keys");
    const keys: TrustedKey[] = keysPath ? JSON.parse(readFileSync(keysPath, "utf8")).keys : trustedKeySet(signingKey()).keys;
    const result = verifyReceipt(receipt, keys, reportPath ? JSON.parse(readFileSync(reportPath, "utf8")) : undefined);
    for (const check of result.checks) console.log(`  ${check.ok ? paint("32", "✓") : paint("31", "✕")} ${check.check.padEnd(14)} ${check.detail}`);
    console.log(result.valid ? paint("32", "\n  Receipt is valid.") : paint("31", "\n  Receipt is NOT valid."));
    return result.valid ? 0 : 1;
  }
  if (command === "keys") {
    const { privateKey } = generateKeyPairSync("ed25519");
    console.log("# Paste into .env. Store production values in your secret manager, not in Git.");
    console.log(`SIGNALWARD_SESSION_SECRET=${randomBytes(32).toString("base64")}`);
    console.log(`SIGNALWARD_INDICATOR_KEY=${randomBytes(32).toString("base64")}`);
    console.log(`SIGNALWARD_SIGNING_KEY=${privateKey.export({ format: "der", type: "pkcs8" }).toString("base64")}`);
    return 0;
  }
  if (command === "doctor") return doctor();
  console.error("Usage:\n  signalward scan <path> [--json] [--out <dir>]\n  signalward url <link>\n  signalward verify <receipt.json> [--report <report.json>] [--keys <keys.json>]\n  signalward keys\n  signalward doctor");
  return 2;
}

main().then(
  (code) => { process.exitCode = code; },
  (error) => {
    console.error(`signalward: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  },
);

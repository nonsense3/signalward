#!/usr/bin/env node
/**
 * SignalWard CLI. Uses the same engine, policy and receipts as the web API.
 *   node apps/cli/signalward.ts scan <path> [--json] [--out <dir>]
 *   node apps/cli/signalward.ts url <link>
 *   node apps/cli/signalward.ts verify <receipt.json> [--report <report.json>] [--keys <keys.json>]
 * Exit codes: 0 pass or valid, 1 block or invalid, 2 incomplete, usage or runtime error.
 */
import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Report } from "../../packages/contracts/src/index.ts";
import { ScanInputError, primaryAction, runRepositoryScan, runUrlScan, type WorkspaceContext } from "../../packages/engine/src/index.ts";
import { issueReceipt, loadSigningKey, trustedKeySet, verifyReceipt, type TrustedKey } from "../../packages/receipts/src/index.ts";
import { readDirectory } from "../../packages/repo-scan/src/index.ts";

const stateDir = process.env.SIGNALWARD_STATE_DIR ?? fileURLToPath(new URL("../../.signalward/", import.meta.url));
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

function localContext(): WorkspaceContext {
  const seen = new Map<string, number>();
  return {
    workspace: "ws_local_cli",
    indicatorKey: randomBytes(32),
    keyVersion: "k1",
    observe(tag) {
      const count = seen.get(tag) ?? 0;
      seen.set(tag, count + 1);
      return count;
    },
    isBlocked: () => false,
  };
}

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
  for (const mitigation of report.mitigations) console.log(`  ${paint("90", `[${mitigation.mode}]`)} ${mitigation.action}: ${mitigation.detail}`);
}

function emit(report: Report): void {
  const key = loadSigningKey(stateDir);
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

async function main(): Promise<number> {
  if (command === "scan") {
    const target = args[1] && !args[1].startsWith("--") ? args[1] : ".";
    const root = resolve(target);
    const { files, skipped } = await readDirectory(root);
    const report = runRepositoryScan(files, basename(root), localContext());
    if (skipped && report.scope.kind === "repository") report.scope.skipped += skipped;
    emit(report);
    return report.verdict === "pass" ? 0 : report.verdict === "block" ? 1 : 2;
  }
  if (command === "url") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a link: signalward url <link>");
    const report = runUrlScan(args[1], localContext());
    emit(report);
    return report.verdict === "high_risk" ? 1 : report.verdict === "low_risk" ? 0 : 2;
  }
  if (command === "verify") {
    if (!args[1]) throw new ScanInputError("USAGE", "Pass a receipt: signalward verify <receipt.json>");
    const receipt = JSON.parse(readFileSync(args[1], "utf8"));
    const reportPath = flag("--report");
    const keysPath = flag("--keys");
    const keys: TrustedKey[] = keysPath ? JSON.parse(readFileSync(keysPath, "utf8")).keys : trustedKeySet(loadSigningKey(stateDir)).keys;
    const result = verifyReceipt(receipt, keys, reportPath ? JSON.parse(readFileSync(reportPath, "utf8")) : undefined);
    for (const check of result.checks) console.log(`  ${check.ok ? paint("32", "✓") : paint("31", "✕")} ${check.check.padEnd(14)} ${check.detail}`);
    console.log(result.valid ? paint("32", "\n  Receipt is valid.") : paint("31", "\n  Receipt is NOT valid."));
    return result.valid ? 0 : 1;
  }
  console.error("Usage:\n  signalward scan <path> [--json] [--out <dir>]\n  signalward url <link>\n  signalward verify <receipt.json> [--report <report.json>] [--keys <keys.json>]");
  return 2;
}

main().then(
  (code) => { process.exitCode = code; },
  (error) => {
    console.error(`signalward: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 2;
  },
);

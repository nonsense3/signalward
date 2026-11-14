export const POLICY_VERSION = "signalward-policy-2026.11.3";

export type RepositoryFinding = {
  category: "secret" | "dependency" | "configuration";
  severity: "low" | "medium" | "high" | "critical";
};

export type RepositoryScanResult = "pass" | "block" | "incomplete";

export function evaluateRepositoryScan(
  findings: readonly RepositoryFinding[],
  coverage: "complete" | "incomplete",
): RepositoryScanResult {
  const hasBlockingSecret = findings.some(
    ({ category, severity }) =>
      category === "secret" && (severity === "high" || severity === "critical"),
  );

  if (hasBlockingSecret) return "block";
  return coverage === "complete" ? "pass" : "incomplete";
}

export type FraudFinding = {
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
};

export type FraudScanResult = "low_risk" | "suspicious" | "high_risk" | "inconclusive";

/**
 * Deterministic fraud verdict. Persuasive language alone stays low risk; elevated verdicts need
 * findings that the scanners only raise for sensitive requests, identity mismatches or risky links.
 * A model explanation can never change this result.
 */
export function evaluateFraudScan(
  findings: readonly FraudFinding[],
  coverage: "complete" | "incomplete",
): FraudScanResult {
  const strong = findings.filter(
    ({ severity, confidence }) => (severity === "high" || severity === "critical") && confidence !== "low",
  );
  const highCount = findings.filter(({ severity }) => severity === "high" || severity === "critical").length;
  const mediumCount = findings.filter(({ severity }) => severity === "medium").length;

  if (strong.length >= 1 || highCount >= 2) return "high_risk";
  if (highCount === 1 || mediumCount >= 1) return "suspicious";
  return coverage === "complete" ? "low_risk" : "inconclusive";
}

export type PolicyAction = { action: string; detail: string; mode: "automatic" | "recommended" };

/** Map a verdict to the actions the workflow takes. Actions are fixed per verdict, never model-generated. */
export function actionsFor(
  kind: "repository" | "message" | "url",
  verdict: RepositoryScanResult | FraudScanResult,
): PolicyAction[] {
  if (kind === "repository") {
    switch (verdict) {
      case "block":
        return [
          { action: "block_scan", detail: "Return a blocking verdict; the CLI exits non-zero. Connect a CI provider to enforce merge protection.", mode: "automatic" },
          { action: "rotate_credential", detail: "Revoke and rotate every exposed credential, then purge it from history.", mode: "recommended" },
        ];
      case "incomplete":
        return [{ action: "hold_for_review", detail: "Coverage was partial. Re-run with the skipped detectors before trusting a pass.", mode: "recommended" }];
      default:
        return [{ action: "pass_scan", detail: "Return a passing scan verdict. This does not publish a commit status to a hosting provider.", mode: "automatic" }];
    }
  }
  switch (verdict) {
    case "high_risk":
      return [
        { action: "block_indicators", detail: "Add high-confidence URL, domain, or IP indicators cited by high-risk findings to this workspace blocklist.", mode: "recommended" },
        { action: "warn_recipient", detail: "Show the high-risk verdict and evidence to the analyst; verify through a trusted channel.", mode: "automatic" },
        { action: "hold_payment", detail: "Do not pay or share codes. Confirm through a channel you already trust.", mode: "recommended" },
      ];
    case "suspicious":
      return [{ action: "warn_recipient", detail: "Show a warning with the evidence and ask the recipient to verify independently.", mode: "automatic" }];
    case "inconclusive":
      return [{ action: "hold_for_review", detail: "Some checks could not run. Treat the content as unverified.", mode: "recommended" }];
    default:
      return [{ action: "no_blocking_signal", detail: "No configured fraud rule produced a blocking signal; this scan does not deliver or approve the content.", mode: "automatic" }];
  }
}

/** Shared report contracts. Every scanner produces this shape so the policy, receipts and UI agree. */

export const REPORT_SCHEMA = "signalward.report/v1";
export const RECEIPT_SCHEMA = "signalward.receipt/v1";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingCategory =
  | "secret"
  | "dependency"
  | "configuration"
  | "message"
  | "phishing"
  | "domain"
  | "redirect"
  | "intelligence";

export type Evidence = { label: string; value: string };

export type Finding = {
  /** Stable across re-scans of the same content: derived from rule, location and a fingerprint. */
  id: string;
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  confidence: Confidence;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  location?: { path: string; line: number } | undefined;
  evidence: Evidence[];
};

export type DetectorCoverage = {
  detector: string;
  status: "ran" | "skipped" | "partial";
  detail: string;
  /** Optional detectors never make a report incomplete. */
  required: boolean;
};

export type IndicatorType =
  | "url"
  | "domain"
  | "email"
  | "phone"
  | "upi"
  | "crypto_wallet"
  | "iban"
  | "ifsc"
  | "ipv4"
  | "amount";

/** A message indicator. The raw value never leaves the scanner; only a redacted display and a keyed tag do. */
export type Indicator = {
  type: IndicatorType;
  display: string;
  /** HMAC-SHA-256 tag under the workspace key. Equality-matchable inside one workspace only. */
  tag: string;
  keyVersion: string;
  seenBefore: number;
  blocked: boolean;
};

export type RepositoryVerdict = "pass" | "block" | "incomplete";
export type FraudVerdict = "low_risk" | "suspicious" | "high_risk" | "inconclusive";

export type Mitigation = {
  id: string;
  action: string;
  detail: string;
  /** "automatic" actions were applied by the scanner; "recommended" actions need a person. */
  mode: "automatic" | "recommended";
  /** Outcome in this report; absent on older stored reports. */
  status?: "applied" | "recommended" | "failed" | "not_applicable";
};

/** Deterministic threat scenario derived from scan findings and detector coverage. */
export type ThreatScenario = {
  id: string;
  actor: string;
  boundary: string;
  targetAsset: string;
  attackPath: string;
  preconditions: string;
  controls: string[];
  mitigations: string[];
  residualRisk: string;
  status: "observed" | "no_signal" | "not_assessed";
  signal: "none" | "low" | "medium" | "high";
  impact: "low" | "medium" | "high" | "critical";
  confidence: Confidence;
  findingIds: string[];
};

export type ThreatAssessment = {
  method: "deterministic-scenarios-v2";
  scope: string;
  coverageLimitations: string[];
  scenarios: ThreatScenario[];
};

export type Stage = { name: string; ms: number; status: "done" | "skipped" };

export type ReportScope =
  | { kind: "repository"; files: number; bytes: number; skipped: number; label: string }
  | { kind: "message"; characters: number; sender: string | null }
  | { kind: "url"; normalized: string; registrableDomain: string | null };

export type Report = {
  urlModel?: { modelVersion: string; score: number; advisory: true };
  urlDataset?: { labels: string[] };
  urlNotice?: "dataset_miss" | "dataset_conflict" | "dataset_unavailable" | "gemini_unverified" | "gemini_unavailable";
  urlSearch?: { provider: "gemini-google-search" | "gemini"; summary: string; sources: string[];
    assessment?: "suspicious" | "unverified"; nextStep?: string };
  schema: typeof REPORT_SCHEMA;
  id: string;
  workspace: string;
  kind: "repository" | "message" | "url";
  createdAt: string;
  scope: ReportScope;
  policyVersion: string;
  verdict: RepositoryVerdict | FraudVerdict;
  coverage: DetectorCoverage[];
  complete: boolean;
  findings: Finding[];
  /** Structured, evidence-linked threat model. Optional for compatibility with older reports. */
  threatAssessment?: ThreatAssessment;
  indicators: Indicator[];
  mitigations: Mitigation[];
  stages: Stage[];
  summary: string;
};

export type ReceiptPayload = {
  reportId: string;
  workspace: string;
  kind: Report["kind"];
  reportDigest: string;
  scope: ReportScope;
  policyVersion: string;
  verdict: Report["verdict"];
  action: string;
  findingIds: string[];
  issuedAt: string;
  keyId: string;
};

export type Receipt = {
  schema: typeof RECEIPT_SCHEMA;
  algorithm: "Ed25519";
  payload: ReceiptPayload;
  /** base64url Ed25519 signature over canonicalJson(payload). */
  signature: string;
};

export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

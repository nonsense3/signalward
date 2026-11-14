import { Buffer } from "node:buffer";
import type { Finding } from "../../contracts/src/index.ts";
import type { UrlEvidence } from "../../fraud-scan/src/url.ts";
import { finding } from "../../fraud-scan/src/rules.ts";

export const URL_MODEL_FEATURES = [
  "url_length", "host_length", "path_length", "query_length", "host_label_count",
  "extra_host_label_count", "digit_ratio", "hyphen_count", "query_param_count",
  "percent_escape_count", "suspicious_keyword_count", "host_entropy", "is_ip", "has_userinfo",
] as const;

export type UrlRiskModel = {
  schema: "signalward.url-risk-model/v1";
  modelVersion: string;
  datasetId: string;
  datasetSha256: string;
  trainedAt: string;
  features: string[];
  coefficients: number[];
  intercept: number;
  threshold: number;
  validation: {
    split: "hostname-disjoint";
    samples: number;
    validationHosts: number;
    positiveSamples: number;
    negativeSamples: number;
    precision: number;
    recall: number;
    falsePositiveRate: number;
    averagePrecision: number;
  };
};

export type UrlModelScore = { score: number; threshold: number; finding: Finding | null };

const FEATURE_LABELS: Record<(typeof URL_MODEL_FEATURES)[number], string> = {
  url_length: "URL length",
  host_length: "Hostname length",
  path_length: "Path length",
  query_length: "Query length",
  host_label_count: "Hostname label count",
  extra_host_label_count: "Extra hostname labels",
  digit_ratio: "Digits in hostname",
  hyphen_count: "Hyphens in hostname",
  query_param_count: "Query parameter count",
  percent_escape_count: "Encoded character count",
  suspicious_keyword_count: "Credential or account terms",
  host_entropy: "Hostname character diversity",
  is_ip: "IP address used as hostname",
  has_userinfo: "Text before @ in URL",
};

function entropy(value: string): number {
  if (!value) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let result = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    result -= probability * Math.log2(probability);
  }
  return result;
}

/** Keep this feature order and scaling in sync with scripts/train_url_model.py. */
export function urlRiskFeatures(url: UrlEvidence): number[] {
  const host = url.hostname.toLowerCase();
  const hostLabels = host.split(".").filter(Boolean);
  const suspiciousTerms = ["login", "signin", "verify", "account", "secure", "update", "password", "wallet", "bank", "kyc", "otp", "refund", "claim"];
  const inspect = `${host}${url.path}${url.query}`.toLowerCase();
  const digits = (host.match(/\d/g) ?? []).length;
  const queryParams = url.query ? [...new URLSearchParams(url.query.slice(1)).keys()].length : 0;
  return [
    Math.min(Math.log1p(url.normalized.length) / 10, 1),
    Math.min(Math.log1p(host.length) / 6, 1),
    Math.min(Math.log1p(url.path.length) / 8, 1),
    Math.min(Math.log1p(url.query.length) / 8, 1),
    Math.min(hostLabels.length / 8, 1),
    Math.min(Math.max(0, hostLabels.length - 2) / 6, 1),
    digits / Math.max(host.length, 1),
    Math.min((host.match(/-/g) ?? []).length / 6, 1),
    Math.min(queryParams / 10, 1),
    Math.min((url.normalized.match(/%[0-9a-f]{2}/gi) ?? []).length / 6, 1),
    Math.min(suspiciousTerms.filter((term) => inspect.includes(term)).length / 5, 1),
    Math.min(entropy(host) / 5, 1),
    url.isIp ? 1 : 0,
    url.hadUserinfo ? 1 : 0,
  ];
}

export function parseUrlRiskModelB64(value: string | null | undefined): UrlRiskModel | null {
  if (!value) return null;
  try {
    if (value.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as Partial<UrlRiskModel>;
    if (parsed.schema !== "signalward.url-risk-model/v1"
      || typeof parsed.modelVersion !== "string" || !/^[A-Za-z0-9._-]{1,80}$/.test(parsed.modelVersion)
      || typeof parsed.datasetId !== "string" || !parsed.datasetId || parsed.datasetId.length > 300
      || /[\u0000-\u001f\u007f]/.test(parsed.datasetId)
      || typeof parsed.datasetSha256 !== "string" || !/^[a-f0-9]{64}$/.test(parsed.datasetSha256)
      || typeof parsed.trainedAt !== "string" || !Number.isFinite(Date.parse(parsed.trainedAt))
      || !Array.isArray(parsed.features) || parsed.features.length !== URL_MODEL_FEATURES.length
      || parsed.features.some((feature, index) => feature !== URL_MODEL_FEATURES[index])
      || !Array.isArray(parsed.coefficients) || parsed.coefficients.length !== URL_MODEL_FEATURES.length
      || parsed.coefficients.some((coefficient) => !Number.isFinite(coefficient) || Math.abs(coefficient) > 100)
      || !Number.isFinite(parsed.intercept) || Math.abs(parsed.intercept!) > 100
      || !Number.isFinite(parsed.threshold) || parsed.threshold! <= 0 || parsed.threshold! > 1
      || !parsed.validation || parsed.validation.split !== "hostname-disjoint"
      || !Number.isSafeInteger(parsed.validation.samples) || parsed.validation.samples < 1
      || !Number.isSafeInteger(parsed.validation.validationHosts) || parsed.validation.validationHosts < 2
      || !Number.isSafeInteger(parsed.validation.positiveSamples) || parsed.validation.positiveSamples < 1
      || !Number.isSafeInteger(parsed.validation.negativeSamples) || parsed.validation.negativeSamples < 1
      || parsed.validation.positiveSamples + parsed.validation.negativeSamples !== parsed.validation.samples
      || ![parsed.validation.precision, parsed.validation.recall, parsed.validation.falsePositiveRate, parsed.validation.averagePrecision]
        .every((metric) => Number.isFinite(metric) && metric >= 0 && metric <= 1)) return null;
    return parsed as UrlRiskModel;
  } catch {
    return null;
  }
}

export function scoreUrlRiskModel(model: UrlRiskModel, url: UrlEvidence): UrlModelScore {
  const features = urlRiskFeatures(url);
  let logit = model.intercept;
  for (let index = 0; index < features.length; index++) logit += features[index]! * model.coefficients[index]!;
  const score = 1 / (1 + Math.exp(-Math.max(-40, Math.min(40, logit))));
  const rounded = Number(score.toFixed(4));
  const topSignals = features
    .map((value, index) => ({ label: FEATURE_LABELS[URL_MODEL_FEATURES[index]!], contribution: value * model.coefficients[index]! }))
    .filter((item) => item.contribution > 0)
    .sort((a, b) => b.contribution - a.contribution)
    .slice(0, 3);
  const modelFinding = score >= model.threshold
    ? finding({
      ruleId: "url.ml_lexical_model",
      category: "phishing",
      severity: "medium",
      confidence: "medium",
      title: "URL model flagged suspicious structure",
      description: `Model ${model.modelVersion} assigned this URL a structural risk score of ${Math.round(rounded * 100)}/100, above its validation-selected review threshold.`,
      impact: "This model uses URL structure learned from its training dataset; it is a risk signal, not proof of malicious content.",
      remediation: "Treat as suspicious and verify the destination through a trusted channel before opening it.",
      evidence: [
        { label: "Structural score", value: `${Math.round(rounded * 100)}/100` },
        { label: "Review threshold", value: `${Math.round(model.threshold * 100)}/100` },
        ...topSignals.map((item) => ({ label: "Model signal", value: `${item.label} (contribution +${item.contribution.toFixed(3)})` })),
        { label: "Model version", value: model.modelVersion },
        { label: "Training dataset", value: model.datasetId.slice(0, 100) },
        { label: "Dataset SHA-256", value: model.datasetSha256 },
        { label: "Holdout metrics", value: `precision ${Math.round(model.validation.precision * 100)}%; recall ${Math.round(model.validation.recall * 100)}%; false-positive rate ${Math.round(model.validation.falsePositiveRate * 10000) / 100}% on ${model.validation.negativeSamples} benign URLs` },
      ],
    })
    : null;
  return { score: rounded, threshold: model.threshold, finding: modelFinding };
}

import { isIP } from "node:net";
import { readFileSync } from "node:fs";
import trainedModel from "./phishing-model.json" with { type: "json" };

let dataset: Map<string, Set<string>> | null = null;
let artifact: Record<string, unknown> = trainedModel;
try {
  const input = JSON.parse(readFileSync(new URL("../../../signalward-url-model.json", import.meta.url), "utf8"));
  if (Array.isArray(input)) {
    const index = new Map<string, Set<string>>();
    for (const row of input) {
      if (typeof row?.url !== "string" || !["benign", "phishing", "defacement", "malware"].includes(row.type)) continue;
      const key = datasetKey(row.url);
      if (!key) continue;
      const labels = index.get(key);
      if (labels) labels.add(row.type);
      else index.set(key, new Set([row.type]));
    }
    dataset = index.size ? index : null;
  } else if (input?.version === trainedModel.version) {
    artifact = input;
  }
} catch {
  // The data file is optional, including in deployments without a local filesystem.
}

function datasetKey(raw: string, preserveScheme = true): string | null {
  const value = raw.trim();
  try {
    const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
    const url = new URL(explicitScheme ? value : "https://" + value);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password) return null;
    return (preserveScheme && explicitScheme ? url.protocol + "//" : "") + url.host + url.pathname + url.search + url.hash;
  } catch {
    return null;
  }
}

export function lookupUrl(raw: string) {
  const exact = datasetKey(raw);
  const neutral = datasetKey(raw, false);
  const https = neutral ? "https://" + neutral : null;
  const keys = new Set([exact, neutral, exact === neutral ? https : null]);
  const labels = new Set<string>();
  for (const key of keys) {
    if (key) for (const label of dataset?.get(key) ?? []) labels.add(label);
  }
  return { available: dataset !== null, labels: [...labels].sort() };
}

const features = ["url_length", "host_length", "host_dots", "host_hyphens",
  "url_digits", "path_length", "query_length", "ip_host"];

function loadModel() {
  const validVector = (values: unknown): values is number[] =>
    Array.isArray(values) && values.length === features.length && values.every(Number.isFinite);
  if (artifact.version !== "signalward-url-lr-v1" ||
      JSON.stringify(artifact.features) !== JSON.stringify(features) ||
      !validVector(artifact.mean) || !validVector(artifact.scale) ||
      !validVector(artifact.weights) || artifact.scale.some(value => value <= 0) ||
      typeof artifact.intercept !== "number" || !Number.isFinite(artifact.intercept)) return null;
  return { version: artifact.version, weights: artifact.weights, mean: artifact.mean,
    scale: artifact.scale, intercept: artifact.intercept };
}

const model = loadModel();

export function scoreUrl(raw: string) {
  if (!model) return null;
  const input = raw.trim();
  // Preserve raw path, query and host lengths as in the training notebook.
  const parts = /^(?:https?:\/\/)([^/?#]+)([^?#]*)(?:\?([^#]*))?/i.exec(
    (input.includes("://") ? input : "https://" + input).replace(/[\t\r\n]/g, ""),
  );
  if (!parts || !URL.canParse(parts[0])) return null;
  const authority = parts[1].split("@").at(-1)!;
  const host = (authority.startsWith("[") ? authority.slice(1, authority.indexOf("]")) :
    authority.split(":")[0]).toLowerCase().replace(/\.+$/, "");
  if (!host) return null;
  const length = (value: string) => Array.from(value).length;
  const values = [length(input), length(host), (host.match(/\./g) ?? []).length,
    (host.match(/-/g) ?? []).length, (input.match(/[0-9]/g) ?? []).length,
    length(parts[2]), length(parts[3] ?? ""), Number(isIP(host) !== 0)];
  const logit = model.weights.reduce((sum, weight, index) =>
    sum + weight * ((values[index] - model.mean[index]) / model.scale[index]), model.intercept);
  return { modelVersion: model.version, score: 1 / (1 + Math.exp(-logit)), advisory: true as const };
}

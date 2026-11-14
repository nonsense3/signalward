/**
 * Independent receipt verification with WebCrypto. Mirrors packages/receipts/src/index.ts:
 * canonical JSON (sorted keys, no whitespace, undefined dropped), SHA-256 digest, Ed25519 signature.
 * Nothing leaves the browser.
 */

export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot encode non-finite numbers.");
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item === undefined ? null : item)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value).filter(([, item]) => item !== undefined).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  throw new TypeError(`Canonical JSON cannot encode ${typeof value}.`);
}

function fromBase64Url(text) {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function fetchTrustedKeys() {
  const response = await fetch("/.well-known/signalward-keys.json", { cache: "no-store" });
  if (!response.ok) throw new Error("Could not load the trusted key set.");
  const set = await response.json();
  return Array.isArray(set.keys) ? set.keys : [];
}

/** Returns { valid, checks: [{ check, ok, detail }] }. */
export async function verifyReceipt(receipt, trustedKeys, report) {
  const checks = [];
  const shapeOk = Boolean(receipt && receipt.schema === "signalward.receipt/v1" && receipt.algorithm === "Ed25519" && receipt.payload && typeof receipt.signature === "string");
  checks.push({ check: "schema", ok: shapeOk, detail: shapeOk ? "signalward.receipt/v1, Ed25519" : "Not a SignalWard v1 receipt." });
  if (!shapeOk) return { valid: false, checks };

  const key = trustedKeys.find((candidate) => candidate.kid === receipt.payload.keyId && candidate.alg === "Ed25519");
  checks.push({ check: "trusted_key", ok: Boolean(key), detail: key ? receipt.payload.keyId : `Key ${receipt.payload.keyId} is not in the trusted key set.` });

  let signatureOk = false;
  let detail = "No trusted key to check against.";
  if (key) {
    try {
      const publicKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: key.x }, { name: "Ed25519" }, false, ["verify"]);
      signatureOk = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, fromBase64Url(receipt.signature), new TextEncoder().encode(canonicalJson(receipt.payload)));
      detail = signatureOk ? "Ed25519 signature matches the canonical payload." : "Signature does not match the payload. The receipt was altered or signed by another key.";
    } catch (error) {
      detail = error?.name === "NotSupportedError" ? "This browser does not support Ed25519 in WebCrypto. Use the CLI verifier." : "The signature could not be checked.";
    }
  }
  checks.push({ check: "signature", ok: signatureOk, detail });

  if (report !== undefined) {
    let digest = "";
    try {
      digest = `sha256:${await sha256Hex(canonicalJson(report))}`;
    } catch {
      digest = "";
    }
    const matches = digest === receipt.payload.reportDigest;
    checks.push({ check: "report_digest", ok: matches, detail: matches ? digest : "The report does not match the digest in the receipt." });
    if (report && typeof report === "object") {
      const consistent = report.id === receipt.payload.reportId && report.verdict === receipt.payload.verdict;
      checks.push({ check: "report_fields", ok: consistent, detail: consistent ? `${report.id} · ${report.verdict}` : "Report ID or verdict differs from the receipt." });
    }
  }
  return { valid: checks.every((item) => item.ok), checks };
}

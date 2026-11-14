import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { RECEIPT_SCHEMA, type Receipt, type ReceiptPayload, type Report } from "../../contracts/src/index.ts";

/**
 * Canonical JSON: object keys sorted by code unit, no insignificant whitespace, undefined members dropped.
 * The browser verifier (apps/web/public/verify.js) implements the same rules; keep them in sync.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot encode non-finite numbers.");
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item === undefined ? null : item)).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`).join(",")}}`;
  }
  throw new TypeError(`Canonical JSON cannot encode ${typeof value}.`);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** Digest over the canonical report. The report carries no digest field, so the value is self-contained. */
export function reportDigest(report: Report): string {
  return `sha256:${sha256Hex(canonicalJson(report))}`;
}

export type SigningKey = { keyId: string; privateKey: KeyObject; publicKey: KeyObject; publicX: string; createdAt: string };
export type TrustedKey = { kid: string; alg: "Ed25519"; x: string; createdAt?: string };

function fromPrivate(privateKey: KeyObject, createdAt: string): SigningKey {
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") throw new Error("Signing key must be Ed25519.");
  return { keyId: `sw-ed25519-${sha256Hex(Buffer.from(jwk.x, "base64url")).slice(0, 12)}`, privateKey, publicKey, publicX: jwk.x, createdAt };
}

/**
 * Load the receipt signing key. Production deployments set SIGNALWARD_SIGNING_KEY to a base64 PKCS#8 DER
 * Ed25519 key from a secret store. Local development generates one key under `.signalward/` (git-ignored).
 */
export function loadSigningKey(stateDir: string, env: NodeJS.ProcessEnv = process.env): SigningKey {
  const configured = env.SIGNALWARD_SIGNING_KEY;
  if (configured) {
    return fromPrivate(createPrivateKey({ key: Buffer.from(configured, "base64"), format: "der", type: "pkcs8" }), "configured");
  }
  const file = join(stateDir, "receipt-ed25519.json");
  if (existsSync(file)) {
    const stored = JSON.parse(readFileSync(file, "utf8")) as { pkcs8: string; createdAt: string };
    return fromPrivate(createPrivateKey({ key: Buffer.from(stored.pkcs8, "base64"), format: "der", type: "pkcs8" }), stored.createdAt);
  }
  const { privateKey } = generateKeyPairSync("ed25519");
  const createdAt = new Date().toISOString();
  mkdirSync(stateDir, { recursive: true });
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  writeFileSync(file, JSON.stringify({ pkcs8, createdAt }, null, 2), { mode: 0o600 });
  return fromPrivate(privateKey, createdAt);
}

export function trustedKeySet(key: SigningKey): { keys: TrustedKey[] } {
  return { keys: [{ kid: key.keyId, alg: "Ed25519", x: key.publicX, createdAt: key.createdAt }] };
}

export function issueReceipt(report: Report, action: string, key: SigningKey, now = new Date()): Receipt {
  const payload: ReceiptPayload = {
    reportId: report.id,
    workspace: report.workspace,
    kind: report.kind,
    reportDigest: reportDigest(report),
    scope: report.scope,
    policyVersion: report.policyVersion,
    verdict: report.verdict,
    action,
    findingIds: report.findings.map((finding) => finding.id),
    issuedAt: now.toISOString(),
    keyId: key.keyId,
  };
  const signature = sign(null, Buffer.from(canonicalJson(payload)), key.privateKey).toString("base64url");
  return { schema: RECEIPT_SCHEMA, algorithm: "Ed25519", payload, signature };
}

export type VerificationCheck = { check: string; ok: boolean; detail: string };

/** Verify a receipt against a trusted key set, and optionally against the report it describes. */
export function verifyReceipt(receipt: unknown, trusted: readonly TrustedKey[], report?: unknown): { valid: boolean; checks: VerificationCheck[] } {
  const checks: VerificationCheck[] = [];
  const r = receipt as Partial<Receipt> | null;
  const shapeOk = Boolean(r && r.schema === RECEIPT_SCHEMA && r.algorithm === "Ed25519" && r.payload && typeof r.signature === "string");
  checks.push({ check: "schema", ok: shapeOk, detail: shapeOk ? RECEIPT_SCHEMA : "Not a SignalWard v1 receipt." });
  if (!shapeOk || !r?.payload || !r.signature) return { valid: false, checks };

  const key = trusted.find((candidate) => candidate.kid === r.payload?.keyId && candidate.alg === "Ed25519");
  checks.push({ check: "trusted_key", ok: Boolean(key), detail: key ? r.payload.keyId : `Key ${String(r.payload.keyId)} is not in the trusted key set.` });

  let signatureOk = false;
  if (key) {
    try {
      const publicKey = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
      signatureOk = verify(null, Buffer.from(canonicalJson(r.payload)), publicKey, Buffer.from(r.signature, "base64url"));
    } catch {
      signatureOk = false;
    }
  }
  checks.push({ check: "signature", ok: signatureOk, detail: signatureOk ? "Ed25519 signature matches the payload." : "Signature does not match the payload." });

  if (report !== undefined) {
    let digest = "";
    try {
      digest = `sha256:${sha256Hex(canonicalJson(report))}`;
    } catch {
      digest = "";
    }
    const matches = digest === r.payload.reportDigest;
    checks.push({ check: "report_digest", ok: matches, detail: matches ? digest : "The report does not match the digest in the receipt." });
  }
  return { valid: checks.every((item) => item.ok), checks };
}

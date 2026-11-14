import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const FORMAT = "signalward/encrypted-json/v1" as const;

export type EncryptedJson = {
  _signalward: typeof FORMAT;
  kid?: string;
  context: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

export function isEncryptedJson(value: unknown): value is EncryptedJson {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<EncryptedJson>;
  return candidate._signalward === FORMAT && typeof candidate.context === "string" && (candidate.kid === undefined || typeof candidate.kid === "string") && typeof candidate.iv === "string" && typeof candidate.tag === "string" && typeof candidate.ciphertext === "string";
}

export function reportKeyId(key: Buffer): string {
  return createHash("sha256").update(key).digest("base64url").slice(0, 12);
}

export function isEncryptedWithKey(value: unknown, key: Buffer): boolean {
  return isEncryptedJson(value) && value.kid === reportKeyId(key);
}

const aadFor = (context: string, kid?: string) => Buffer.from(JSON.stringify(kid ? [FORMAT, context, kid] : [FORMAT, context]), "utf8");

/** Encrypt JSON data with a dedicated 256-bit key and AES-256-GCM authentication. */
export function encryptJson(key: Buffer, value: unknown, context = ""): EncryptedJson {
  if (key.length !== 32) throw new Error("Report encryption key must be exactly 32 bytes.");
  const iv = randomBytes(12);
  const kid = reportKeyId(key);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aadFor(context, kid));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
  return {
    _signalward: FORMAT,
    kid,
    context,
    iv: iv.toString("base64url"),
    tag: cipher.getAuthTag().toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
  };
}

/** Decrypt new envelopes; return legacy plaintext values for the one-way storage migration. */
export function decryptJson<T>(key: Buffer | readonly Buffer[], value: unknown, options: { required?: boolean; context?: string } = {}): T {
  if (!isEncryptedJson(value)) {
    if (options.required || value && typeof value === "object" && (value as { _signalward?: unknown })._signalward === FORMAT) {
      throw new Error("Stored report has an invalid encryption envelope.");
    }
    return value as T;
  }
  const context = options.context ?? "";
  if (value.context !== context) throw new Error("Stored report encryption context does not match its owner or report.");
  const iv = Buffer.from(value.iv, "base64url");
  const tag = Buffer.from(value.tag, "base64url");
  const ciphertext = Buffer.from(value.ciphertext, "base64url");
  if (iv.length !== 12 || tag.length !== 16 || iv.toString("base64url") !== value.iv || tag.toString("base64url") !== value.tag || ciphertext.toString("base64url") !== value.ciphertext) {
    throw new Error("Stored report has an invalid encryption envelope.");
  }
  const keys: readonly Buffer[] = Buffer.isBuffer(key) ? [key] : key;
  for (const candidate of keys) {
    if (candidate.length !== 32) continue;
    if (value.kid && value.kid !== reportKeyId(candidate)) continue;
    try {
      const decipher = createDecipheriv("aes-256-gcm", candidate, iv);
      decipher.setAAD(aadFor(context, value.kid));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
      return JSON.parse(plaintext) as T;
    } catch {
      // Continue only across configured retained keys; never return unauthenticated plaintext.
    }
  }
  throw new Error("Stored report could not be authenticated or decrypted. Check SIGNALWARD_REPORT_ENCRYPTION_KEY and its retained-key history.");
}

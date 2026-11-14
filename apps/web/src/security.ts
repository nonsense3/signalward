import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { IncomingMessage } from "node:http";

export type IndicatorMasterVersion = { version: string; key: Buffer };

/** Parse the base64url JSON secret history used to overlap report-encryption key rotations. */
export function parseReportEncryptionKeyHistory(encoded: string | null | undefined): Buffer[] {
  if (!encoded) return [];
  if (encoded.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(encoded) || Buffer.from(encoded, "base64url").toString("base64url") !== encoded) {
    throw new Error("SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS must be canonical base64url-encoded JSON.");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS does not contain valid JSON.");
  }
  const entries = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(entries) || entries.length > 3) throw new Error("SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS must contain at most 3 previous keys.");
  const keys = entries.map((entry) => {
    if (typeof entry !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(entry)) throw new Error("Previous report-encryption keys must be base64-encoded 32-byte keys.");
    const key = Buffer.from(entry, "base64");
    if (key.length !== 32 || key.toString("base64") !== entry) throw new Error("A previous report-encryption key is malformed.");
    return key;
  });
  if (keys.some((key, index) => keys.slice(index + 1).some((other) => key.equals(other)))) throw new Error("Previous report-encryption keys must be unique.");
  return keys;
}

/** Parse the base64url JSON secret history used to overlap indicator-key rotations. */
export function parseIndicatorKeyHistory(encoded: string | null | undefined): IndicatorMasterVersion[] {
  if (!encoded) return [];
  if (encoded.length > 16_384 || !/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error("SIGNALWARD_PREVIOUS_INDICATOR_KEYS must be base64url-encoded JSON.");
  if (Buffer.from(encoded, "base64url").toString("base64url") !== encoded) throw new Error("SIGNALWARD_PREVIOUS_INDICATOR_KEYS must use canonical base64url encoding.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("SIGNALWARD_PREVIOUS_INDICATOR_KEYS does not contain valid JSON.");
  }
  const entries = (parsed as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(entries) || entries.length > 3) throw new Error("SIGNALWARD_PREVIOUS_INDICATOR_KEYS must contain at most 3 previous keys.");
  const versions = new Set<string>();
  return entries.map((entry): IndicatorMasterVersion => {
    if (!entry || typeof entry !== "object") throw new Error("A previous indicator key entry is invalid.");
    const candidate = entry as Record<string, unknown>;
    if (typeof candidate.version !== "string" || !/^k\d{1,6}$/.test(candidate.version) || typeof candidate.key !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(candidate.key)) {
      throw new Error("Previous indicator keys need a k-number version and a base64-encoded 32-byte key.");
    }
    const key = Buffer.from(candidate.key, "base64");
    if (key.length !== 32 || key.toString("base64") !== candidate.key || versions.has(candidate.version)) throw new Error("A previous indicator key is malformed or has a duplicate version.");
    versions.add(candidate.version);
    return { version: candidate.version, key };
  });
}

/** Use a configured base64 secret, else a git-ignored development secret under the state directory. */
export function resolveSecret(configured: string | null, stateDir: string, fileName: string): Buffer {
  if (configured) return Buffer.from(configured, "base64");
  const file = join(stateDir, fileName);
  if (existsSync(file)) return Buffer.from(readFileSync(file, "utf8").trim(), "base64");
  mkdirSync(stateDir, { recursive: true });
  const value = randomBytes(32);
  writeFileSync(file, value.toString("base64"), { mode: 0o600 });
  return value;
}

export function deriveKey(master: Buffer, salt: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", master, Buffer.from(salt), Buffer.from(info), 32));
}

/** Per-user indicator key: one master secret never produces the same tag for two accounts. */
export function deriveIndicatorKey(master: Buffer, userId: string, keyVersion: string): Buffer {
  return deriveKey(master, userId, `signalward/indicator/${keyVersion}`);
}

/**
 * Authenticated encryption for cookies (AES-256-GCM). Contents are confidential and tamper-evident;
 * the expiry inside the payload is checked on every open.
 */
export function seal(key: Buffer, payload: Record<string, unknown>): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  return `v1.${Buffer.concat([iv, cipher.getAuthTag(), body]).toString("base64url")}`;
}

export function open<T extends { exp: number }>(key: Buffer, token: string | undefined, now = Date.now()): T | null {
  if (!token || token.length > 3800 || !token.startsWith("v1.")) return null;
  try {
    const raw = Buffer.from(token.slice(3), "base64url");
    if (raw.length < 29) return null;
    const decipher = createDecipheriv("aes-256-gcm", key, raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    const text = Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString("utf8");
    const payload = JSON.parse(text) as T;
    if (typeof payload.exp !== "number" || payload.exp * 1000 <= now) return null;
    return payload;
  } catch {
    return null;
  }
}

export function readCookie(request: IncomingMessage, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

export function cookie(name: string, value: string, maxAge: number, secure: boolean): string {
  return `${name}=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}

/**
 * Same-origin gate for state-changing requests. Browsers send Origin on cross-origin POSTs and
 * Sec-Fetch-Site when supported, so a request initiated by another site is refused before routing.
 */
export function sameOrigin(request: IncomingMessage): boolean {
  const site = request.headers["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = request.headers.origin;
  if (!origin) return site === "same-origin" || site === "none";
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

/** Fixed-window limiter keyed by caller. In-memory, which suits one process. */
export class RateLimiter {
  #windows = new Map<string, { start: number; count: number }>();
  readonly limit: number;
  readonly windowMs: number;
  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  take(key: string, now = Date.now()): { ok: boolean; retryAfter: number } {
    const window = this.#windows.get(key);
    if (!window || now - window.start >= this.windowMs) {
      this.#windows.set(key, { start: now, count: 1 });
      if (this.#windows.size > 10_000) this.#windows.delete(this.#windows.keys().next().value as string);
      return { ok: true, retryAfter: 0 };
    }
    window.count += 1;
    return window.count <= this.limit ? { ok: true, retryAfter: 0 } : { ok: false, retryAfter: Math.max(1, Math.ceil((window.start + this.windowMs - now) / 1000)) };
  }
}

export const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "X-Frame-Options": "DENY",
};

import { createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { IncomingMessage } from "node:http";

/** Load a 32-byte secret from the environment, else from the git-ignored state directory, else create it. */
export function loadSecret(stateDir: string, envName: string, fileName: string, env: NodeJS.ProcessEnv = process.env): Buffer {
  const configured = env[envName];
  if (configured) {
    const value = Buffer.from(configured, "base64");
    if (value.length < 32) throw new Error(`${envName} must be at least 32 bytes, base64 encoded.`);
    return value;
  }
  const file = join(stateDir, fileName);
  if (existsSync(file)) return Buffer.from(readFileSync(file, "utf8").trim(), "base64");
  mkdirSync(stateDir, { recursive: true });
  const value = randomBytes(32);
  writeFileSync(file, value.toString("base64"), { mode: 0o600 });
  return value;
}

/** Per-workspace indicator key, derived so one master secret never tags two workspaces the same way. */
export function deriveIndicatorKey(master: Buffer, workspace: string, keyVersion: string): Buffer {
  return Buffer.from(hkdfSync("sha256", master, Buffer.from(workspace), Buffer.from(`signalward/indicator/${keyVersion}`), 32));
}

export type SessionClaims = { v: 1; wid: string; sid: string; iat: number; exp: number };
export const SESSION_TTL_SECONDS = 12 * 60 * 60;
export const SESSION_COOKIE = "sw_session";

export function signSession(secret: Buffer, claims: SessionClaims): string {
  const body = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const mac = createHmac("sha256", secret).update(`sw1.${body}`).digest("base64url");
  return `sw1.${body}.${mac}`;
}

export function verifySession(secret: Buffer, token: string | undefined, now = Date.now()): SessionClaims | null {
  if (!token || token.length > 1024) return null;
  const [prefix, body, mac] = token.split(".");
  if (prefix !== "sw1" || !body || !mac) return null;
  const expected = createHmac("sha256", secret).update(`sw1.${body}`).digest();
  const given = Buffer.from(mac, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as SessionClaims;
    if (claims.v !== 1 || typeof claims.wid !== "string" || typeof claims.exp !== "number" || claims.exp * 1000 <= now) return null;
    return claims;
  } catch {
    return null;
  }
}

export function readCookie(request: IncomingMessage, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

export function sessionCookie(token: string, maxAge: number): string {
  return `${SESSION_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

/**
 * Same-origin gate for state-changing requests. Browsers always send Origin on cross-origin POSTs, and
 * Sec-Fetch-Site when supported, so a request from another site is refused before it reaches a handler.
 */
export function sameOrigin(request: IncomingMessage): boolean {
  const site = request.headers["sec-fetch-site"];
  if (site && site !== "same-origin" && site !== "none") return false;
  const origin = request.headers.origin;
  if (!origin) return site === "same-origin" || site === "none" || request.method === "GET";
  try {
    return new URL(origin).host === request.headers.host;
  } catch {
    return false;
  }
}

/** Fixed-window limiter keyed by caller. Small and in-memory, which suits one local process. */
export class RateLimiter {
  #windows = new Map<string, { start: number; count: number }>();
  limit: number;
  windowMs: number;
  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  take(key: string, now = Date.now()): { ok: boolean; retryAfter: number } {
    const window = this.#windows.get(key);
    if (!window || now - window.start >= this.windowMs) {
      this.#windows.set(key, { start: now, count: 1 });
      if (this.#windows.size > 5000) this.#windows.delete(this.#windows.keys().next().value as string);
      return { ok: true, retryAfter: 0 };
    }
    window.count += 1;
    return window.count <= this.limit ? { ok: true, retryAfter: 0 } : { ok: false, retryAfter: Math.ceil((window.start + this.windowMs - now) / 1000) };
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

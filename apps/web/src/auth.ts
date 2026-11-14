import { createHash, randomBytes, randomUUID, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { AppError, unauthorized, unavailable } from "./errors.ts";
import { deriveKey } from "./security.ts";
import { decryptJson, encryptJson, isEncryptedJson, isEncryptedWithKey } from "./storage-crypto.ts";

const scrypt = promisify(scryptCb) as (password: string, salt: Buffer, keylen: number, options: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;

export type User = { id: string; email: string; emailConfirmed: boolean; createdAt: string };
export type Tokens = { accessToken: string; refreshToken: string; expiresAt: number };
export type AuthResult = { user: User; tokens: Tokens | null; sessionVersion?: number };

export interface AuthProvider {
  readonly kind: "supabase" | "local";
  readonly supportsRecovery: boolean;
  readonly supportsMagicLink: boolean;
  readonly oauthProviders: readonly string[];
  /** Build the provider's hosted authorize URL, or null when OAuth is unavailable. */
  oauthUrl(provider: string, redirectTo: string, codeChallenge: string): string | null;
  /** Send a passwordless sign-in link. */
  magicLink(email: string, redirectTo: string, codeChallenge: string): Promise<void>;
  /** Exchange an OAuth or passwordless authorization code bound to the browser's PKCE verifier. */
  exchangeCode(code: string, codeVerifier: string): Promise<AuthResult>;
  signUp(email: string, password: string, displayName: string, redirectTo: string): Promise<AuthResult & { needsConfirmation: boolean }>;
  signIn(email: string, password: string): Promise<AuthResult>;
  refresh(refreshToken: string): Promise<AuthResult>;
  /** Validate the session's credential and return the current user. */
  verify(session: SessionData): Promise<User>;
  signOut(session: SessionData): Promise<void>;
  recover(email: string, redirectTo: string): Promise<void>;
  updatePassword(session: SessionData, currentPassword: string, newPassword: string): Promise<{ sessionVersion?: number }>;
}

/** Contents of the encrypted session cookie. */
export type SessionData = {
  uid: string;
  email: string;
  iat: number;
  exp: number;
  /** Supabase access and refresh tokens. */
  at?: string;
  rt?: string;
  atExp?: number;
  /** Local accounts: bumping the version revokes every existing session. */
  sv?: number;
};

export const PASSWORD_RULES = "Use at least 10 characters, with letters and a number or symbol.";
export function checkPassword(password: string, email: string): string | null {
  if (password.length < 10) return PASSWORD_RULES;
  if (password.length > 128) return "Passwords can be at most 128 characters.";
  if (!/[A-Za-z]/.test(password) || !/[^A-Za-z]/.test(password)) return PASSWORD_RULES;
  if (password.toLowerCase().includes(email.split("@")[0]!.toLowerCase()) && email.split("@")[0]!.length >= 4) return "Your password must not contain your email name.";
  if (/^(.)\1+$/.test(password) || /^(password|qwerty|letmein|welcome|signalward)/i.test(password)) return "That password is too easy to guess.";
  return null;
}

/* ---------------------------------------------------------------- Supabase */

type SupabaseSession = { access_token?: string; refresh_token?: string; expires_in?: number; expires_at?: number; user?: SupabaseUser } & Partial<SupabaseUser>;
type SupabaseUser = { id: string; email?: string; email_confirmed_at?: string | null; confirmed_at?: string | null; created_at: string };

function toUser(raw: SupabaseUser): User {
  return { id: raw.id, email: raw.email ?? "", emailConfirmed: Boolean(raw.email_confirmed_at ?? raw.confirmed_at), createdAt: raw.created_at };
}

/** Map GoTrue errors onto stable SignalWard codes and plain messages. */
function supabaseError(status: number, body: Record<string, unknown>): AppError {
  const code = String(body.error_code ?? body.error ?? "");
  const detail = String(body.msg ?? body.error_description ?? body.message ?? "");
  if (status === 429 || code === "over_request_rate_limit" || code === "over_email_send_rate_limit") return new AppError(429, "RATE_LIMITED", "Too many attempts. Wait a minute and try again.", { retryAfter: 60 });
  if (code === "invalid_credentials" || code === "invalid_grant" && /credentials/i.test(detail)) return new AppError(401, "AUTH_INVALID_CREDENTIALS", "The email or password is incorrect.");
  if (code === "email_not_confirmed") return new AppError(403, "AUTH_EMAIL_NOT_CONFIRMED", "Confirm your email address first. Check your inbox for the link.");
  if (code === "user_already_exists" || code === "email_exists") return new AppError(409, "AUTH_EMAIL_TAKEN", "An account with this email already exists.", { field: "email" });
  if (code === "weak_password") return new AppError(422, "AUTH_WEAK_PASSWORD", detail || PASSWORD_RULES, { field: "password" });
  if (code === "signup_disabled") return new AppError(403, "AUTH_SIGNUP_DISABLED", "New accounts are not being accepted.");
  if (code === "email_address_invalid" || code === "validation_failed") return new AppError(400, "FIELD_INVALID", "Enter a valid email address.", { field: "email" });
  if (code === "same_password") return new AppError(422, "AUTH_SAME_PASSWORD", "Choose a password you have not used for this account.", { field: "newPassword" });
  if (code === "refresh_token_not_found" || code === "refresh_token_already_used" || code === "session_not_found" || code === "bad_jwt" || status === 401 || status === 403) {
    return unauthorized("Your session has ended. Sign in again.", "AUTH_SESSION_EXPIRED");
  }
  if (status >= 500) return unavailable("AUTH_UNAVAILABLE", "The sign-in service is unavailable. Try again shortly.");
  return new AppError(400, "AUTH_REJECTED", detail.slice(0, 200) || "The request was rejected.");
}

export class SupabaseAuth implements AuthProvider {
  readonly kind = "supabase" as const;
  readonly supportsRecovery = true;
  readonly supportsMagicLink = true;
  readonly oauthProviders = ["github", "google"] as const;
  #userCache = new Map<string, { user: User; until: number }>();
  private url: string;
  private anonKey: string;
  constructor(url: string, anonKey: string) {
    this.url = url;
    this.anonKey = anonKey;
  }

  async #call(path: string, init: { method?: string; body?: unknown; token?: string; query?: Record<string, string> } = {}): Promise<Record<string, unknown>> {
    const target = new URL(`/auth/v1/${path}`, this.url);
    for (const [key, value] of Object.entries(init.query ?? {})) target.searchParams.set(key, value);
    let response: Response;
    try {
      response = await fetch(target, {
        method: init.method ?? "POST",
        headers: { apikey: this.anonKey, "Content-Type": "application/json", ...(init.token ? { Authorization: `Bearer ${init.token}` } : {}) },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      throw unavailable("AUTH_UNAVAILABLE", "The sign-in service could not be reached. Check SUPABASE_URL and your connection.", error);
    }
    const text = await response.text();
    let body: Record<string, unknown> = {};
    try {
      body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
    } catch {
      body = {};
    }
    if (!response.ok) throw supabaseError(response.status, body);
    return body;
  }

  #session(body: SupabaseSession): AuthResult {
    const user = body.user ?? (body.id ? (body as SupabaseUser) : null);
    if (!user) throw unavailable("AUTH_UNAVAILABLE", "The sign-in service returned an unexpected response.");
    const tokens = body.access_token && body.refresh_token
      ? { accessToken: body.access_token, refreshToken: body.refresh_token, expiresAt: body.expires_at ?? Math.floor(Date.now() / 1000) + (body.expires_in ?? 3600) }
      : null;
    return { user: toUser(user), tokens };
  }

  async signUp(email: string, password: string, displayName: string, redirectTo: string) {
    const body = (await this.#call("signup", { body: { email, password, data: { display_name: displayName } }, query: { redirect_to: redirectTo } })) as SupabaseSession;
    const result = this.#session(body);
    return { ...result, needsConfirmation: !result.tokens };
  }

  async signIn(email: string, password: string) {
    const result = this.#session((await this.#call("token", { body: { email, password }, query: { grant_type: "password" } })) as SupabaseSession);
    if (!result.tokens) throw unavailable("AUTH_UNAVAILABLE", "The sign-in service did not return a session.");
    return result;
  }

  async refresh(refreshToken: string) {
    const result = this.#session((await this.#call("token", { body: { refresh_token: refreshToken }, query: { grant_type: "refresh_token" } })) as SupabaseSession);
    if (!result.tokens) throw unauthorized("Your session has ended. Sign in again.", "AUTH_SESSION_EXPIRED");
    return result;
  }

  /** Access tokens are checked with the auth server and cached briefly to keep requests fast. */
  async verify(session: SessionData): Promise<User> {
    if (!session.at) throw unauthorized();
    const key = createHash("sha256").update(session.at).digest("base64url");
    const cached = this.#userCache.get(key);
    if (cached && cached.until > Date.now()) return cached.user;
    const user = toUser((await this.#call("user", { method: "GET", token: session.at })) as unknown as SupabaseUser);
    if (session.uid && user.id !== session.uid) throw unauthorized("Your session does not match this account. Sign in again.", "AUTH_SESSION_EXPIRED");
    this.#userCache.set(key, { user, until: Date.now() + 60_000 });
    if (this.#userCache.size > 2000) this.#userCache.delete(this.#userCache.keys().next().value as string);
    return user;
  }

  async signOut(session: SessionData) {
    if (session.at) {
      this.#userCache.delete(createHash("sha256").update(session.at).digest("base64url"));
      await this.#call("logout", { token: session.at, query: { scope: "global" } }).catch(() => undefined);
    }
  }

  async recover(email: string, redirectTo: string) {
    await this.#call("recover", { body: { email }, query: { redirect_to: redirectTo } });
  }

  oauthUrl(provider: string, redirectTo: string, codeChallenge: string): string | null {
    if (!this.oauthProviders.includes(provider as (typeof this.oauthProviders)[number])) return null;
    const url = new URL("/auth/v1/authorize", this.url);
    url.searchParams.set("provider", provider);
    url.searchParams.set("redirect_to", redirectTo);
    url.searchParams.set("code_challenge", codeChallenge);
    url.searchParams.set("code_challenge_method", "s256");
    return url.toString();
  }

  async magicLink(email: string, redirectTo: string, codeChallenge: string) {
    // create_user so a first-time visitor is onboarded by the same link.
    await this.#call("otp", { body: { email, create_user: true, code_challenge: codeChallenge, code_challenge_method: "s256" }, query: { redirect_to: redirectTo } });
  }

  async exchangeCode(code: string, codeVerifier: string) {
    const result = this.#session((await this.#call("token", { body: { auth_code: code, code_verifier: codeVerifier }, query: { grant_type: "pkce" } })) as SupabaseSession);
    if (!result.tokens) throw unauthorized("The sign-in link could not be exchanged. Restart sign-in.", "AUTH_SESSION_EXPIRED");
    return result;
  }

  async updatePassword(session: SessionData, currentPassword: string, newPassword: string) {
    // Re-authenticate first so a stolen session cookie alone cannot change the password.
    if (currentPassword) await this.signIn(session.email, currentPassword);
    await this.#call("user", { method: "PUT", token: session.at, body: { password: newPassword } });
    return {};
  }
}

/* ---------------------------------------------------------------- Local accounts */

type LocalRecord = { id: string; email: string; salt: string; hash: string; createdAt: string; sv: number; failed: number; lockedUntil: number };
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function localUsersFrom(value: unknown): LocalRecord[] {
  if (!value || typeof value !== "object" || !Array.isArray((value as { users?: unknown }).users) || (value as { users: unknown[] }).users.length > 100_000) {
    throw new Error("The local account store has an invalid structure; no account data was changed.");
  }
  const users = (value as { users: unknown[] }).users.map((entry): LocalRecord => {
    if (!entry || typeof entry !== "object") throw new Error("The local account store contains an invalid account record.");
    const user = entry as Record<string, unknown>;
    if (typeof user.id !== "string" || !/^[0-9a-f-]{36}$/i.test(user.id)
      || typeof user.email !== "string" || user.email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email)
      || typeof user.salt !== "string" || !/^[A-Za-z0-9+/]{22}==$/.test(user.salt)
      || typeof user.hash !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(user.hash)
      || typeof user.createdAt !== "string" || !Number.isFinite(Date.parse(user.createdAt))
      || !Number.isSafeInteger(user.sv) || (user.sv as number) < 1
      || !Number.isSafeInteger(user.failed) || (user.failed as number) < 0 || (user.failed as number) > 7
      || !Number.isSafeInteger(user.lockedUntil) || (user.lockedUntil as number) < 0) {
      throw new Error("The local account store contains an invalid account record; no account data was changed.");
    }
    const salt = Buffer.from(user.salt, "base64");
    const hash = Buffer.from(user.hash, "base64");
    if (salt.length !== 16 || salt.toString("base64") !== user.salt || hash.length !== 32 || hash.toString("base64") !== user.hash) {
      throw new Error("The local account store contains an invalid password verifier; no account data was changed.");
    }
    return user as LocalRecord;
  });
  if (new Set(users.map((user) => user.id)).size !== users.length || new Set(users.map((user) => user.email.toLowerCase())).size !== users.length) {
    throw new Error("The local account store contains duplicate identities; no account data was changed.");
  }
  return users;
}

/**
 * File-backed accounts for development and offline demos. Passwords use scrypt (N=2^15) with a random
 * salt; repeated failures lock the account briefly. Recovery needs email, so it is Supabase-only.
 */
export class LocalAuth implements AuthProvider {
  readonly kind = "local" as const;
  readonly supportsRecovery = false;
  readonly supportsMagicLink = false;
  readonly oauthProviders: readonly string[] = [];
  #file: string;
  #users: LocalRecord[];
  #dummySalt = randomBytes(16);
  #storageKeys: Buffer[];

  constructor(stateDir: string, encryptionKeys: Buffer[]) {
    mkdirSync(stateDir, { recursive: true });
    this.#file = join(stateDir, "users.json");
    this.#storageKeys = encryptionKeys.map((key) => deriveKey(key, "signalward", "signalward/local-auth-storage/v1"));
    if (!existsSync(this.#file)) {
      this.#users = [];
      return;
    }
    const stored: unknown = JSON.parse(readFileSync(this.#file, "utf8"));
    if (isEncryptedJson(stored)) {
      this.#users = localUsersFrom(decryptJson(this.#storageKeys, stored, { required: true, context: "local-auth-users-v1" }));
      if (!isEncryptedWithKey(stored, this.#storageKeys[0]!)) this.#save();
    } else {
      this.#users = localUsersFrom(stored);
      this.#save();
    }
  }

  #save() {
    const temp = `${this.#file}.${process.pid}.tmp`;
    writeFileSync(temp, JSON.stringify(encryptJson(this.#storageKeys[0]!, { users: this.#users }, "local-auth-users-v1")), { mode: 0o600 });
    renameSync(temp, this.#file);
  }

  #find(email: string) {
    return this.#users.find((user) => user.email === email.toLowerCase());
  }

  #user(record: LocalRecord): User {
    return { id: record.id, email: record.email, emailConfirmed: true, createdAt: record.createdAt };
  }

  async #hash(password: string, salt: Buffer) {
    return scrypt(password.normalize("NFKC"), salt, 32, SCRYPT);
  }

  async signUp(email: string, password: string) {
    if (this.#find(email)) throw new AppError(409, "AUTH_EMAIL_TAKEN", "An account with this email already exists.", { field: "email" });
    const salt = randomBytes(16);
    const record: LocalRecord = { id: randomUUID(), email: email.toLowerCase(), salt: salt.toString("base64"), hash: (await this.#hash(password, salt)).toString("base64"), createdAt: new Date().toISOString(), sv: 1, failed: 0, lockedUntil: 0 };
    this.#users.push(record);
    this.#save();
    return { user: this.#user(record), tokens: null, sessionVersion: record.sv, needsConfirmation: false };
  }

  async signIn(email: string, password: string) {
    const record = this.#find(email);
    if (record && record.lockedUntil > Date.now()) {
      throw new AppError(429, "AUTH_LOCKED", "Too many failed attempts. This account is locked for a few minutes.", { retryAfter: Math.ceil((record.lockedUntil - Date.now()) / 1000) });
    }
    // Hash even for unknown emails so timing does not reveal which accounts exist.
    const computed = await this.#hash(password, record ? Buffer.from(record.salt, "base64") : this.#dummySalt);
    const ok = Boolean(record) && timingSafeEqual(computed, Buffer.from(record!.hash, "base64"));
    if (!record || !ok) {
      if (record) {
        record.failed += 1;
        if (record.failed >= 8) {
          record.lockedUntil = Date.now() + 5 * 60_000;
          record.failed = 0;
        }
        this.#save();
      }
      throw new AppError(401, "AUTH_INVALID_CREDENTIALS", "The email or password is incorrect.");
    }
    if (record.failed) {
      record.failed = 0;
      this.#save();
    }
    return { user: this.#user(record), tokens: null, sessionVersion: record.sv };
  }

  async refresh(): Promise<AuthResult> {
    throw unauthorized("Your session has ended. Sign in again.", "AUTH_SESSION_EXPIRED");
  }

  async verify(session: SessionData) {
    const record = this.#users.find((user) => user.id === session.uid);
    if (!record || record.sv !== session.sv) throw unauthorized("Your session has ended. Sign in again.", "AUTH_SESSION_EXPIRED");
    return this.#user(record);
  }

  async signOut(session: SessionData) {
    const record = this.#users.find((user) => user.id === session.uid);
    if (!record) return;
    record.sv += 1;
    this.#save();
  }

  async recover(): Promise<void> {
    throw new AppError(501, "AUTH_RECOVERY_UNAVAILABLE", "Password reset by email needs Supabase. Ask an administrator to reset local accounts.");
  }

  oauthUrl(): string | null {
    return null;
  }

  async magicLink(): Promise<void> {
    throw new AppError(501, "AUTH_MAGIC_UNAVAILABLE", "Magic-link sign-in needs Supabase. Use email and password for local accounts.");
  }

  async exchangeCode(): Promise<AuthResult> {
    throw new AppError(501, "AUTH_OAUTH_UNAVAILABLE", "Code exchange needs Supabase authentication.");
  }

  async updatePassword(session: SessionData, currentPassword: string, newPassword: string) {
    const record = this.#users.find((user) => user.id === session.uid);
    if (!record) throw unauthorized();
    await this.signIn(record.email, currentPassword).catch((error: unknown) => {
      if (error instanceof AppError && error.code === "AUTH_INVALID_CREDENTIALS") throw new AppError(401, "AUTH_INVALID_CREDENTIALS", "Your current password is incorrect.", { field: "currentPassword" });
      throw error;
    });
    const salt = randomBytes(16);
    record.salt = salt.toString("base64");
    record.hash = (await this.#hash(newPassword, salt)).toString("base64");
    record.sv += 1;
    this.#save();
    return { sessionVersion: record.sv };
  }
}

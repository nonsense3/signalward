import { existsSync, readFileSync } from "node:fs";
import { parseTrustedKeyHistory, type TrustedKey } from "../../../packages/receipts/src/index.ts";
import { parseIndicatorKeyHistory, parseReportEncryptionKeyHistory, type IndicatorMasterVersion } from "./security.ts";

/**
 * Environment loading and strict validation. Every problem is collected and reported together so a
 * misconfigured deployment fails at startup with one clear list, never at the first request.
 */

export type AuthProviderKind = "supabase" | "local";

export type Config = {
  nodeEnv: "development" | "production" | "test";
  host: string;
  port: number | null;
  publicUrl: string | null;
  stateDir: string;
  secureCookies: boolean;
  secrets: { session: string | null; indicator: string | null; signing: string | null; reportEncryption: string | null };
  previousSigningKeys: TrustedKey[];
  indicatorKeyVersion: string;
  previousIndicatorKeys: IndicatorMasterVersion[];
  previousReportEncryptionKeys: Buffer[];
  auth: {
    provider: AuthProviderKind;
    allowSignup: boolean;
    supabase: { url: string; anonKey: string } | null;
  };
  ai: { apiKey: string | null; model: string; timeoutMs: number };
  warnings: string[];
};

export class ConfigError extends Error {
  problems: string[];
  constructor(problems: string[]) {
    super(`Invalid configuration:\n  - ${problems.join("\n  - ")}`);
    this.problems = problems;
  }
}

/** Minimal dotenv parser: KEY=value, optional quotes, # comments, `export` prefix. No interpolation. */
export function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2] ?? "";
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote) && value.length >= 2) {
      value = value.slice(1, -1);
      if (quote === '"') value = value.replace(/\\n/g, "\n");
    } else {
      value = value.replace(/\s+#.*$/, "").trim();
    }
    out[match[1]!] = value;
  }
  return out;
}

/** Real environment variables win over the file, so deployments can override `.env`. */
export function loadEnvFile(file: string, base: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  if (!existsSync(file)) return { ...base };
  const parsed = parseDotenv(readFileSync(file, "utf8"));
  const merged: NodeJS.ProcessEnv = { ...parsed };
  for (const [key, value] of Object.entries(base)) if (value !== undefined && value !== "") merged[key] = value;
  return merged;
}

const blank = (value: string | undefined) => (value === undefined || value.trim() === "" ? null : value.trim());

function base64Bytes(value: string): number {
  if (!/^[A-Za-z0-9+/_-]+=*$/.test(value)) return -1;
  return Buffer.from(value, "base64").length;
}

export function readConfig(env: NodeJS.ProcessEnv, defaults: { stateDir: string }): Config {
  const problems: string[] = [];
  const warnings: string[] = [];

  const nodeEnv = (blank(env.NODE_ENV) ?? "development") as Config["nodeEnv"];
  if (!["development", "production", "test"].includes(nodeEnv)) problems.push(`NODE_ENV must be development, production or test (got "${env.NODE_ENV}").`);
  const production = nodeEnv === "production";

  const host = blank(env.HOST) ?? "127.0.0.1";
  if (!/^[A-Za-z0-9.:-]+$/.test(host)) problems.push("HOST must be a hostname or IP address.");

  let port: number | null = null;
  if (blank(env.PORT)) {
    port = Number(env.PORT);
    if (!Number.isInteger(port) || port < 1 || port > 65535) problems.push("PORT must be a whole number between 1 and 65535.");
  }

  let publicUrl = blank(env.PUBLIC_URL);
  if (publicUrl) {
    try {
      const url = new URL(publicUrl);
      if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("scheme");
      if (production && url.protocol !== "https:") problems.push("PUBLIC_URL must use https in production.");
      publicUrl = url.origin;
    } catch {
      problems.push("PUBLIC_URL must be an absolute http(s) URL, for example https://signalward.example.com.");
    }
  } else if (production) {
    problems.push("PUBLIC_URL is required in production (used for auth redirects and secure cookies).");
  }

  const secrets = {
    session: blank(env.SIGNALWARD_SESSION_SECRET),
    indicator: blank(env.SIGNALWARD_INDICATOR_KEY),
    signing: blank(env.SIGNALWARD_SIGNING_KEY),
    reportEncryption: blank(env.SIGNALWARD_REPORT_ENCRYPTION_KEY),
  };
  let previousSigningKeys: TrustedKey[] = [];
  try {
    previousSigningKeys = parseTrustedKeyHistory(blank(env.SIGNALWARD_PREVIOUS_SIGNING_KEYS));
  } catch (error) {
    problems.push(error instanceof Error ? error.message : "SIGNALWARD_PREVIOUS_SIGNING_KEYS is invalid.");
  }
  let previousIndicatorKeys: IndicatorMasterVersion[] = [];
  try {
    previousIndicatorKeys = parseIndicatorKeyHistory(blank(env.SIGNALWARD_PREVIOUS_INDICATOR_KEYS));
  } catch (error) {
    problems.push(error instanceof Error ? error.message : "SIGNALWARD_PREVIOUS_INDICATOR_KEYS is invalid.");
  }
  let previousReportEncryptionKeys: Buffer[] = [];
  try {
    previousReportEncryptionKeys = parseReportEncryptionKeyHistory(blank(env.SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS));
  } catch (error) {
    problems.push(error instanceof Error ? error.message : "SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS is invalid.");
  }
  const indicatorKeyVersion = blank(env.SIGNALWARD_INDICATOR_KEY_VERSION) ?? "k1";
  if (!/^k\d{1,6}$/.test(indicatorKeyVersion)) problems.push("SIGNALWARD_INDICATOR_KEY_VERSION must look like k1.");
  if (previousIndicatorKeys.some((item) => item.version === indicatorKeyVersion)) problems.push("The active and previous indicator key versions must be unique.");
  for (const [name, value] of [["SIGNALWARD_SESSION_SECRET", secrets.session], ["SIGNALWARD_INDICATOR_KEY", secrets.indicator], ["SIGNALWARD_REPORT_ENCRYPTION_KEY", secrets.reportEncryption]] as const) {
    if (value === null) {
      if (production) problems.push(`${name} is required in production. Generate one with: node apps/cli/signalward.ts keys`);
      else warnings.push(`${name} is empty; a local development value is generated under .signalward/.`);
    } else if (base64Bytes(value) < 32) {
      problems.push(`${name} must be at least 32 random bytes, base64 encoded.`);
    }
  }
  if (secrets.reportEncryption && base64Bytes(secrets.reportEncryption) !== 32) {
    problems.push("SIGNALWARD_REPORT_ENCRYPTION_KEY must be exactly 32 random bytes, base64 encoded.");
  }
  if (secrets.reportEncryption && previousReportEncryptionKeys.some((key) => key.equals(Buffer.from(secrets.reportEncryption!, "base64")))) {
    problems.push("The active and previous report-encryption keys must be unique.");
  }
  if (secrets.signing === null) {
    if (production) problems.push("SIGNALWARD_SIGNING_KEY is required in production (base64 PKCS#8 Ed25519).");
    else warnings.push("SIGNALWARD_SIGNING_KEY is empty; a local development Ed25519 key is generated under .signalward/.");
  } else if (base64Bytes(secrets.signing) < 40) {
    problems.push("SIGNALWARD_SIGNING_KEY must be a base64 PKCS#8 DER Ed25519 private key.");
  }

  const supabaseUrl = blank(env.SUPABASE_URL);
  const anonKey = blank(env.SUPABASE_ANON_KEY) ?? blank(env.SUPABASE_PUBLISHABLE_KEY);
  let supabase: Config["auth"]["supabase"] = null;
  if (supabaseUrl || anonKey) {
    if (!supabaseUrl) problems.push("SUPABASE_URL is required when SUPABASE_ANON_KEY is set.");
    if (!anonKey) problems.push("SUPABASE_ANON_KEY is required when SUPABASE_URL is set.");
    if (supabaseUrl) {
      try {
        const url = new URL(supabaseUrl);
        const local = ["localhost", "127.0.0.1"].includes(url.hostname);
        if (url.protocol !== "https:" && !(local && url.protocol === "http:")) problems.push("SUPABASE_URL must use https.");
        if (supabaseUrl && anonKey) supabase = { url: url.origin, anonKey };
      } catch {
        problems.push("SUPABASE_URL must be a URL such as https://<project-ref>.supabase.co.");
      }
    }
    if (anonKey && anonKey.length < 20) problems.push("SUPABASE_ANON_KEY looks truncated.");
  }
  if (blank(env.SUPABASE_SERVICE_ROLE_KEY)) warnings.push("SUPABASE_SERVICE_ROLE_KEY is set but unused. SignalWard only needs the anon key; remove the service key from this environment.");

  const requested = blank(env.AUTH_PROVIDER) ?? "auto";
  let provider: AuthProviderKind = "local";
  if (!["auto", "supabase", "local"].includes(requested)) problems.push("AUTH_PROVIDER must be auto, supabase or local.");
  else if (requested === "supabase") {
    if (!supabaseUrl || !anonKey) problems.push("AUTH_PROVIDER=supabase requires SUPABASE_URL and SUPABASE_ANON_KEY.");
    provider = "supabase";
  } else if (requested === "auto") provider = supabase ? "supabase" : "local";
  if (provider === "local") {
    if (production) warnings.push("Using local accounts in production. Configure Supabase for managed auth, email verification and recovery.");
    else warnings.push("Supabase is not configured; using local accounts stored under .signalward/.");
  }

  const allowSignupRaw = blank(env.ALLOW_SIGNUP) ?? "true";
  if (!["true", "false"].includes(allowSignupRaw)) problems.push("ALLOW_SIGNUP must be true or false.");

  const aiKey = blank(env.GEMINI_API_KEY);
  const model = blank(env.GEMINI_MODEL) ?? "gemini-2.5-flash";
  if (!/^[a-z0-9][a-z0-9.\-]{2,63}$/.test(model)) problems.push("GEMINI_MODEL must be a model name such as gemini-2.5-flash.");
  const timeoutMs = Number(blank(env.GEMINI_TIMEOUT_MS) ?? 7000);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) problems.push("GEMINI_TIMEOUT_MS must be between 1000 and 30000.");
  if (!aiKey) warnings.push("GEMINI_API_KEY is empty; report summaries use the deterministic fallback.");

  if (problems.length) throw new ConfigError(problems);

  return {
    nodeEnv,
    host,
    port,
    publicUrl,
    stateDir: blank(env.SIGNALWARD_STATE_DIR) ?? defaults.stateDir,
    secureCookies: production || (publicUrl?.startsWith("https://") ?? false),
    secrets,
    previousSigningKeys,
    indicatorKeyVersion,
    previousIndicatorKeys,
    previousReportEncryptionKeys,
    auth: { provider, allowSignup: allowSignupRaw === "true", supabase: provider === "supabase" ? supabase : null },
    ai: { apiKey: aiKey, model, timeoutMs },
    warnings,
  };
}

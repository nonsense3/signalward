/** Typed application errors. Every API failure leaves the server as { error: { code, message, field?, requestId } }. */
export class AppError extends Error {
  status: number;
  code: string;
  field: string | undefined;
  retryAfter: number | undefined;
  constructor(status: number, code: string, message: string, options: { field?: string; retryAfter?: number; cause?: unknown } = {}) {
    super(message, { cause: options.cause });
    this.status = status;
    this.code = code;
    this.field = options.field;
    this.retryAfter = options.retryAfter;
  }
}

export const badRequest = (code: string, message: string, field?: string) => new AppError(400, code, message, field ? { field } : {});
export const unauthorized = (message = "Sign in to continue.", code = "AUTH_REQUIRED") => new AppError(401, code, message);
export const forbidden = (message: string, code = "FORBIDDEN") => new AppError(403, code, message);
export const notFound = (message = "Not found.") => new AppError(404, "NOT_FOUND", message);
export const rateLimited = (retryAfter: number, message?: string) =>
  new AppError(429, "RATE_LIMITED", message ?? `Too many requests. Try again in ${retryAfter} s.`, { retryAfter });
export const unavailable = (code: string, message: string, cause?: unknown) => new AppError(503, code, message, { cause });

type FieldRule = { type: "string" | "number" | "boolean" | "array" | "object"; required?: boolean; max?: number; min?: number; pattern?: RegExp; label?: string };

/**
 * Validate a JSON body against an explicit field list. Unknown fields are rejected so typos and
 * injected properties fail loudly instead of being ignored.
 */
export function validate<T extends Record<string, unknown>>(body: Record<string, unknown>, rules: Record<keyof T & string, FieldRule>): T {
  for (const key of Object.keys(body)) {
    if (!(key in rules)) throw badRequest("UNKNOWN_FIELD", `Unexpected field "${key.slice(0, 40)}".`, key.slice(0, 40));
  }
  const out: Record<string, unknown> = {};
  for (const [key, rule] of Object.entries(rules)) {
    const label = rule.label ?? key;
    let value = body[key];
    if (typeof value === "string" && rule.type === "string") value = value.trim();
    const missing = value === undefined || value === null || value === "";
    if (missing) {
      if (rule.required) throw badRequest("FIELD_REQUIRED", `${label} is required.`, key);
      continue;
    }
    const actual = Array.isArray(value) ? "array" : typeof value;
    if (actual !== rule.type) throw badRequest("FIELD_INVALID", `${label} must be ${rule.type === "array" ? "a list" : `a ${rule.type}`}.`, key);
    if (rule.type === "string") {
      const text = value as string;
      if (rule.max !== undefined && text.length > rule.max) throw badRequest("FIELD_TOO_LONG", `${label} must be at most ${rule.max} characters.`, key);
      if (rule.min !== undefined && text.length < rule.min) throw badRequest("FIELD_TOO_SHORT", `${label} must be at least ${rule.min} characters.`, key);
      if (rule.pattern && !rule.pattern.test(text)) throw badRequest("FIELD_INVALID", `${label} is not in the expected format.`, key);
    }
    if (rule.type === "number") {
      const n = value as number;
      if (!Number.isFinite(n)) throw badRequest("FIELD_INVALID", `${label} must be a number.`, key);
      if (rule.min !== undefined && n < rule.min) throw badRequest("FIELD_INVALID", `${label} must be at least ${rule.min}.`, key);
      if (rule.max !== undefined && n > rule.max) throw badRequest("FIELD_INVALID", `${label} must be at most ${rule.max}.`, key);
    }
    if (rule.type === "array" && rule.max !== undefined && (value as unknown[]).length > rule.max) {
      throw badRequest("FIELD_TOO_LONG", `${label} can contain at most ${rule.max} items.`, key);
    }
    out[key] = value;
  }
  return out as T;
}

export const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,24}$/;

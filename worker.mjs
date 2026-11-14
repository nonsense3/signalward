/**
 * Cloudflare Workers entry for SignalWard.
 *
 * Reuses the Node API router through a small Request -> Node-style adapter and serves static files
 * from the ASSETS binding. Workers have no filesystem, so the Worker runs in production mode:
 * Supabase and every SignalWard secret must be set (see README, "Deploy to Cloudflare").
 * Live events (SSE) are not available on Workers; the console falls back to polling-free operation.
 */
import { Buffer } from "node:buffer";
import { createApi } from "./apps/web/src/api.ts";
import { SupabaseAuth } from "./apps/web/src/auth.ts";
import { ConfigError, readConfig } from "./apps/web/src/env.ts";
import { SECURITY_HEADERS, deriveKey } from "./apps/web/src/security.ts";
import { SupabaseStore } from "./apps/web/src/store.ts";
import { loadSigningKey } from "./packages/receipts/src/index.ts";

// Cloudflare's asset handler serves /scan from scan.html and redirects /scan.html -> /scan,
// so routes map to extensionless paths. Only the OAuth callback needs an alias.
const APP_ROUTES = { "/": "/", "/scan": "/scan", "/account": "/account", "/auth": "/auth", "/auth/callback": "/auth", "/verify": "/verify" };
const PROTECTED = new Set(["/scan", "/account"]);

let cached = null;

function build(env) {
  if (cached) return cached;
  const vars = {};
  for (const [key, value] of Object.entries(env)) if (typeof value === "string") vars[key] = value;
  vars.NODE_ENV = "production";
  vars.AUTH_PROVIDER = "supabase";
  const config = readConfig(vars, { stateDir: "/tmp/signalward" });
  const supabase = config.auth.supabase;
  const reportEncryptionKeys = [Buffer.from(config.secrets.reportEncryption, "base64"), ...config.previousReportEncryptionKeys];
  const api = createApi({
    auth: new SupabaseAuth(supabase.url, supabase.anonKey),
    store: new SupabaseStore(supabase.url, supabase.anonKey, reportEncryptionKeys),
    cookieKey: deriveKey(Buffer.from(config.secrets.session, "base64"), "signalward", "signalward/cookie/v1"),
    indicatorMaster: Buffer.from(config.secrets.indicator, "base64"),
    indicatorKeyVersion: config.indicatorKeyVersion,
    previousIndicatorKeys: config.previousIndicatorKeys,
    signingKey: loadSigningKey(config.stateDir, { SIGNALWARD_SIGNING_KEY: config.secrets.signing }),
    previousSigningKeys: config.previousSigningKeys,
    ai: config.ai,
    urlIntel: config.urlIntel,
    publicUrl: config.publicUrl,
    secureCookies: true,
    allowSignup: config.auth.allowSignup,
  });
  cached = api;
  return api;
}

function applyHeaders(target, headers) {
  if (!headers) return;
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) for (const item of value) target.append(key, String(item));
    else if (value !== undefined) target.set(key, String(value));
  }
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" } });
}

/** Run the Node-style router against a Web Request and collect a Web Response. */
async function runApi(api, request, path) {
  const url = new URL(request.url);
  const body = request.method === "GET" || request.method === "HEAD" ? null : Buffer.from(await request.arrayBuffer());
  const req = {
    method: request.method,
    url: url.pathname + url.search,
    headers: Object.fromEntries(request.headers),
    socket: { remoteAddress: request.headers.get("cf-connecting-ip") || "0.0.0.0" },
    on() {},
    async *[Symbol.asyncIterator]() {
      if (body && body.length) yield body;
    },
  };
  let status = 200;
  const headers = new Headers();
  const chunks = [];
  let finish;
  const finished = new Promise((resolve) => (finish = resolve));
  const res = {
    headersSent: false,
    writeHead(code, headerObject) {
      status = code;
      applyHeaders(headers, headerObject);
      this.headersSent = true;
      return this;
    },
    write(chunk) {
      if (chunk) chunks.push(Buffer.from(chunk));
      return true;
    },
    end(chunk) {
      if (chunk) chunks.push(Buffer.from(chunk));
      finish();
    },
    on() {},
  };
  const handled = await api.handle(req, res, path);
  if (!handled) return null;
  await finished;
  return new Response(chunks.length ? Buffer.concat(chunks) : null, { status, headers });
}

async function serveAsset(env, request, url, path) {
  const mapped = APP_ROUTES[path];
  let response = await env.ASSETS.fetch(new Request(new URL(mapped ?? path, url.origin), request));
  if (response.status === 404) {
    const page = await env.ASSETS.fetch(new Request(new URL("/404", url.origin), request));
    response = new Response(page.body, { status: 404, headers: page.headers });
  }
  const headers = new Headers(response.headers);
  applyHeaders(headers, SECURITY_HEADERS);
  return new Response(response.body, { status: response.status, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    let path = url.pathname;
    if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
    if (path.endsWith(".html") && APP_ROUTES[path.slice(0, -5)]) path = path.slice(0, -5);
    if (path === "/index") path = "/";

    const isApi = path.startsWith("/api/") || path === "/.well-known/signalward-keys.json";
    let api = null;
    if (isApi || PROTECTED.has(path)) {
      try {
        api = build(env);
      } catch (error) {
        const message = error instanceof ConfigError ? error.problems.join(" ") : error instanceof Error ? error.message : "Configuration error.";
        return json(503, { error: { code: "NOT_CONFIGURED", message } });
      }
    }

    if (isApi) {
      if (path === "/api/events") return json(501, { error: { code: "SSE_UNAVAILABLE", message: "Live events are not available on this deployment." } });
      try {
        const response = await runApi(api, request, path);
        return response ?? json(404, { error: { code: "NOT_FOUND", message: "Unknown API route." } });
      } catch (error) {
        console.error("worker api error", error instanceof Error ? error.stack : error);
        return json(500, { error: { code: "INTERNAL", message: "Something went wrong on our side. Try again." } });
      }
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", { status: 405, headers: { ...SECURITY_HEADERS, Allow: "GET, HEAD" } });
    }
    if (PROTECTED.has(path) && !api.hasSession({ headers: Object.fromEntries(request.headers) })) {
      return new Response(null, { status: 303, headers: { ...SECURITY_HEADERS, Location: `/auth?next=${encodeURIComponent(path + url.search)}` } });
    }
    return serveAsset(env, request, url, path);
  },
};

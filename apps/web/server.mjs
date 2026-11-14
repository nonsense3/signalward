import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createApi } from "./src/api.ts";
import { LocalAuth, SupabaseAuth } from "./src/auth.ts";
import { ConfigError, loadEnvFile, readConfig } from "./src/env.ts";
import { SECURITY_HEADERS, deriveKey, resolveSecret } from "./src/security.ts";
import { LocalStore, SupabaseStore } from "./src/store.ts";
import { loadSigningKey } from "../../packages/receipts/src/index.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));

let config;
try {
  config = readConfig(loadEnvFile(`${root}.env`), { stateDir: `${root}.signalward` });
} catch (error) {
  if (error instanceof ConfigError) {
    console.error(`SignalWard cannot start.\n${error.message}\n\nEdit .env (see .env.example) and try again.`);
    process.exit(1);
  }
  throw error;
}

const sessionSecret = resolveSecret(config.secrets.session, config.stateDir, "session-secret");
const reportEncryptionKey = resolveSecret(config.secrets.reportEncryption, config.stateDir, "report-encryption-key");
const reportEncryptionKeys = [reportEncryptionKey, ...config.previousReportEncryptionKeys];
const supabase = config.auth.supabase;
const api = createApi({
  auth: supabase ? new SupabaseAuth(supabase.url, supabase.anonKey) : new LocalAuth(config.stateDir, reportEncryptionKeys),
  store: supabase ? new SupabaseStore(supabase.url, supabase.anonKey, reportEncryptionKeys) : new LocalStore(config.stateDir, reportEncryptionKeys),
  cookieKey: deriveKey(sessionSecret, "signalward", "signalward/cookie/v1"),
  indicatorMaster: resolveSecret(config.secrets.indicator, config.stateDir, "indicator-master"),
  indicatorKeyVersion: config.indicatorKeyVersion,
  previousIndicatorKeys: config.previousIndicatorKeys,
  signingKey: loadSigningKey(config.stateDir, config.secrets.signing ? { SIGNALWARD_SIGNING_KEY: config.secrets.signing } : {}),
  previousSigningKeys: config.previousSigningKeys,
  ai: config.ai,
  urlIntel: config.urlIntel,
  urlHausAuthKey: config.urlHausAuthKey,
  urlRiskModel: config.urlRiskModel,
  publicUrl: config.publicUrl,
  secureCookies: config.secureCookies,
  allowSignup: config.auth.allowSignup,
});

const html = (file) => [file, "text/html; charset=utf-8"];
/** Explicit allowlist: nothing outside this table is served, so path traversal has nothing to reach. */
const assets = new Map([
  ["/", html("index.html")],
  ["/scan", html("scan.html")],
  ["/account", html("account.html")],
  ["/auth", html("auth.html")],
  ["/auth/callback", html("auth.html")],
  ["/verify", html("verify.html")],
  ...["base.css", "site.css", "app.css"].map((name) => [`/${name}`, [name, "text/css; charset=utf-8"]]),
  ...["theme.js", "ui.js", "site.js", "scene.js", "shapes.js", "footer-logo.js", "console.js", "verify.js", "verify-page.js", "auth.js", "account.js"].map((name) => [`/${name}`, [name, "text/javascript; charset=utf-8"]]),
  ["/poster.svg", ["poster.svg", "image/svg+xml"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml"]],
  ...["MonaSansVF.woff2", "HubotSansVF.woff2", "MonaspaceNeon-Regular.woff2"].map((name) => [`/fonts/${name}`, [`fonts/${name}`, "font/woff2"]]),
]);
const PROTECTED = new Set(["/scan", "/account"]);

async function notFoundPage(response) {
  response.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/html; charset=utf-8" });
  response.end(await readFile(new URL("./public/404.html", import.meta.url)).catch(() => "Not found"));
}

export async function handleRequest(request, response) {
  let url;
  try {
    url = new URL(request.url ?? "/", "http://localhost");
  } catch {
    response.writeHead(400, SECURITY_HEADERS).end("Bad request");
    return;
  }
  let path = url.pathname;
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  if (path.endsWith(".html") && assets.has(path.slice(0, -5))) path = path.slice(0, -5);

  if (await api.handle(request, response, path)) return;

  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { ...SECURITY_HEADERS, Allow: "GET, HEAD" }).end();
    return;
  }
  const asset = assets.get(path);
  if (!asset) return notFoundPage(response);
  if (PROTECTED.has(path) && !api.hasSession(request)) {
    response.writeHead(303, { ...SECURITY_HEADERS, Location: `/auth?next=${encodeURIComponent(path + url.search)}` }).end();
    return;
  }
  try {
    const body = await readFile(new URL(`./public/${asset[0]}`, import.meta.url));
    const cache = asset[1].startsWith("font/") ? "public, max-age=31536000, immutable" : "no-cache";
    response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": asset[1], "Cache-Control": cache });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch {
    response.writeHead(500, SECURITY_HEADERS).end("Could not load asset");
  }
}

process.on("unhandledRejection", (reason) => console.error("Unhandled rejection:", reason instanceof Error ? reason.stack : reason));

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = config.port ?? 3000;
  const server = createServer({ requestTimeout: 60_000, headersTimeout: 15_000 }, (request, response) => {
    handleRequest(request, response).catch((error) => {
      console.error("Request failed:", error);
      if (!response.headersSent) response.writeHead(500, SECURITY_HEADERS);
      response.end();
    });
  });
  server.on("clientError", (_error, socket) => socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"));
  let triedFallback = false;
  server.on("error", (error) => {
    if (error.code === "EADDRINUSE" && config.port === null && !triedFallback) {
      console.log(`Port ${port} is in use. Selecting an available port.`);
      triedFallback = true;
      server.listen(0, config.host);
      return;
    }
    console.error(`SignalWard could not start. ${error.message}`);
    process.exitCode = 1;
  });
  server.on("listening", () => {
    const address = `http://${config.host}:${server.address().port}`;
    console.log(`SignalWard is running at ${address}`);
    console.log(`  auth: ${config.auth.provider}${config.auth.provider === "supabase" ? ` (${new URL(config.auth.supabase.url).host})` : ""}  ·  summaries: ${config.ai.apiKey ? config.ai.model : "rules"}  ·  env: ${config.nodeEnv}`);
    for (const warning of config.warnings) console.log(`  note: ${warning}`);
  });
  server.listen(port, config.host);
}

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createApi } from "./src/api.ts";
import { SECURITY_HEADERS, loadSecret } from "./src/security.ts";
import { loadSigningKey } from "../../packages/receipts/src/index.ts";

const stateDir = process.env.SIGNALWARD_STATE_DIR ?? fileURLToPath(new URL("../../.signalward/", import.meta.url));

const api = createApi({
  sessionSecret: loadSecret(stateDir, "SIGNALWARD_SESSION_SECRET", "session-secret"),
  indicatorMaster: loadSecret(stateDir, "SIGNALWARD_INDICATOR_KEY", "indicator-master"),
  signingKey: loadSigningKey(stateDir),
});

/** Explicit allowlist: nothing outside this table is served, so path traversal has nothing to reach. */
const assets = new Map([
  ["/", ["index.html", "text/html; charset=utf-8"]],
  ["/scan", ["scan.html", "text/html; charset=utf-8"]],
  ["/site.css", ["site.css", "text/css; charset=utf-8"]],
  ["/app.css", ["app.css", "text/css; charset=utf-8"]],
  ["/site.js", ["site.js", "text/javascript; charset=utf-8"]],
  ["/scene.js", ["scene.js", "text/javascript; charset=utf-8"]],
  ["/shapes.js", ["shapes.js", "text/javascript; charset=utf-8"]],
  ["/console.js", ["console.js", "text/javascript; charset=utf-8"]],
  ["/verify.js", ["verify.js", "text/javascript; charset=utf-8"]],
  ["/poster.svg", ["poster.svg", "image/svg+xml"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml"]],
  ["/fonts/MonaSansVF.woff2", ["fonts/MonaSansVF.woff2", "font/woff2"]],
  ["/fonts/MonaspaceNeon-Regular.woff2", ["fonts/MonaspaceNeon-Regular.woff2", "font/woff2"]],
]);

export async function handleRequest(request, response) {
  let path;
  try {
    path = new URL(request.url ?? "/", "http://localhost").pathname;
  } catch {
    response.writeHead(400).end("Bad request");
    return;
  }
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);
  if (path === "/scan.html") path = "/scan";

  if (await api.handle(request, response, path)) return;

  const asset = (request.method === "GET" || request.method === "HEAD") && assets.get(path);
  if (!asset) {
    response.writeHead(404, { ...SECURITY_HEADERS, "Content-Type": "text/plain; charset=utf-8" }).end("Not found");
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

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const configuredPort = process.env.PORT;
  const port = Number(configuredPort ?? 3000);

  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("Set PORT to a whole number between 1 and 65535.");
    process.exitCode = 1;
  } else {
    const server = createServer({ requestTimeout: 30_000, headersTimeout: 10_000 }, handleRequest);
    let triedFallback = false;
    server.on("error", error => {
      if (error.code === "EADDRINUSE" && configuredPort === undefined && !triedFallback) {
        console.log(`Port ${port} is in use. Selecting an available local port.`);
        triedFallback = true;
        server.listen(0, "127.0.0.1");
        return;
      }
      console.error(`SignalWard could not start. ${error.message}`);
      process.exitCode = 1;
    });
    server.on("listening", () => {
      const url = `http://127.0.0.1:${server.address().port}`;
      console.log(`SignalWard is running at ${url}`);
      console.log(`Scanner console: ${url}/scan`);
    });
    server.listen(port, "127.0.0.1");
  }
}

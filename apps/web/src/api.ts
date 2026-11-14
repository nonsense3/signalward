import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Receipt, Report } from "../../../packages/contracts/src/index.ts";
import { ScanInputError, primaryAction, runMessageScan, runRepositoryScan, runUrlScan, type WorkspaceContext } from "../../../packages/engine/src/index.ts";
import { MESSAGE_LIMIT, SAMPLE_MESSAGES } from "../../../packages/fraud-scan/src/index.ts";
import { LIMITS, type SourceFile } from "../../../packages/repo-scan/src/index.ts";
import { remediatedRepository, syntheticRepository } from "../../../packages/repo-scan/src/fixture.ts";
import { issueReceipt, trustedKeySet, verifyReceipt, type SigningKey } from "../../../packages/receipts/src/index.ts";
import {
  RateLimiter, SECURITY_HEADERS, SESSION_COOKIE, SESSION_TTL_SECONDS, deriveIndicatorKey, readCookie, sameOrigin,
  sessionCookie, signSession, verifySession, type SessionClaims,
} from "./security.ts";

const KEY_VERSION = "k1";
const MAX_REPORTS = 200;
const MAX_WORKSPACES = 500;

type StoredReport = { report: Report; receipt: Receipt };
type Workspace = {
  id: string;
  createdAt: number;
  indicatorKey: Buffer;
  reports: Map<string, StoredReport>;
  seen: Map<string, number>;
  blocklist: Map<string, { type: string; display: string; addedAt: string; reportId: string }>;
  listeners: Set<ServerResponse>;
};

export type ApiConfig = { sessionSecret: Buffer; indicatorMaster: Buffer; signingKey: SigningKey };

class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function createApi(config: ApiConfig) {
  const workspaces = new Map<string, Workspace>();
  const ipLimiter = new RateLimiter(300, 60_000);
  const scanLimiter = new RateLimiter(40, 60_000);
  const sessionLimiter = new RateLimiter(20, 60_000);

  function workspaceFor(claims: SessionClaims): Workspace {
    let workspace = workspaces.get(claims.wid);
    if (!workspace) {
      if (workspaces.size >= MAX_WORKSPACES) {
        const oldest = [...workspaces.values()].sort((a, b) => a.createdAt - b.createdAt)[0];
        if (oldest) dropWorkspace(oldest.id);
      }
      workspace = {
        id: claims.wid, createdAt: Date.now(), indicatorKey: deriveIndicatorKey(config.indicatorMaster, claims.wid, KEY_VERSION),
        reports: new Map(), seen: new Map(), blocklist: new Map(), listeners: new Set(),
      };
      workspaces.set(claims.wid, workspace);
    }
    return workspace;
  }

  function dropWorkspace(id: string) {
    const workspace = workspaces.get(id);
    if (!workspace) return;
    for (const listener of workspace.listeners) listener.end();
    workspace.indicatorKey.fill(0);
    workspaces.delete(id);
  }

  function context(workspace: Workspace): WorkspaceContext {
    return {
      workspace: workspace.id,
      indicatorKey: workspace.indicatorKey,
      keyVersion: KEY_VERSION,
      observe(tag) {
        const count = workspace.seen.get(tag) ?? 0;
        workspace.seen.set(tag, count + 1);
        return count;
      },
      isBlocked: (tag) => workspace.blocklist.has(tag),
    };
  }

  /** Broadcast status only. Events never carry content, indicators or findings. */
  function broadcast(workspace: Workspace, event: Record<string, unknown>) {
    const line = `event: activity\ndata: ${JSON.stringify({ ...event, at: new Date().toISOString() })}\n\n`;
    for (const listener of workspace.listeners) listener.write(line);
  }

  function store(workspace: Workspace, report: Report): StoredReport {
    const receipt = issueReceipt(report, primaryAction(report), config.signingKey);
    workspace.reports.set(report.id, { report, receipt });
    if (workspace.reports.size > MAX_REPORTS) workspace.reports.delete(workspace.reports.keys().next().value as string);
    broadcast(workspace, { type: "scan.completed", reportId: report.id, kind: report.kind, verdict: report.verdict, findings: report.findings.length });
    return { report, receipt };
  }

  function send(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
    response.writeHead(status, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
    response.end(JSON.stringify(body));
  }

  async function readJson(request: IncomingMessage, limit: number): Promise<Record<string, unknown>> {
    if (!/^application\/json\b/i.test(request.headers["content-type"] ?? "")) throw new HttpError(415, "UNSUPPORTED_MEDIA_TYPE", "Send JSON with Content-Type: application/json.");
    const declared = Number(request.headers["content-length"] ?? 0);
    if (declared > limit) throw new HttpError(413, "PAYLOAD_TOO_LARGE", `The request is larger than ${Math.round(limit / 1_000_000)} MB.`);
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += (chunk as Buffer).length;
      if (size > limit) throw new HttpError(413, "PAYLOAD_TOO_LARGE", `The request is larger than ${Math.round(limit / 1_000_000)} MB.`);
      chunks.push(chunk as Buffer);
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      return parsed as Record<string, unknown>;
    } catch {
      throw new HttpError(400, "INVALID_JSON", "The request body is not a JSON object.");
    }
  }

  function optionalString(body: Record<string, unknown>, key: string, max: number): string | undefined {
    const value = body[key];
    if (value === undefined || value === null || value === "") return undefined;
    if (typeof value !== "string") throw new HttpError(400, "INVALID_FIELD", `${key} must be a string.`);
    if (value.length > max) throw new HttpError(400, "FIELD_TOO_LONG", `${key} is longer than ${max} characters.`);
    return value;
  }

  function parseFiles(value: unknown): SourceFile[] {
    if (!Array.isArray(value) || !value.length) throw new HttpError(400, "NO_FILES", "Choose a folder or files to scan.");
    if (value.length > LIMITS.maxFiles) throw new HttpError(400, "TOO_MANY_FILES", `Scan at most ${LIMITS.maxFiles} files at once.`);
    return value.map((item, index) => {
      const file = item as { path?: unknown; content?: unknown };
      if (typeof file?.path !== "string" || typeof file.content !== "string") throw new HttpError(400, "INVALID_FILE", `File ${index + 1} needs a path and text content.`);
      return { path: file.path, content: file.content };
    });
  }

  function requireSession(request: IncomingMessage): { claims: SessionClaims; workspace: Workspace } {
    const claims = verifySession(config.sessionSecret, readCookie(request, SESSION_COOKIE));
    if (!claims) throw new HttpError(401, "SESSION_REQUIRED", "Your workspace session is missing or expired. Reload the console.");
    return { claims, workspace: workspaceFor(claims) };
  }

  function sessionView(claims: SessionClaims, workspace: Workspace) {
    return {
      workspace: claims.wid,
      session: claims.sid,
      issuedAt: new Date(claims.iat * 1000).toISOString(),
      expiresAt: new Date(claims.exp * 1000).toISOString(),
      indicatorKeyVersion: KEY_VERSION,
      signingKeyId: config.signingKey.keyId,
      reports: workspace.reports.size,
      blocked: workspace.blocklist.size,
    };
  }

  function summary({ report }: StoredReport) {
    return { id: report.id, kind: report.kind, verdict: report.verdict, createdAt: report.createdAt, findings: report.findings.length, summary: report.summary };
  }

  async function route(request: IncomingMessage, response: ServerResponse, path: string): Promise<boolean> {
    const method = request.method ?? "GET";

    if (path === "/.well-known/signalward-keys.json" && method === "GET") {
      send(response, 200, trustedKeySet(config.signingKey), { "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" });
      return true;
    }
    if (!path.startsWith("/api/")) return false;

    const ip = request.socket.remoteAddress ?? "unknown";
    const ipRate = ipLimiter.take(ip);
    if (!ipRate.ok) throw new HttpError(429, "RATE_LIMITED", `Too many requests. Retry in ${ipRate.retryAfter} s.`);
    if (method !== "GET" && !sameOrigin(request)) throw new HttpError(403, "CROSS_ORIGIN", "Cross-origin requests are refused.");

    if (path === "/api/session" && method === "POST") {
      const existing = verifySession(config.sessionSecret, readCookie(request, SESSION_COOKIE));
      if (existing) {
        send(response, 200, sessionView(existing, workspaceFor(existing)));
        return true;
      }
      if (!sessionLimiter.take(ip).ok) throw new HttpError(429, "RATE_LIMITED", "Too many new sessions from this address.");
      const now = Math.floor(Date.now() / 1000);
      const claims: SessionClaims = { v: 1, wid: `ws_${randomBytes(6).toString("base64url")}`, sid: randomBytes(9).toString("base64url"), iat: now, exp: now + SESSION_TTL_SECONDS };
      send(response, 201, sessionView(claims, workspaceFor(claims)), { "Set-Cookie": sessionCookie(signSession(config.sessionSecret, claims), SESSION_TTL_SECONDS) });
      return true;
    }
    if (path === "/api/session/end" && method === "POST") {
      const claims = verifySession(config.sessionSecret, readCookie(request, SESSION_COOKIE));
      if (claims) dropWorkspace(claims.wid);
      send(response, 200, { ended: Boolean(claims), deleted: "Reports, indicator history, blocklist and the derived indicator key were erased." }, { "Set-Cookie": sessionCookie("", 0) });
      return true;
    }

    if (path === "/api/sample-scan" && method === "POST") {
      const seen = new Map<string, number>();
      const report = runRepositoryScan(syntheticRepository(), "synthetic fixture", {
        workspace: "ws_public_demo", indicatorKey: randomBytes(32), keyVersion: KEY_VERSION,
        observe: (tag) => { const count = seen.get(tag) ?? 0; seen.set(tag, count + 1); return count; },
        isBlocked: () => false,
      });
      const top = report.findings.find((item) => item.category === "secret");
      send(response, 200, {
        fixture: true, result: report.verdict, summary: report.summary, findings: report.findings.length,
        finding: top && { title: top.title, location: `${top.location?.path}:${top.location?.line}`, evidence: top.evidence[0]?.value, remediation: top.remediation },
      });
      return true;
    }

    if (path === "/api/verify" && method === "POST") {
      const body = await readJson(request, 2_000_000);
      send(response, 200, verifyReceipt(body.receipt, trustedKeySet(config.signingKey).keys, body.report));
      return true;
    }

    const { claims, workspace } = requireSession(request);

    if (path === "/api/session" && method === "GET") {
      send(response, 200, sessionView(claims, workspace));
      return true;
    }

    if (path.startsWith("/api/scans/") && method === "POST") {
      const scanRate = scanLimiter.take(workspace.id);
      if (!scanRate.ok) throw new HttpError(429, "RATE_LIMITED", `Scan limit reached. Retry in ${scanRate.retryAfter} s.`);
      const kind = path.slice("/api/scans/".length);
      broadcast(workspace, { type: "scan.started", kind });
      let report: Report;
      if (kind === "repository") {
        const body = await readJson(request, LIMITS.maxTotalBytes + 2_000_000);
        const sample = optionalString(body, "sample", 20);
        const label = optionalString(body, "label", 120) ?? "uploaded files";
        if (sample === "vulnerable") report = runRepositoryScan(syntheticRepository(), "synthetic fixture (vulnerable)", context(workspace));
        else if (sample === "remediated") report = runRepositoryScan(remediatedRepository(), "synthetic fixture (remediated)", context(workspace));
        else report = runRepositoryScan(parseFiles(body.files), label, context(workspace));
      } else if (kind === "message") {
        const body = await readJson(request, 200_000);
        const sample = optionalString(body, "sample", 20);
        if (sample === "scam" || sample === "benign") {
          report = runMessageScan({ ...SAMPLE_MESSAGES[sample] }, context(workspace));
        } else {
          const text = optionalString(body, "text", MESSAGE_LIMIT);
          if (!text?.trim()) throw new HttpError(400, "NO_TEXT", "Paste the message text to analyse.");
          const sender = optionalString(body, "sender", 320);
          const subject = optionalString(body, "subject", 500);
          report = runMessageScan({ text, ...(sender ? { sender } : {}), ...(subject ? { subject } : {}) }, context(workspace));
        }
      } else if (kind === "url") {
        const body = await readJson(request, 20_000);
        const url = optionalString(body, "url", 2048);
        if (!url) throw new HttpError(400, "NO_URL", "Enter a link or domain.");
        try {
          report = runUrlScan(url, context(workspace));
        } catch (error) {
          if (error instanceof ScanInputError) throw new HttpError(422, error.code, error.message);
          throw error;
        }
      } else {
        throw new HttpError(404, "NOT_FOUND", "Unknown scan type.");
      }
      send(response, 201, store(workspace, report));
      return true;
    }

    if (path === "/api/reports" && method === "GET") {
      send(response, 200, { reports: [...workspace.reports.values()].reverse().map(summary) });
      return true;
    }
    const reportMatch = /^\/api\/reports\/(rpt_[A-Za-z0-9_-]{6,32})$/.exec(path);
    if (reportMatch && method === "GET") {
      // Reports from other workspaces are indistinguishable from missing ones.
      const stored = workspace.reports.get(reportMatch[1]!);
      if (!stored) throw new HttpError(404, "NOT_FOUND", "No report with that ID in this workspace.");
      send(response, 200, stored);
      return true;
    }

    if (path === "/api/blocklist" && method === "GET") {
      send(response, 200, { entries: [...workspace.blocklist.entries()].map(([tag, entry]) => ({ tag, ...entry })) });
      return true;
    }
    if (path === "/api/blocklist" && method === "POST") {
      const body = await readJson(request, 10_000);
      const tag = optionalString(body, "tag", 80);
      if (!tag) throw new HttpError(400, "NO_TAG", "Choose an indicator to block.");
      if (body.remove === true) {
        workspace.blocklist.delete(tag);
        broadcast(workspace, { type: "blocklist.removed" });
      } else {
        const reportId = optionalString(body, "reportId", 40) ?? "";
        const indicator = workspace.reports.get(reportId)?.report.indicators.find((item) => item.tag === tag);
        if (!indicator) throw new HttpError(404, "NOT_FOUND", "That indicator is not in a report from this workspace.");
        workspace.blocklist.set(tag, { type: indicator.type, display: indicator.display, addedAt: new Date().toISOString(), reportId });
        broadcast(workspace, { type: "blocklist.added", indicatorType: indicator.type });
      }
      send(response, 200, { entries: [...workspace.blocklist.entries()].map(([entryTag, entry]) => ({ tag: entryTag, ...entry })) });
      return true;
    }

    if (path === "/api/events" && method === "GET") {
      response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive" });
      response.write(`retry: 4000\nevent: ready\ndata: ${JSON.stringify({ workspace: workspace.id })}\n\n`);
      if (workspace.listeners.size >= 8) [...workspace.listeners][0]?.end();
      workspace.listeners.add(response);
      const ping = setInterval(() => response.write(": ping\n\n"), 25_000);
      const expiry = setTimeout(() => response.end(), Math.max(0, claims.exp * 1000 - Date.now()));
      request.on("close", () => {
        clearInterval(ping);
        clearTimeout(expiry);
        workspace.listeners.delete(response);
      });
      return true;
    }

    throw new HttpError(404, "NOT_FOUND", "Unknown API route.");
  }

  async function handle(request: IncomingMessage, response: ServerResponse, path: string): Promise<boolean> {
    try {
      return await route(request, response, path);
    } catch (error) {
      if (error instanceof HttpError) {
        send(response, error.status, { error: { code: error.code, message: error.message } });
      } else {
        console.error("SignalWard API error:", error instanceof Error ? error.message : "unknown");
        send(response, 500, { error: { code: "INTERNAL", message: "The scan could not be completed." } });
      }
      return true;
    }
  }

  return { handle };
}

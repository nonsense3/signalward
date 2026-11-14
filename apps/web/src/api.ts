import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Report } from "../../../packages/contracts/src/index.ts";
import { ScanInputError, primaryAction, runMessageScan, runRepositoryScan, runUrlScan, type WorkspaceContext } from "../../../packages/engine/src/index.ts";
import { MESSAGE_LIMIT } from "../../../packages/fraud-scan/src/index.ts";
import { RepoFetchError, fetchRepository } from "../../../packages/repo-fetch/src/index.ts";
import { domainAgeFinding } from "../../../packages/url-intel/src/index.ts";
import { issueReceipt, trustedKeySet, verifyReceipt, type SigningKey, type TrustedKey } from "../../../packages/receipts/src/index.ts";
import { briefFor, type AiConfig } from "./ai.ts";
import { checkPassword, type AuthProvider, type AuthResult, type SessionData, type User } from "./auth.ts";
import { AppError, EMAIL, badRequest, forbidden, notFound, rateLimited, unauthorized, validate } from "./errors.ts";
import { RateLimiter, SECURITY_HEADERS, cookie, deriveIndicatorKey, open, readCookie, sameOrigin, seal, type IndicatorMasterVersion } from "./security.ts";
import { summarize, type Actor, type Store, type StoredReport } from "./store.ts";

const DEV_SESSION_COOKIE = "sw_session";
const SECURE_SESSION_COOKIE = "__Host-sw_session";
const SESSION_DAYS = 7;

export type ApiDeps = {
  auth: AuthProvider;
  store: Store;
  cookieKey: Buffer;
  indicatorMaster: Buffer;
  indicatorKeyVersion: string;
  previousIndicatorKeys: IndicatorMasterVersion[];
  signingKey: SigningKey;
  previousSigningKeys: TrustedKey[];
  ai: AiConfig;
  publicUrl: string | null;
  secureCookies: boolean;
  allowSignup: boolean;
  /** Enable network-backed URL enrichment (RDAP domain age). Never fetches the link itself. */
  urlIntel: boolean;
};

type Ctx = { rid: string; ip: string; setCookies: string[]; origin: string };
type Authed = { session: SessionData; user: User; actor: Actor };

export function createApi(deps: ApiDeps) {
  const sessionCookie = deps.secureCookies ? SECURE_SESSION_COOKIE : DEV_SESSION_COOKIE;
  const limits = {
    ip: new RateLimiter(300, 60_000),
    scan: new RateLimiter(30, 60_000),
    signIn: new RateLimiter(20, 10 * 60_000),
    signInEmail: new RateLimiter(10, 10 * 60_000),
    signUp: new RateLimiter(5, 10 * 60_000),
    recover: new RateLimiter(3, 10 * 60_000),
  };
  const listeners = new Map<string, Set<ServerResponse>>();

  /* ---------- responses ---------- */

  function send(response: ServerResponse, ctx: Ctx, status: number, body: unknown, headers: Record<string, string> = {}) {
    response.writeHead(status, {
      ...SECURITY_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Request-Id": ctx.rid,
      ...(ctx.setCookies.length ? { "Set-Cookie": ctx.setCookies } : {}),
      ...headers,
    });
    response.end(JSON.stringify(body));
  }

  async function readJson(request: IncomingMessage, limit: number): Promise<Record<string, unknown>> {
    if (!/^application\/json\b/i.test(request.headers["content-type"] ?? "")) throw new AppError(415, "UNSUPPORTED_MEDIA_TYPE", "Send the request as JSON.");
    const tooLarge = () => new AppError(413, "PAYLOAD_TOO_LARGE", `The request is larger than ${(limit / 1_000_000).toFixed(limit < 1_000_000 ? 2 : 0)} MB.`);
    if (Number(request.headers["content-length"] ?? 0) > limit) throw tooLarge();
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      size += (chunk as Buffer).length;
      if (size > limit) throw tooLarge();
      chunks.push(chunk as Buffer);
    }
    try {
      const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
      return parsed as Record<string, unknown>;
    } catch {
      throw badRequest("INVALID_JSON", "The request body is not valid JSON.");
    }
  }

  /* ---------- sessions ---------- */

  function issueSession(ctx: Ctx, result: AuthResult) {
    const now = Math.floor(Date.now() / 1000);
    const data: SessionData = { uid: result.user.id, email: result.user.email, iat: now, exp: now + SESSION_DAYS * 86400 };
    if (result.tokens) Object.assign(data, { at: result.tokens.accessToken, rt: result.tokens.refreshToken, atExp: result.tokens.expiresAt });
    if (result.sessionVersion !== undefined) data.sv = result.sessionVersion;
    ctx.setCookies.push(cookie(sessionCookie, seal(deps.cookieKey, data), SESSION_DAYS * 86400, deps.secureCookies));
    if (deps.secureCookies) ctx.setCookies.push(cookie(DEV_SESSION_COOKIE, "", 0, true));
  }

  function clearSession(ctx: Ctx) {
    ctx.setCookies.push(cookie(sessionCookie, "", 0, deps.secureCookies));
    if (deps.secureCookies) ctx.setCookies.push(cookie(DEV_SESSION_COOKIE, "", 0, true));
  }

  /** Decrypt-only check used for page gating. The API always verifies fully. */
  function hasSession(request: IncomingMessage): boolean {
    return Boolean(open<SessionData>(deps.cookieKey, readCookie(request, sessionCookie)));
  }

  async function authenticate(request: IncomingMessage, ctx: Ctx): Promise<Authed> {
    let session = open<SessionData>(deps.cookieKey, readCookie(request, sessionCookie));
    if (!session) throw unauthorized();
    try {
      if (deps.auth.kind === "supabase" && session.rt && (session.atExp ?? 0) - Date.now() / 1000 < 90) {
        const refreshed = await deps.auth.refresh(session.rt);
        issueSession(ctx, refreshed);
        session = { ...session, at: refreshed.tokens!.accessToken, rt: refreshed.tokens!.refreshToken, atExp: refreshed.tokens!.expiresAt };
      }
      const user = await deps.auth.verify(session);
      return { session, user, actor: { userId: user.id, email: user.email, ...(session.at ? { accessToken: session.at } : {}) } };
    } catch (error) {
      if (error instanceof AppError && error.status === 401) clearSession(ctx);
      throw error;
    }
  }

  function workspaceContext(actor: Actor): WorkspaceContext {
    const versions = [
      { version: deps.indicatorKeyVersion, master: deps.indicatorMaster },
      ...deps.previousIndicatorKeys.map(({ version, key }) => ({ version, master: key })),
    ];
    return {
      workspace: actor.userId,
      indicatorKey: deriveIndicatorKey(deps.indicatorMaster, actor.userId, deps.indicatorKeyVersion),
      keyVersion: deps.indicatorKeyVersion,
      indicatorKeys: versions.map(({ version, master }) => ({ key: deriveIndicatorKey(master, actor.userId, version), keyVersion: version })),
      lookup: (tags) => deps.store.lookupIndicators(actor, tags),
      record: (tags) => deps.store.recordIndicators(actor, tags),
    };
  }

  /** Status-only events. Never content, indicators or findings. */
  function broadcast(userId: string, event: Record<string, unknown>) {
    const line = `event: activity\ndata: ${JSON.stringify({ ...event, at: new Date().toISOString() })}\n\n`;
    for (const listener of listeners.get(userId) ?? []) listener.write(line);
  }

  function closeStreams(userId: string) {
    for (const listener of listeners.get(userId) ?? []) listener.end();
    listeners.delete(userId);
  }

  const redirectTo = (ctx: Ctx, path: string) => `${deps.publicUrl ?? ctx.origin}${path}`;

  /* ---------- routes ---------- */

  async function route(request: IncomingMessage, response: ServerResponse, path: string, ctx: Ctx): Promise<void> {
    const method = request.method ?? "GET";
    const ok = (body: unknown, status = 200) => send(response, ctx, status, body);

    if (method !== "GET" && !sameOrigin(request)) throw forbidden("Cross-site requests are refused.", "CROSS_ORIGIN");

    if (path === "/api/health" && method === "GET") {
      return ok({ ok: true, auth: deps.auth.kind, signup: deps.allowSignup, recovery: deps.auth.supportsRecovery, magicLink: deps.auth.supportsMagicLink, oauth: deps.auth.oauthProviders });
    }

    if (path.startsWith("/api/auth/oauth/") && method === "GET") {
      const provider = path.slice("/api/auth/oauth/".length);
      if (!/^[a-z]{2,20}$/.test(provider)) throw notFound("Unknown sign-in provider.");
      const params = new URL(request.url ?? path, ctx.origin).searchParams;
      const codeChallenge = params.get("code_challenge") ?? "";
      if (!/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
        throw badRequest("AUTH_PKCE_REQUIRED", "Restart sign-in from this browser to protect the OAuth flow.");
      }
      const url = deps.auth.oauthUrl(provider, redirectTo(ctx, "/auth/callback"), codeChallenge);
      if (!url) throw new AppError(501, "AUTH_OAUTH_UNAVAILABLE", "That sign-in method is not available on this server.");
      const take = limits.signIn.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter);
      // Top-level redirect to the provider's hosted consent screen; tokens return to /auth/callback.
      response.writeHead(303, { ...SECURITY_HEADERS, "Cache-Control": "no-store", "X-Request-Id": ctx.rid, Location: url });
      response.end();
      return;
    }

    if (path === "/api/auth/magic-link" && method === "POST") {
      const take = limits.recover.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter, "Too many sign-in-link requests. Try again later.");
      const body = validate<{ email: string; codeChallenge: string }>(await readJson(request, 2048), {
        email: { type: "string", required: true, max: 254, pattern: EMAIL, label: "Email" },
        codeChallenge: { type: "string", required: true, pattern: /^[A-Za-z0-9_-]{43}$/, label: "PKCE challenge" },
      });
      await deps.auth.magicLink(body.email.toLowerCase(), redirectTo(ctx, "/auth/callback"), body.codeChallenge);
      return ok({ status: "sent" }, 202); // Same answer whether or not the account exists.
    }

    /* --- auth --- */
    if (path === "/api/auth/signup" && method === "POST") {
      if (!deps.allowSignup) throw forbidden("New accounts are not being accepted.", "AUTH_SIGNUP_DISABLED");
      const body = validate<{ email: string; password: string; displayName: string }>(await readJson(request, 4096), {
        email: { type: "string", required: true, max: 254, pattern: EMAIL, label: "Email" },
        password: { type: "string", required: true, max: 128, label: "Password" },
        displayName: { type: "string", required: true, min: 1, max: 60, label: "Name" },
      });
      const email = body.email.toLowerCase();
      const weak = checkPassword(body.password, email);
      if (weak) throw new AppError(422, "AUTH_WEAK_PASSWORD", weak, { field: "password" });
      // Count only well-formed attempts, so typos don't lock out a real person.
      const take = limits.signUp.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter, "Too many sign-up attempts. Try again later.");
      const result = await deps.auth.signUp(email, body.password, body.displayName, redirectTo(ctx, "/auth/callback"));
      if (result.needsConfirmation) return ok({ status: "confirm_email", email }, 202);
      issueSession(ctx, result);
      const actor = { userId: result.user.id, email, ...(result.tokens ? { accessToken: result.tokens.accessToken } : {}) };
      await deps.store.updateProfile(actor, { displayName: body.displayName });
      return ok({ status: "signed_in" }, 201);
    }

    if (path === "/api/auth/signin" && method === "POST") {
      const take = limits.signIn.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter, "Too many sign-in attempts. Try again later.");
      const body = validate<{ email: string; password: string }>(await readJson(request, 4096), {
        email: { type: "string", required: true, max: 254, pattern: EMAIL, label: "Email" },
        password: { type: "string", required: true, max: 128, label: "Password" },
      });
      const email = body.email.toLowerCase();
      const perEmail = limits.signInEmail.take(email);
      if (!perEmail.ok) throw rateLimited(perEmail.retryAfter, "Too many attempts for this account. Try again later.");
      issueSession(ctx, await deps.auth.signIn(email, body.password));
      return ok({ status: "signed_in" });
    }

    if (path === "/api/auth/callback" && method === "POST") {
      if (deps.auth.kind !== "supabase") throw notFound();
      const raw = await readJson(request, 8192);
      if (typeof raw.code === "string") {
        const body = validate<{ code: string; codeVerifier: string }>(raw, {
          code: { type: "string", required: true, min: 1, max: 2048 },
          codeVerifier: { type: "string", required: true, pattern: /^[A-Za-z0-9._~-]{43,128}$/ },
        });
        issueSession(ctx, await deps.auth.exchangeCode(body.code, body.codeVerifier));
        return ok({ status: "signed_in" });
      }
      const body = validate<{ accessToken: string; refreshToken: string; expiresAt: number }>(raw, {
        accessToken: { type: "string", required: true, max: 4096 },
        refreshToken: { type: "string", required: true, max: 512 },
        expiresAt: { type: "number", min: 0 },
      });
      const probe: SessionData = { uid: "", email: "", iat: 0, exp: 0, at: body.accessToken };
      const user = await deps.auth.verify(probe);
      issueSession(ctx, { user, tokens: { accessToken: body.accessToken, refreshToken: body.refreshToken, expiresAt: body.expiresAt ?? Math.floor(Date.now() / 1000) + 3600 } });
      return ok({ status: "signed_in" });
    }

    if (path === "/api/auth/recover" && method === "POST") {
      const take = limits.recover.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter, "Too many reset requests. Try again later.");
      const body = validate<{ email: string }>(await readJson(request, 1024), { email: { type: "string", required: true, max: 254, pattern: EMAIL, label: "Email" } });
      await deps.auth.recover(body.email.toLowerCase(), redirectTo(ctx, "/auth/callback"));
      // Same answer whether or not the account exists.
      return ok({ status: "sent" }, 202);
    }

    if (path === "/api/auth/signout" && method === "POST") {
      const session = open<SessionData>(deps.cookieKey, readCookie(request, sessionCookie));
      if (session) await deps.auth.signOut(session).catch(() => undefined);
      if (session) closeStreams(session.uid);
      clearSession(ctx);
      return ok({ status: "signed_out" });
    }

    if (path === "/api/verify" && method === "POST") {
      const body = await readJson(request, 2_000_000);
      return ok(verifyReceipt(body.receipt, trustedKeySet(deps.signingKey, deps.previousSigningKeys).keys, body.report));
    }

    /* --- everything below requires a verified user --- */
    const { session, user, actor } = await authenticate(request, ctx);

    if (path === "/api/me" && method === "GET") {
      const profile = await deps.store.getProfile(actor);
      return ok({
        user: { id: user.id, email: user.email, emailConfirmed: user.emailConfirmed, createdAt: user.createdAt },
        profile,
        session: { issuedAt: new Date(session.iat * 1000).toISOString(), expiresAt: new Date(session.exp * 1000).toISOString(), provider: deps.auth.kind },
        keys: { indicator: `${deps.indicatorKeyVersion} · HKDF per account (${deps.previousIndicatorKeys.length} retained)`, signing: deps.signingKey.keyId },
      });
    }

    if (path === "/api/me/profile" && method === "PATCH") {
      const patch = validate<{ displayName: string; organization: string; title: string; avatarHue: number }>(await readJson(request, 4096), {
        displayName: { type: "string", min: 1, max: 60, label: "Name" },
        organization: { type: "string", max: 80, label: "Organization" },
        title: { type: "string", max: 60, label: "Role" },
        avatarHue: { type: "number", min: 0, max: 359, label: "Avatar colour" },
      });
      if (!Object.keys(patch).length) throw badRequest("NOTHING_TO_UPDATE", "Change at least one field.");
      if (patch.avatarHue !== undefined) patch.avatarHue = Math.round(patch.avatarHue);
      const profile = await deps.store.updateProfile(actor, patch);
      broadcast(actor.userId, { type: "profile.updated" });
      return ok({ profile });
    }

    if (path === "/api/me/password" && method === "POST") {
      const body = validate<{ currentPassword: string; newPassword: string }>(await readJson(request, 4096), {
        currentPassword: { type: "string", required: deps.auth.kind === "local", max: 128, label: "Current password" },
        newPassword: { type: "string", required: true, max: 128, label: "New password" },
      });
      const weak = checkPassword(body.newPassword, user.email);
      if (weak) throw new AppError(422, "AUTH_WEAK_PASSWORD", weak, { field: "newPassword" });
      if (body.currentPassword && body.currentPassword === body.newPassword) throw new AppError(422, "AUTH_SAME_PASSWORD", "Choose a different password.", { field: "newPassword" });
      const result = await deps.auth.updatePassword(session, body.currentPassword ?? "", body.newPassword);
      closeStreams(user.id);
      if (result.sessionVersion !== undefined) issueSession(ctx, { user, tokens: null, sessionVersion: result.sessionVersion });
      return ok({ status: "updated" });
    }

    if (path === "/api/me/stats" && method === "GET") {
      const [reports, blocklist] = await Promise.all([deps.store.listReports(actor, 500), deps.store.listBlocklist(actor)]);
      const byVerdict: Record<string, number> = {};
      const byKind: Record<string, number> = { repository: 0, message: 0, url: 0 };
      const days: number[] = Array(30).fill(0);
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      for (const report of reports) {
        byVerdict[report.verdict] = (byVerdict[report.verdict] ?? 0) + 1;
        byKind[report.kind] = (byKind[report.kind] ?? 0) + 1;
        const age = Math.floor((today.getTime() - new Date(report.createdAt).setHours(0, 0, 0, 0)) / 86_400_000);
        if (age >= 0 && age < 30) days[29 - age]! += 1;
      }
      return ok({
        total: reports.length,
        threats: (byVerdict.block ?? 0) + (byVerdict.high_risk ?? 0),
        findings: reports.reduce((sum, item) => sum + item.findings, 0),
        high: reports.reduce((sum, item) => sum + item.high, 0),
        blocked: blocklist.length,
        byVerdict, byKind, days,
        recent: reports.slice(0, 6),
      });
    }

    if (path === "/api/me/export" && method === "GET") {
      const [profile, reports, blocklist] = await Promise.all([deps.store.getProfile(actor), deps.store.exportReports(actor), deps.store.listBlocklist(actor)]);
      return send(response, ctx, 200, { exportedAt: new Date().toISOString(), profile, reports, blocklist, trustedKeys: trustedKeySet(deps.signingKey, deps.previousSigningKeys) }, {
        "Content-Disposition": `attachment; filename="signalward-export-${new Date().toISOString().slice(0, 10)}.json"`,
      });
    }

    if (path === "/api/me/erase" && method === "POST") {
      const body = validate<{ confirm: string }>(await readJson(request, 256), { confirm: { type: "string", required: true, max: 10 } });
      if (body.confirm !== "ERASE") throw badRequest("CONFIRMATION_REQUIRED", 'Type ERASE to confirm.', "confirm");
      await deps.store.erase(actor);
      broadcast(actor.userId, { type: "data.erased" });
      return ok({ status: "erased" });
    }

    /* --- scans --- */
    if (path.startsWith("/api/scans/") && method === "POST") {
      const take = limits.scan.take(actor.userId);
      if (!take.ok) throw rateLimited(take.retryAfter, `Scan limit reached. Try again in ${take.retryAfter} s.`);
      const kind = path.slice("/api/scans/".length);
      const ws = workspaceContext(actor);
      let report: Report;
      if (kind === "repository") {
        const body = validate<{ url: string; ref: string; token: string }>(await readJson(request, 8192), {
          url: { type: "string", required: true, max: 300, label: "Repository URL" },
          ref: { type: "string", max: 120, label: "Branch or tag" },
          token: { type: "string", max: 200, label: "GitHub token" },
        });
        broadcast(actor.userId, { type: "scan.started", kind });
        let fetched;
        try {
          fetched = await fetchRepository(body.url, { ...(body.ref ? { ref: body.ref } : {}), ...(body.token ? { token: body.token } : {}) });
        } catch (error) {
          if (error instanceof RepoFetchError) throw new AppError(error.status, error.code, error.message, { field: "url" });
          throw error;
        }
        report = runRepositoryScan(fetched.files, fetched.label, ws);
        if (fetched.truncated && report.scope.kind === "repository") {
          report.coverage.push({ detector: "repository_snapshot", status: "partial", detail: "The repository is large; the snapshot was truncated before scanning.", required: false });
        }
      } else if (kind === "message") {
        const body = validate<{ text: string; sender: string; subject: string }>(await readJson(request, 200_000), {
          text: { type: "string", required: true, max: MESSAGE_LIMIT, label: "Message" },
          sender: { type: "string", max: 320, label: "Sender" },
          subject: { type: "string", max: 500, label: "Subject" },
        });
        broadcast(actor.userId, { type: "scan.started", kind });
        report = await runMessageScan({ text: body.text, ...(body.sender ? { sender: body.sender } : {}), ...(body.subject ? { subject: body.subject } : {}) }, ws);
      } else if (kind === "url") {
        const body = validate<{ url: string }>(await readJson(request, 8192), { url: { type: "string", required: true, max: 2048, label: "Link" } });
        broadcast(actor.userId, { type: "scan.started", kind });
        try {
          const domainAge = deps.urlIntel ? (domain: string) => domainAgeFinding(domain, { timeoutMs: deps.ai.timeoutMs }) : undefined;
          report = await runUrlScan(body.url, ws, domainAge ? { domainAge } : {});
        } catch (error) {
          if (error instanceof ScanInputError) throw new AppError(422, error.code, error.message, { field: "url" });
          throw error;
        }
      } else {
        throw notFound("Unknown scan type.");
      }
      if (report.kind !== "repository" && report.verdict === "high_risk") {
        const action = report.mitigations.find((item) => item.action === "block_indicators");
        if (action) {
          const evidence = report.findings
            .filter((item) => (item.severity === "high" || item.severity === "critical") && item.confidence === "high")
            .flatMap((item) => [item.title, ...item.evidence.map((entry) => entry.value)])
            .map((value) => value.toLowerCase());
          const candidates = report.indicators.filter((item) =>
            ["url", "domain", "ipv4"].includes(item.type) &&
            evidence.some((value) => value.includes(item.display.toLowerCase())),
          );
          let applied = 0;
          let failed = 0;
          for (const indicator of candidates) {
            try {
              await deps.store.addBlock(actor, {
                tag: indicator.tag,
                type: indicator.type,
                display: indicator.display,
                reportId: report.id,
                addedAt: new Date().toISOString(),
              });
              indicator.blocked = true;
              applied += 1;
            } catch (error) {
              failed += 1;
              console.warn(`[${ctx.rid}] automatic indicator block failed: ${error instanceof Error ? error.name : "unknown error"}`);
            }
          }
          if (applied > 0) broadcast(actor.userId, { type: "blocklist.added", automatic: true, count: applied });
          if (failed) {
            action.mode = "recommended";
            action.status = "failed";
            action.detail = `Blocklist update failed for ${failed} indicator(s); ${applied} were added. Review the blocklist and retry failed entries.`;
          } else if (applied) {
            action.mode = "automatic";
            action.status = "applied";
            action.detail = `Automatically added ${applied} high-confidence URL, domain, or IP indicator(s) to this workspace blocklist. Future matching scans will be flagged.`;
          } else {
            action.mode = "recommended";
            action.status = "not_applicable";
            action.detail = "No URL, domain, or IP indicator was directly cited by a high-confidence blocking finding. Review the evidence and add any confirmed indicators manually.";
          }
        }
      }
      const receipt = issueReceipt(report, primaryAction(report), deps.signingKey);
      const brief = await briefFor(report, deps.ai, (message) => console.warn(`[${ctx.rid}] ${message}`));
      const stored: StoredReport = { report, receipt, brief };
      await deps.store.saveReport(actor, stored);
      broadcast(actor.userId, { type: "scan.completed", reportId: report.id, kind: report.kind, verdict: report.verdict, findings: report.findings.length });
      return ok(stored, 201);
    }

    if (path === "/api/reports" && method === "GET") {
      return ok({ reports: await deps.store.listReports(actor, 100) });
    }
    const reportMatch = /^\/api\/reports\/(rpt_[A-Za-z0-9_-]{6,32})$/.exec(path);
    if (reportMatch && method === "GET") {
      // Another account's report is indistinguishable from a missing one.
      const stored = await deps.store.getReport(actor, reportMatch[1]!);
      if (!stored) throw notFound("No report with that ID in your account.");
      return ok(stored);
    }

    /* --- blocklist --- */
    if (path === "/api/blocklist" && method === "GET") return ok({ entries: await deps.store.listBlocklist(actor) });
    if (path === "/api/blocklist" && method === "POST") {
      const body = validate<{ tag: string; reportId: string }>(await readJson(request, 1024), {
        tag: { type: "string", required: true, max: 80, pattern: /^k\d+:[A-Za-z0-9_-]{16,64}$/, label: "Indicator" },
        reportId: { type: "string", required: true, max: 40, pattern: /^rpt_[A-Za-z0-9_-]{6,32}$/, label: "Report" },
      });
      const stored = await deps.store.getReport(actor, body.reportId);
      const indicator = stored?.report.indicators.find((item) => item.tag === body.tag);
      if (!indicator) throw notFound("That indicator is not in one of your reports.");
      await deps.store.addBlock(actor, { tag: indicator.tag, type: indicator.type, display: indicator.display, reportId: body.reportId, addedAt: new Date().toISOString() });
      broadcast(actor.userId, { type: "blocklist.added", indicatorType: indicator.type });
      return ok({ entries: await deps.store.listBlocklist(actor) });
    }
    if (path === "/api/blocklist" && method === "DELETE") {
      const body = validate<{ tag: string }>(await readJson(request, 512), { tag: { type: "string", required: true, max: 80, pattern: /^k\d+:[A-Za-z0-9_-]{16,64}$/, label: "Indicator" } });
      await deps.store.removeBlock(actor, body.tag);
      broadcast(actor.userId, { type: "blocklist.removed" });
      return ok({ entries: await deps.store.listBlocklist(actor) });
    }

    /* --- live events --- */
    if (path === "/api/events" && method === "GET") {
      response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive", "X-Request-Id": ctx.rid, ...(ctx.setCookies.length ? { "Set-Cookie": ctx.setCookies } : {}) });
      response.write(`retry: 5000\nevent: ready\ndata: {}\n\n`);
      const set = listeners.get(actor.userId) ?? new Set();
      listeners.set(actor.userId, set);
      if (set.size >= 6) [...set][0]?.end();
      set.add(response);
      const ping = setInterval(() => response.write(": ping\n\n"), 25_000);
      const verify = setInterval(() => {
        void deps.auth.verify(session).catch(() => response.end());
      }, 25_000);
      // Refreshable Supabase access tokens and revoked sessions reconnect through normal auth.
      const tokenExpiry = session.atExp ? session.atExp * 1000 : Number.POSITIVE_INFINITY;
      const closeAt = Math.min(session.exp * 1000, tokenExpiry, Date.now() + 60 * 60_000);
      const close = setTimeout(() => response.end(), Math.max(0, closeAt - Date.now()));
      response.on("close", () => {
        clearInterval(ping);
        clearInterval(verify);
        clearTimeout(close);
        set.delete(response);
        if (!set.size && listeners.get(actor.userId) === set) listeners.delete(actor.userId);
      });
      return;
    }

    throw notFound("Unknown API route.");
  }

  async function handle(request: IncomingMessage, response: ServerResponse, path: string): Promise<boolean> {
    if (path === "/.well-known/signalward-keys.json") {
      response.writeHead(200, { ...SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*" });
      response.end(JSON.stringify(trustedKeySet(deps.signingKey, deps.previousSigningKeys)));
      return true;
    }
    if (!path.startsWith("/api/")) return false;
    const ctx: Ctx = {
      rid: randomBytes(6).toString("hex"),
      ip: request.socket.remoteAddress ?? "unknown",
      setCookies: [],
      origin: `http://${request.headers.host ?? "127.0.0.1"}`,
    };
    try {
      const take = limits.ip.take(ctx.ip);
      if (!take.ok) throw rateLimited(take.retryAfter);
      await route(request, response, path, ctx);
    } catch (error) {
      if (response.headersSent) {
        response.end();
        return true;
      }
      if (error instanceof AppError) {
        if (error.status >= 500) console.error(`[${ctx.rid}] ${error.code}: ${error.message}${error.cause ? ` (${error.cause instanceof Error ? error.cause.message : String(error.cause)})` : ""}`);
        send(response, ctx, error.status, { error: { code: error.code, message: error.message, ...(error.field ? { field: error.field } : {}), requestId: ctx.rid } },
          error.retryAfter ? { "Retry-After": String(error.retryAfter) } : {});
      } else {
        console.error(`[${ctx.rid}] unhandled:`, error instanceof Error ? error.stack ?? error.message : error);
        send(response, ctx, 500, { error: { code: "INTERNAL", message: "Something went wrong on our side. Try again.", requestId: ctx.rid } });
      }
    }
    return true;
  }

  return { handle, hasSession };
}

export { summarize };

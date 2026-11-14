import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Receipt, Report } from "../../../packages/contracts/src/index.ts";
import type { Brief } from "./ai.ts";
import { AppError, unauthorized, unavailable } from "./errors.ts";

export type StoredReport = { report: Report; receipt: Receipt; brief: Brief };
export type ReportSummary = { id: string; kind: Report["kind"]; verdict: Report["verdict"]; findings: number; high: number; summary: string; createdAt: string };
export type Profile = { id: string; email: string; displayName: string; organization: string; title: string; avatarHue: number; createdAt: string; updatedAt: string };
export type ProfilePatch = Partial<Pick<Profile, "displayName" | "organization" | "title" | "avatarHue">>;
export type BlockEntry = { tag: string; type: string; display: string; reportId: string; addedAt: string };
export type Actor = { userId: string; email: string; accessToken?: string };

export interface Store {
  getProfile(actor: Actor): Promise<Profile>;
  updateProfile(actor: Actor, patch: ProfilePatch): Promise<Profile>;
  saveReport(actor: Actor, stored: StoredReport): Promise<void>;
  listReports(actor: Actor, limit: number): Promise<ReportSummary[]>;
  getReport(actor: Actor, id: string): Promise<StoredReport | null>;
  lookupIndicators(actor: Actor, tags: string[]): Promise<{ seen: Map<string, number>; blocked: Set<string> }>;
  recordIndicators(actor: Actor, tags: string[]): Promise<void>;
  listBlocklist(actor: Actor): Promise<BlockEntry[]>;
  addBlock(actor: Actor, entry: BlockEntry): Promise<void>;
  removeBlock(actor: Actor, tag: string): Promise<void>;
  erase(actor: Actor): Promise<void>;
  exportReports(actor: Actor): Promise<StoredReport[]>;
}

export function summarize({ report }: StoredReport): ReportSummary {
  return {
    id: report.id, kind: report.kind, verdict: report.verdict, findings: report.findings.length,
    high: report.findings.filter((item) => item.severity === "high" || item.severity === "critical").length,
    summary: report.summary, createdAt: report.createdAt,
  };
}

const defaultName = (email: string) => email.split("@")[0]!.replace(/[._-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()).slice(0, 60);
const hueFor = (id: string) => [...id].reduce((sum, char) => (sum * 31 + char.charCodeAt(0)) >>> 0, 7) % 360;

/* ---------------------------------------------------------------- Local file store */

type LocalData = { profile: Omit<Profile, "id" | "email">; reports: StoredReport[]; sightings: Record<string, number>; blocklist: BlockEntry[] };

export class LocalStore implements Store {
  #dir: string;
  #cache = new Map<string, LocalData>();
  constructor(stateDir: string) {
    this.#dir = join(stateDir, "data");
    mkdirSync(this.#dir, { recursive: true });
  }

  #file(userId: string) {
    if (!/^[A-Za-z0-9-]{8,64}$/.test(userId)) throw unauthorized();
    return join(this.#dir, `${userId}.json`);
  }

  #load(actor: Actor): LocalData {
    const cached = this.#cache.get(actor.userId);
    if (cached) return cached;
    const file = this.#file(actor.userId);
    const now = new Date().toISOString();
    const data: LocalData = existsSync(file)
      ? (JSON.parse(readFileSync(file, "utf8")) as LocalData)
      : { profile: { displayName: defaultName(actor.email), organization: "", title: "", avatarHue: hueFor(actor.userId), createdAt: now, updatedAt: now }, reports: [], sightings: {}, blocklist: [] };
    this.#cache.set(actor.userId, data);
    return data;
  }

  #save(actor: Actor) {
    const file = this.#file(actor.userId);
    const temp = `${file}.${process.pid}.tmp`;
    writeFileSync(temp, JSON.stringify(this.#load(actor)), { mode: 0o600 });
    renameSync(temp, file);
  }

  async getProfile(actor: Actor) {
    return { id: actor.userId, email: actor.email, ...this.#load(actor).profile };
  }
  async updateProfile(actor: Actor, patch: ProfilePatch) {
    const data = this.#load(actor);
    data.profile = { ...data.profile, ...patch, updatedAt: new Date().toISOString() };
    this.#save(actor);
    return this.getProfile(actor);
  }
  async saveReport(actor: Actor, stored: StoredReport) {
    const data = this.#load(actor);
    data.reports.push(stored);
    if (data.reports.length > 500) data.reports.splice(0, data.reports.length - 500);
    this.#save(actor);
  }
  async listReports(actor: Actor, limit: number) {
    return this.#load(actor).reports.slice(-limit).reverse().map(summarize);
  }
  async getReport(actor: Actor, id: string) {
    return this.#load(actor).reports.find((item) => item.report.id === id) ?? null;
  }
  async lookupIndicators(actor: Actor, tags: string[]) {
    const data = this.#load(actor);
    const blockedTags = new Set(data.blocklist.map((entry) => entry.tag));
    return { seen: new Map(tags.map((tag) => [tag, data.sightings[tag] ?? 0])), blocked: new Set(tags.filter((tag) => blockedTags.has(tag))) };
  }
  async recordIndicators(actor: Actor, tags: string[]) {
    const data = this.#load(actor);
    for (const tag of new Set(tags)) data.sightings[tag] = (data.sightings[tag] ?? 0) + 1;
    this.#save(actor);
  }
  async listBlocklist(actor: Actor) {
    return [...this.#load(actor).blocklist].reverse();
  }
  async addBlock(actor: Actor, entry: BlockEntry) {
    const data = this.#load(actor);
    if (!data.blocklist.some((item) => item.tag === entry.tag)) data.blocklist.push(entry);
    this.#save(actor);
  }
  async removeBlock(actor: Actor, tag: string) {
    const data = this.#load(actor);
    data.blocklist = data.blocklist.filter((item) => item.tag !== tag);
    this.#save(actor);
  }
  async exportReports(actor: Actor) {
    return [...this.#load(actor).reports].reverse();
  }
  async erase(actor: Actor) {
    const data = this.#load(actor);
    data.reports = [];
    data.sightings = {};
    data.blocklist = [];
    this.#save(actor);
  }
}

/* ---------------------------------------------------------------- Supabase store */

type ProfileRow = { id: string; display_name: string | null; organization: string | null; title: string | null; avatar_hue: number | null; created_at: string; updated_at: string };
type ReportRow = { id: string; kind: Report["kind"]; verdict: Report["verdict"]; findings_count: number; high_count: number; summary: string; created_at: string };

/**
 * Every call carries the signed-in user's access token, so Postgres row-level security decides what
 * each request can read or write. The server never holds a service-role key.
 */
export class SupabaseStore implements Store {
  private url: string;
  private anonKey: string;
  constructor(url: string, anonKey: string) {
    this.url = url;
    this.anonKey = anonKey;
  }

  async #rest<T>(actor: Actor, path: string, init: { method?: string; body?: unknown; prefer?: string } = {}): Promise<T> {
    if (!actor.accessToken) throw unauthorized();
    let response: Response;
    try {
      response = await fetch(new URL(`/rest/v1/${path}`, this.url), {
        method: init.method ?? "GET",
        headers: {
          apikey: this.anonKey,
          Authorization: `Bearer ${actor.accessToken}`,
          "Content-Type": "application/json",
          ...(init.prefer ? { Prefer: init.prefer } : {}),
        },
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: AbortSignal.timeout(10_000),
      });
    } catch (error) {
      throw unavailable("DATABASE_UNAVAILABLE", "The database could not be reached. Try again shortly.", error);
    }
    const text = await response.text();
    if (!response.ok) {
      let body: { code?: string; message?: string } = {};
      try {
        body = JSON.parse(text);
      } catch {
        body = {};
      }
      if (response.status === 401 || body.code === "PGRST301") throw unauthorized("Your session has ended. Sign in again.", "AUTH_SESSION_EXPIRED");
      if (body.code === "42P01" || body.code === "PGRST205" || body.code === "PGRST202") {
        throw unavailable("DATABASE_NOT_MIGRATED", "The database tables are missing. Run supabase/migrations/20261114000000_signalward.sql in your Supabase project.");
      }
      if (body.code === "42501") throw new AppError(403, "FORBIDDEN", "The database refused this change.");
      throw unavailable("DATABASE_ERROR", "The database rejected the request.", new Error(`${response.status} ${body.code ?? ""} ${body.message ?? ""}`));
    }
    return (text ? JSON.parse(text) : null) as T;
  }

  #profile(actor: Actor, row: ProfileRow): Profile {
    return {
      id: row.id, email: actor.email, displayName: row.display_name || defaultName(actor.email), organization: row.organization ?? "",
      title: row.title ?? "", avatarHue: row.avatar_hue ?? hueFor(row.id), createdAt: row.created_at, updatedAt: row.updated_at,
    };
  }

  async getProfile(actor: Actor) {
    const rows = await this.#rest<ProfileRow[]>(actor, `profiles?id=eq.${actor.userId}&select=*`);
    if (rows[0]) return this.#profile(actor, rows[0]);
    // The signup trigger normally creates the row; create it if the account predates the migration.
    const created = await this.#rest<ProfileRow[]>(actor, "profiles", {
      method: "POST", prefer: "return=representation,resolution=merge-duplicates",
      body: { id: actor.userId, display_name: defaultName(actor.email), avatar_hue: hueFor(actor.userId) },
    });
    return this.#profile(actor, created[0]!);
  }

  async updateProfile(actor: Actor, patch: ProfilePatch) {
    const body: Record<string, unknown> = {};
    if (patch.displayName !== undefined) body.display_name = patch.displayName;
    if (patch.organization !== undefined) body.organization = patch.organization;
    if (patch.title !== undefined) body.title = patch.title;
    if (patch.avatarHue !== undefined) body.avatar_hue = patch.avatarHue;
    await this.getProfile(actor);
    const rows = await this.#rest<ProfileRow[]>(actor, `profiles?id=eq.${actor.userId}`, { method: "PATCH", body, prefer: "return=representation" });
    return this.#profile(actor, rows[0]!);
  }

  async saveReport(actor: Actor, stored: StoredReport) {
    const s = summarize(stored);
    await this.#rest(actor, "reports", {
      method: "POST", prefer: "return=minimal",
      body: { id: s.id, user_id: actor.userId, kind: s.kind, verdict: s.verdict, findings_count: s.findings, high_count: s.high, summary: s.summary, report: stored.report, receipt: stored.receipt, brief: stored.brief },
    });
  }

  async listReports(actor: Actor, limit: number) {
    const rows = await this.#rest<ReportRow[]>(actor, `reports?select=id,kind,verdict,findings_count,high_count,summary,created_at&order=created_at.desc&limit=${limit}`);
    return rows.map((row) => ({ id: row.id, kind: row.kind, verdict: row.verdict, findings: row.findings_count, high: row.high_count, summary: row.summary, createdAt: row.created_at }));
  }

  async getReport(actor: Actor, id: string) {
    const rows = await this.#rest<{ report: Report; receipt: Receipt; brief: Brief }[]>(actor, `reports?id=eq.${encodeURIComponent(id)}&select=report,receipt,brief`);
    return rows[0] ?? null;
  }

  async lookupIndicators(actor: Actor, tags: string[]) {
    if (!tags.length) return { seen: new Map<string, number>(), blocked: new Set<string>() };
    const list = encodeURIComponent(`(${tags.map((tag) => `"${tag}"`).join(",")})`);
    const [sightings, blocked] = await Promise.all([
      this.#rest<{ tag: string; count: number }[]>(actor, `indicator_sightings?select=tag,count&tag=in.${list}`),
      this.#rest<{ tag: string }[]>(actor, `blocklist?select=tag&tag=in.${list}`),
    ]);
    const seen = new Map(tags.map((tag) => [tag, 0]));
    for (const row of sightings) seen.set(row.tag, row.count);
    return { seen, blocked: new Set(blocked.map((row) => row.tag)) };
  }

  async recordIndicators(actor: Actor, tags: string[]) {
    if (tags.length) await this.#rest(actor, "rpc/record_sightings", { method: "POST", body: { p_tags: [...new Set(tags)] } });
  }

  async listBlocklist(actor: Actor) {
    const rows = await this.#rest<{ tag: string; type: string; display: string; report_id: string; added_at: string }[]>(actor, "blocklist?select=tag,type,display,report_id,added_at&order=added_at.desc");
    return rows.map((row) => ({ tag: row.tag, type: row.type, display: row.display, reportId: row.report_id, addedAt: row.added_at }));
  }

  async addBlock(actor: Actor, entry: BlockEntry) {
    await this.#rest(actor, "blocklist?on_conflict=user_id,tag", {
      method: "POST", prefer: "return=minimal,resolution=ignore-duplicates",
      body: { user_id: actor.userId, tag: entry.tag, type: entry.type, display: entry.display, report_id: entry.reportId },
    });
  }

  async removeBlock(actor: Actor, tag: string) {
    await this.#rest(actor, `blocklist?user_id=eq.${actor.userId}&tag=eq.${encodeURIComponent(tag)}`, { method: "DELETE", prefer: "return=minimal" });
  }

  async exportReports(actor: Actor) {
    return this.#rest<StoredReport[]>(actor, "reports?select=report,receipt,brief&order=created_at.desc&limit=500");
  }

  async erase(actor: Actor) {
    for (const table of ["reports", "blocklist", "indicator_sightings"]) {
      await this.#rest(actor, `${table}?user_id=eq.${actor.userId}`, { method: "DELETE", prefer: "return=minimal" });
    }
  }
}

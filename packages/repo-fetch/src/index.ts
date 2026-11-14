import { LIMITS, isIgnoredPath, safeRelativePath, type SourceFile } from "../../repo-scan/src/index.ts";

/**
 * Fetch a Git repository snapshot by URL and return bounded in-memory source files.
 * Uses only Web APIs (fetch, DecompressionStream) so it runs on Node and Cloudflare Workers.
 * It downloads the host's source tarball; it never executes anything from the repository.
 */

export class RepoFetchError extends Error {
  code: string;
  status: number;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export type RepoTarget = { host: "github"; owner: string; repo: string; ref?: string };

const MAX_DOWNLOAD_BYTES = 48_000_000; // decompressed cap before scan-time limits apply

/** Parse a GitHub URL or `owner/repo` shorthand. Other hosts are rejected with a clear message. */
export function parseRepoTarget(input: string): RepoTarget {
  const raw = String(input).trim();
  if (!raw) throw new RepoFetchError(400, "REPO_URL_REQUIRED", "Enter a Git repository URL.");
  if (/^[\w.-]+\/[\w.-]+$/.test(raw)) {
    const [owner, repo] = raw.split("/");
    return { host: "github", owner: owner!, repo: repo!.replace(/\.git$/, "") };
  }
  let url: URL;
  try {
    url = new URL(raw.replace(/^git@github\.com:/i, "https://github.com/"));
  } catch {
    throw new RepoFetchError(422, "REPO_URL_INVALID", "That does not look like a repository URL. Use https://github.com/owner/repo.");
  }
  const host = url.hostname.toLowerCase().replace(/^www\./, "");
  if (host !== "github.com") {
    throw new RepoFetchError(422, "REPO_HOST_UNSUPPORTED", "Only github.com repositories are supported right now.");
  }
  const parts = url.pathname.replace(/^\/+/, "").split("/").filter(Boolean);
  if (parts.length < 2) throw new RepoFetchError(422, "REPO_URL_INVALID", "The URL is missing the owner or repository name.");
  const owner = parts[0]!;
  const repo = parts[1]!.replace(/\.git$/, "");
  // Accept .../tree/<ref> or .../tree/<ref>/<subpath> and treat the ref as the branch.
  let ref: string | undefined;
  if (parts[2] === "tree" && parts[3]) ref = parts.slice(3).join("/");
  return { host: "github", owner, repo, ...(ref ? { ref } : {}) };
}

type TarEntry = { name: string; data: Uint8Array };

/** Minimal POSIX/ustar tar reader: 512-byte header blocks, octal size, regular files only. */
function parseTar(buffer: Uint8Array): TarEntry[] {
  const entries: TarEntry[] = [];
  const decoder = new TextDecoder();
  const field = (start: number, length: number) => decoder.decode(buffer.subarray(start, start + length)).replace(/\0.*$/s, "").trim();
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const name = field(offset, 100);
    const prefix = field(offset + 345, 155);
    const sizeOctal = field(offset + 124, 12);
    const size = Number.parseInt(sizeOctal, 8) || 0;
    const type = String.fromCharCode(header[156] ?? 0);
    offset += 512;
    if ((type === "0" || type === "\0" || type === "") && size > 0) {
      entries.push({ name: prefix ? `${prefix}/${name}` : name, data: buffer.subarray(offset, offset + size) });
    }
    offset += Math.ceil(size / 512) * 512;
  }
  return entries;
}

async function readCapped(stream: ReadableStream<Uint8Array>): Promise<{ buffer: Uint8Array; truncated: boolean }> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > MAX_DOWNLOAD_BYTES) {
      truncated = true;
      await reader.cancel().catch(() => {});
      break;
    }
    chunks.push(value);
  }
  const buffer = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let at = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, at);
    at += chunk.length;
  }
  return { buffer, truncated };
}

export type FetchedRepository = { files: SourceFile[]; label: string; truncated: boolean; fileCount: number };

export type FetchOptions = {
  ref?: string;
  /** The caller's own token (private repositories). Sent only to api.github.com. */
  token?: string;
  /**
   * Server-wide token used when the caller gave none. It must be scoped to public repositories only
   * (fine-grained, "Public repositories (read-only)"), otherwise any user could scan what it can see.
   */
  fallbackToken?: string;
  signal?: AbortSignal;
};

async function download(url: string, headers: Record<string, string>, signal?: AbortSignal): Promise<Response> {
  try {
    return await fetch(url, { headers, redirect: "follow", signal: signal ?? AbortSignal.timeout(25_000) });
  } catch {
    throw new RepoFetchError(503, "REPO_UNREACHABLE", "Could not reach GitHub. Check the URL and your connection.");
  }
}

const isRateLimited = (response: Response) =>
  response.status === 429 || (response.status === 403 && response.headers.get("x-ratelimit-remaining") === "0");

/**
 * Get the tarball stream. Without a caller token, public repositories come from the source archive
 * (github.com/<o>/<r>/archive/<ref>.tar.gz), which is not counted against the REST API's 60-requests-
 * per-hour anonymous limit. Private repositories, or archive failures, go through the REST API with
 * the caller's token, or the server's public-only token as a fallback.
 */
async function openTarball(target: RepoTarget, ref: string, options: FetchOptions): Promise<ReadableStream<Uint8Array>> {
  const base = { "User-Agent": "SignalWard-Scanner" };
  let archiveStatus = 0;
  if (!options.token) {
    const archive = await download(`https://github.com/${target.owner}/${target.repo}/archive/${ref ? ref.split("/").map(encodeURIComponent).join("/") : "HEAD"}.tar.gz`, base, options.signal);
    if (archive.ok && archive.body) return archive.body;
    archiveStatus = archive.status;
    await archive.body?.cancel().catch(() => {});
  }

  const token = options.token ?? options.fallbackToken;
  if (!token && archiveStatus === 404) {
    throw new RepoFetchError(404, "REPO_NOT_FOUND", "Repository or branch not found. For a private repo, add a GitHub token.");
  }
  const headers: Record<string, string> = { ...base, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const response = await download(`https://api.github.com/repos/${target.owner}/${target.repo}/tarball${ref ? `/${encodeURIComponent(ref)}` : ""}`, headers, options.signal);
  if (response.ok && response.body) return response.body;
  await response.body?.cancel().catch(() => {});

  const own = Boolean(options.token);
  if (response.status === 404) throw new RepoFetchError(404, "REPO_NOT_FOUND", own ? "Repository or branch not found, or the token can't read it." : "Repository or branch not found. For a private repo, add a GitHub token.");
  if (response.status === 401) {
    if (!own) throw new RepoFetchError(503, "REPO_SERVER_TOKEN_INVALID", "The scanner's GitHub access is misconfigured. Add your own token or try again later.");
    throw new RepoFetchError(401, "REPO_TOKEN_REJECTED", "The GitHub token was rejected. Use a fine-grained token with read-only contents access.");
  }
  if (isRateLimited(response)) {
    const reset = Number(response.headers.get("x-ratelimit-reset"));
    const minutes = Number.isFinite(reset) && reset > 0 ? Math.max(1, Math.ceil((reset * 1000 - Date.now()) / 60_000)) : 0;
    const when = minutes ? `in about ${minutes} min` : "in a few minutes";
    throw new RepoFetchError(429, "REPO_RATE_LIMITED", own ? `Your GitHub token hit its rate limit. Try again ${when}.` : `GitHub is limiting requests right now. Add a GitHub token under "Branch, or a private repository", or try again ${when}.`);
  }
  if (response.status === 403) throw new RepoFetchError(403, "REPO_FORBIDDEN", "Access denied. The repository may be private — add a GitHub token.");
  throw new RepoFetchError(502, "REPO_DOWNLOAD_FAILED", `GitHub returned an unexpected status (${response.status}).`);
}

/** Download and extract a repository into bounded SourceFile[]. Tokens are used only for this request. */
export async function fetchRepository(input: string, options: FetchOptions = {}): Promise<FetchedRepository> {
  const target = parseRepoTarget(input);
  const ref = (options.ref ?? target.ref ?? "").replace(/^\/+|\/+$/g, "");
  if (ref && (!/^[\w./-]{1,200}$/.test(ref) || ref.includes(".."))) {
    throw new RepoFetchError(422, "REPO_REF_INVALID", "That branch, tag or commit name isn't valid.");
  }
  const stream = await openTarball(target, ref, options);

  const { buffer, truncated } = await readCapped(stream.pipeThrough(new DecompressionStream("gzip")));
  const entries = parseTar(buffer);

  const files: SourceFile[] = [];
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let bytes = 0;
  let dropped = truncated;
  for (const entry of entries) {
    // Strip the "owner-repo-sha/" root directory GitHub adds.
    const rel = safeRelativePath(entry.name.split("/").slice(1).join("/"));
    if (!rel || isIgnoredPath(rel)) continue;
    if (entry.data.length > LIMITS.maxFileBytes) continue;
    if (files.length >= LIMITS.maxFiles || bytes + entry.data.length > LIMITS.maxTotalBytes) {
      dropped = true;
      break;
    }
    // Skip obvious binaries (NUL in the first block); the scanner also re-checks.
    if (entry.data.subarray(0, 8000).includes(0)) continue;
    bytes += entry.data.length;
    files.push({ path: rel, content: decoder.decode(entry.data) });
  }

  if (!files.length) throw new RepoFetchError(422, "REPO_EMPTY", "No scannable text files were found in that repository.");
  return { files, label: `${target.owner}/${target.repo}${ref ? `@${ref}` : ""}`, truncated: dropped, fileCount: files.length };
}

import { createHash } from "node:crypto";
import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { DetectorCoverage, Finding, Severity } from "../../contracts/src/index.ts";
import { ADVISORY_DB_VERSION, advisoriesFor } from "./advisories.ts";

export type SourceFile = { path: string; content: string };

export const LIMITS = { maxFiles: 2000, maxFileBytes: 1_000_000, maxTotalBytes: 12_000_000, maxLineChars: 4000 };

const IGNORED_DIRECTORIES = new Set(["node_modules", ".git", ".hg", ".svn", "dist", "build", ".next", "out", "coverage", "vendor", ".venv", "venv", "__pycache__", ".signalward", ".turbo", ".cache"]);
const BINARY_EXTENSIONS = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|o|a|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|glb|gltf|bin|dat|db|sqlite|lockb)$/i;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function findingId(ruleId: string, path: string, line: number, fingerprint: string): string {
  return `SW-${sha256(`${ruleId}|${path}|${line}|${fingerprint}`).slice(0, 10).toUpperCase()}`;
}

/** Normalise an untrusted relative path. Absolute paths, traversal segments and NUL bytes are refused. */
export function safeRelativePath(input: unknown): string | null {
  if (typeof input !== "string" || !input || input.length > 512 || input.includes("\0")) return null;
  const normalized = input.replace(/\\/g, "/").replace(/^(\.\/)+/, "");
  if (normalized.startsWith("/") || /^[a-z]:/i.test(normalized)) return null;
  const segments = normalized.split("/").filter(Boolean);
  if (!segments.length || segments.some((segment) => segment === ".." || segment === ".")) return null;
  return segments.join("/");
}

export function isIgnoredPath(path: string): boolean {
  return path.split("/").some((segment) => IGNORED_DIRECTORIES.has(segment)) || BINARY_EXTENSIONS.test(path);
}

/** Keep the first four characters so a reviewer can recognise the credential type, and nothing else. */
export function redact(value: string): string {
  return `${value.slice(0, 4)}…[${value.length} chars redacted]`;
}

function entropy(value: string): number {
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

type SecretRule = {
  id: string;
  title: string;
  severity: Severity;
  pattern: RegExp;
  /** Capture group holding the secret. Defaults to the whole match. */
  group?: number;
  remediation: string;
};

const ROTATE = "Revoke the credential at its provider, issue a new one into a secret store, and purge it from Git history.";

const SECRET_RULES: SecretRule[] = [
  { id: "secret.private_key", title: "Private key block committed", severity: "critical", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, remediation: "Treat the key as compromised. Replace it, update every system that trusts it, and purge it from history." },
  { id: "secret.aws_access_key_id", title: "AWS access key ID", severity: "high", pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.aws_secret_access_key", title: "AWS secret access key", severity: "critical", pattern: /aws.{0,24}(?:secret|private).{0,24}?['"=:\s]\s*['"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, group: 1, remediation: ROTATE },
  { id: "secret.github_token", title: "GitHub token", severity: "high", pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.github_fine_grained", title: "GitHub fine-grained token", severity: "high", pattern: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.gitlab_token", title: "GitLab personal access token", severity: "high", pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.slack_token", title: "Slack token", severity: "high", pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.slack_webhook", title: "Slack incoming webhook", severity: "medium", pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{16,})/g, group: 1, remediation: "Delete the webhook in Slack and create a replacement stored as a secret." },
  { id: "secret.stripe_live", title: "Stripe live secret key", severity: "critical", pattern: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/g, group: 1, remediation: ROTATE },
  { id: "secret.google_api_key", title: "Google API key", severity: "high", pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g, group: 1, remediation: "Delete or restrict the key in Google Cloud, then issue a replacement with API and referrer restrictions." },
  { id: "secret.connection_string", title: "Database URL with an embedded password", severity: "high", pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?):\/\/[^:\s/@]+:([^@\s'"]{4,})@/gi, group: 1, remediation: "Change the database password and load the URL from the environment or a secret store." },
  { id: "secret.jwt", title: "JSON Web Token", severity: "medium", pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g, group: 1, remediation: "If the token is long-lived or privileged (for example a service-role key), rotate the signing secret." },
];

const GENERIC_ASSIGNMENT = /\b([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passwd|password|pwd|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*(["']?)([^\s"'`,;#]{12,200})\2/gi;
const PLACEHOLDER = /^(\$\{|\$[A-Z_]|%[A-Z_]+%|process\.env|os\.environ|env\(|<|\{\{|x{4,}|\*{4,}|changeme|change_me|example|your[_-]|placeholder|dummy|sample|redacted|null|undefined|none|true|false|todo)/i;

function isSecretFile(path: string): boolean {
  const base = path.split("/").pop() ?? "";
  return /^\.env(\..+)?$|\.env$|^\.npmrc$|^\.pypirc$|^credentials(\.json)?$|\.pem$|\.key$|^secrets?\.(ya?ml|json|toml)$/i.test(base);
}

type Draft = Omit<Finding, "id"> & { fingerprint: string };

function toFinding(draft: Draft): Finding {
  const { fingerprint, ...rest } = draft;
  return { id: findingId(draft.ruleId, draft.location?.path ?? "", draft.location?.line ?? 0, fingerprint), ...rest };
}

function excerpt(line: string, secret: string): string {
  const masked = line.split(secret).join(redact(secret)).trim();
  return masked.length > 160 ? `${masked.slice(0, 159)}…` : masked;
}

function scanSecrets(file: SourceFile, suppressed: { count: number }): Draft[] {
  const drafts: Draft[] = [];
  const lines = file.content.split(/\r?\n/);
  const secretFile = isSecretFile(file.path);
  lines.forEach((rawLine, index) => {
    const line = rawLine.length > LIMITS.maxLineChars ? rawLine.slice(0, LIMITS.maxLineChars) : rawLine;
    if (!line.trim()) return;
    if (/signalward:allow/i.test(line)) {
      suppressed.count += 1;
      return;
    }
    const lineNumber = index + 1;
    const matchedValues = new Set<string>();
    for (const rule of SECRET_RULES) {
      rule.pattern.lastIndex = 0;
      for (const match of line.matchAll(rule.pattern)) {
        const value = match[rule.group ?? 0] ?? match[0];
        if (matchedValues.has(value)) continue;
        // Loose patterns (passwords in URLs, AWS secrets) also match template placeholders such as ${DB_PASSWORD}.
        if ((rule.id === "secret.connection_string" || rule.id === "secret.aws_secret_access_key") && PLACEHOLDER.test(value)) continue;
        matchedValues.add(value);
        const fingerprint = sha256(value).slice(0, 12);
        drafts.push({
          ruleId: rule.id, category: "secret", severity: rule.severity, confidence: "high", title: rule.title,
          description: `A value matching the ${rule.title.toLowerCase()} format appears in ${file.path} on line ${lineNumber}.`,
          impact: "Anyone with read access to the repository or its history can use this credential.",
          remediation: rule.remediation,
          location: { path: file.path, line: lineNumber },
          evidence: [
            { label: "Line", value: rule.id === "secret.private_key" ? "-----BEGIN … PRIVATE KEY----- [key body redacted]" : excerpt(line, value) },
            { label: "Fingerprint", value: `sha256:${fingerprint}` },
          ],
          fingerprint,
        });
      }
    }
    GENERIC_ASSIGNMENT.lastIndex = 0;
    for (const match of line.matchAll(GENERIC_ASSIGNMENT)) {
      const name = match[1] ?? "";
      const value = match[3] ?? "";
      if ([...matchedValues].some((known) => known.includes(value) || value.includes(known))) continue;
      if (PLACEHOLDER.test(value) || /[()[\]{}]/.test(value) || /^[a-z_]+(\.[a-z_]+)+$/i.test(value) || /^(.)\1+$/.test(value)) continue;
      if (/^(https?:)?\/\//i.test(value) && !/:[^@/]+@/.test(value)) continue;
      if (entropy(value) < 3.3) continue;
      const fingerprint = sha256(value).slice(0, 12);
      drafts.push({
        ruleId: "secret.generic_assignment", category: "secret", severity: secretFile ? "high" : "medium", confidence: "medium",
        title: `High-entropy value assigned to "${name.slice(0, 48)}"`,
        description: `A credential-like value is assigned to ${name.slice(0, 48)} in ${file.path} on line ${lineNumber}.`,
        impact: secretFile ? "Environment and credential files are a common source of leaked production secrets." : "Hard-coded credentials spread to every clone, fork and build log.",
        remediation: "If the value is real, rotate it and load it from the environment. If it is test data, mark the line with signalward:allow.",
        location: { path: file.path, line: lineNumber },
        evidence: [{ label: "Line", value: excerpt(line, value) }, { label: "Fingerprint", value: `sha256:${fingerprint}` }],
        fingerprint,
      });
    }
  });
  return drafts;
}

type Dependency = { ecosystem: "npm" | "pypi"; name: string; version: string; path: string; line: number };

function lineOf(content: string, needle: string): number {
  const index = content.indexOf(needle);
  return index < 0 ? 1 : content.slice(0, index).split("\n").length;
}

function collectDependencies(file: SourceFile): Dependency[] {
  const base = file.path.split("/").pop() ?? "";
  const found: Dependency[] = [];
  try {
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      const lock = JSON.parse(file.content) as { packages?: Record<string, { version?: string }>; dependencies?: Record<string, unknown> };
      if (lock.packages) {
        for (const [key, value] of Object.entries(lock.packages)) {
          if (!key || !value?.version) continue;
          const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
          found.push({ ecosystem: "npm", name, version: value.version, path: file.path, line: lineOf(file.content, `"${key}"`) });
        }
      } else if (lock.dependencies) {
        const walk = (deps: Record<string, unknown>) => {
          for (const [name, raw] of Object.entries(deps)) {
            const entry = raw as { version?: string; dependencies?: Record<string, unknown> };
            if (entry.version) found.push({ ecosystem: "npm", name, version: entry.version, path: file.path, line: lineOf(file.content, `"${name}"`) });
            if (entry.dependencies) walk(entry.dependencies);
          }
        };
        walk(lock.dependencies);
      }
    } else if (base === "package.json") {
      const manifest = JSON.parse(file.content) as Record<string, Record<string, string> | undefined>;
      for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
        for (const [name, spec] of Object.entries(manifest[field] ?? {})) {
          const exact = /^=?v?(\d+\.\d+\.\d+(?:-[\w.]+)?)$/.exec(String(spec).trim());
          if (exact) found.push({ ecosystem: "npm", name, version: exact[1]!, path: file.path, line: lineOf(file.content, `"${name}"`) });
        }
      }
    } else if (base === "yarn.lock") {
      const lines = file.content.split(/\r?\n/);
      let current: string | null = null;
      lines.forEach((line, index) => {
        const header = /^"?(@?[^@"\s]+)@[^:]*:\s*$/.exec(line);
        if (header) current = header[1]!;
        const version = /^\s+version:?\s+"?([^"\s]+)"?/.exec(line);
        if (current && version) {
          found.push({ ecosystem: "npm", name: current, version: version[1]!, path: file.path, line: index + 1 });
          current = null;
        }
      });
    } else if (base === "pnpm-lock.yaml") {
      file.content.split(/\r?\n/).forEach((line, index) => {
        const entry = /^\s{2}['"]?\/?((?:@[^/@\s'"]+\/)?[^/@\s'"]+)[@/](\d+\.\d+\.\d+[^:'"\s(]*)/.exec(line);
        if (entry) found.push({ ecosystem: "npm", name: entry[1]!, version: entry[2]!, path: file.path, line: index + 1 });
      });
    } else if (/^requirements.*\.txt$/i.test(base)) {
      file.content.split(/\r?\n/).forEach((line, index) => {
        const entry = /^\s*([A-Za-z0-9_.-]+)\s*==\s*([0-9][\w.]*)/.exec(line);
        if (entry) found.push({ ecosystem: "pypi", name: entry[1]!.toLowerCase().replace(/_/g, "-"), version: entry[2]!, path: file.path, line: index + 1 });
      });
    }
  } catch {
    return [];
  }
  return found;
}

function scanDependencies(files: SourceFile[]): { drafts: Draft[]; manifests: string[]; packages: number } {
  const drafts: Draft[] = [];
  const manifests: string[] = [];
  const seen = new Set<string>();
  let packages = 0;
  for (const file of files) {
    const deps = collectDependencies(file);
    if (!deps.length) continue;
    manifests.push(file.path);
    packages += deps.length;
    for (const dep of deps) {
      for (const advisory of advisoriesFor(dep.ecosystem, dep.name, dep.version)) {
        const key = `${advisory.id}|${dep.name}|${dep.version}|${dep.path}`;
        if (seen.has(key)) continue;
        seen.add(key);
        drafts.push({
          ruleId: `dependency.${advisory.id}`, category: "dependency", severity: advisory.severity, confidence: "high",
          title: `${dep.name}@${dep.version}: ${advisory.summary.replace(/\.$/, "")}`,
          description: `${dep.path} resolves ${dep.name} ${dep.version}, which ${advisory.id}${advisory.aliases.length ? ` (${advisory.aliases.join(", ")})` : ""} lists as affected.`,
          impact: advisory.severity === "critical" ? "Known-exploited or malicious releases can run attacker code during install or at runtime." : "A published vulnerability affects this version.",
          remediation: advisory.fixedIn === "remove" ? `Remove ${dep.name} and audit hosts that installed it.` : `Upgrade ${dep.name} to ${advisory.fixedIn} or later and regenerate the lockfile.`,
          location: { path: dep.path, line: dep.line },
          evidence: [{ label: "Package", value: `${dep.ecosystem}:${dep.name}@${dep.version}` }, { label: "Advisory", value: advisory.id }],
          fingerprint: `${advisory.id}:${dep.name}@${dep.version}`,
        });
      }
    }
  }
  return { drafts, manifests, packages };
}

const CI_FILE = /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|Jenkinsfile|Dockerfile[^/]*)$/i;
const UNTRUSTED_CONTEXT = /\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|pages|commits)[\w.[\]*]*\.(title|body|message|name|label|ref|email)|github\.head_ref)\s*\}\}/i;

function scanCi(file: SourceFile): Draft[] {
  if (!CI_FILE.test(file.path)) return [];
  const drafts: Draft[] = [];
  const lines = file.content.split(/\r?\n/);
  const isGithub = file.path.includes(".github/workflows/");
  const privilegedTrigger = isGithub && /\bpull_request_target\b|\bworkflow_run\b/.test(file.content);
  let runIndent = -1;

  const push = (ruleId: string, severity: Severity, title: string, description: string, impact: string, remediation: string, lineNumber: number, value: string) => {
    drafts.push({
      ruleId, category: "configuration", severity, confidence: severity === "low" ? "medium" : "high", title, description, impact, remediation,
      location: { path: file.path, line: lineNumber },
      evidence: [{ label: "Line", value: value.trim().slice(0, 160) }],
      fingerprint: `${ruleId}:${value.trim()}`,
    });
  };

  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const indent = line.length - line.trimStart().length;
    if (runIndent >= 0 && line.trim() && indent <= runIndent) runIndent = -1;
    const runStart = /^(\s*)(-\s*)?run:\s*(.*)$/.exec(line);
    const inRun = Boolean(runStart) || runIndent >= 0;
    if (runStart && /^[|>]/.test(runStart[3] ?? "")) runIndent = indent;

    if (isGithub && inRun && UNTRUSTED_CONTEXT.test(line)) {
      push("ci.script_injection", "high", "Untrusted event text interpolated into a shell step",
        "A run step expands attacker-controlled event fields (titles, bodies, branch names) directly into the shell.",
        "Anyone who can open an issue or pull request can run commands with the workflow's token and secrets.",
        "Pass the value through an env: variable and reference it as \"$VAR\" inside the script.", lineNumber, line);
    }
    if (privilegedTrigger && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)\s*\}\}/.test(line)) {
      push("ci.untrusted_checkout", "high", "Privileged workflow checks out pull request code",
        "The workflow runs on pull_request_target or workflow_run and checks out the contributor's head commit.",
        "Fork code then runs with a write token and repository secrets.",
        "Use the pull_request trigger for untrusted code, or split build and privileged steps into separate workflows.", lineNumber, line);
    }
    if (isGithub && /^\s*permissions:\s*write-all\s*$/.test(line)) {
      push("ci.write_all_permissions", "medium", "Workflow token has write access to everything",
        "permissions: write-all grants the GITHUB_TOKEN every write scope.", "A compromised step can push code, publish releases and alter settings.",
        "Declare the minimal permissions block each job needs, defaulting to contents: read.", lineNumber, line);
    }
    const uses = /uses:\s*['"]?([\w.-]+)\/([\w./-]+)@([\w.-]+)/.exec(line);
    if (isGithub && uses && !["actions", "github"].includes(uses[1]!.toLowerCase()) && !/^[0-9a-f]{40}$/i.test(uses[3]!)) {
      push("ci.unpinned_action", "low", `Third-party action ${uses[1]}/${uses[2]} pinned to a mutable ref`,
        `The action is referenced by "${uses[3]}", which its owner can move to different code.`,
        "A compromised action release runs inside your pipeline with its secrets.",
        "Pin third-party actions to a full commit SHA and let Dependabot propose updates.", lineNumber, line);
    }
    if (/\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b/.test(line)) {
      push("ci.pipe_to_shell", "medium", "Remote script piped straight into a shell",
        "The build downloads a script and executes it without verifying its integrity.",
        "Whoever controls that URL, or the network path to it, controls the build.",
        "Download to a file, verify a pinned checksum or signature, then execute.", lineNumber, line);
    }
    if (/\becho\b[^\n]*\$\{\{\s*secrets\./.test(line)) {
      push("ci.secret_echo", "high", "Secret written to the build log",
        "A step echoes a secrets.* expression.", "Masking is best-effort; transformed or partial values leak into logs and artifacts.",
        "Remove the echo. Pass secrets to tools through environment variables only.", lineNumber, line);
    }
  });
  return drafts;
}

export type RepositoryScanOutput = {
  findings: Finding[];
  coverage: DetectorCoverage[];
  files: number;
  bytes: number;
  skipped: number;
  suppressed: number;
};

/** Scan an in-memory snapshot. Callers must already have bounded the input; limits are re-checked here. */
export function scanFiles(input: readonly SourceFile[]): RepositoryScanOutput {
  const files: SourceFile[] = [];
  let bytes = 0;
  let skipped = 0;
  for (const raw of input) {
    const path = safeRelativePath(raw.path);
    if (!path || typeof raw.content !== "string" || isIgnoredPath(path)) {
      skipped += 1;
      continue;
    }
    const size = Buffer.byteLength(raw.content);
    if (size > LIMITS.maxFileBytes || files.length >= LIMITS.maxFiles || bytes + size > LIMITS.maxTotalBytes || raw.content.slice(0, 8000).includes("\u0000")) {
      skipped += 1;
      continue;
    }
    bytes += size;
    files.push({ path, content: raw.content });
  }

  const suppressed = { count: 0 };
  const drafts: Draft[] = [];
  for (const file of files) drafts.push(...scanSecrets(file, suppressed));
  const deps = scanDependencies(files);
  drafts.push(...deps.drafts);
  const ciFiles = files.filter((file) => CI_FILE.test(file.path));
  for (const file of ciFiles) drafts.push(...scanCi(file));

  const unique = new Map<string, Finding>();
  for (const draft of drafts) {
    const finding = toFinding(draft);
    unique.set(finding.id, finding);
  }

  const coverage: DetectorCoverage[] = [
    {
      detector: "secrets",
      status: skipped ? "partial" : "ran",
      detail: `${SECRET_RULES.length + 1} rules over ${files.length} files${skipped ? `; ${skipped} skipped by path, type or size limits` : ""}${suppressed.count ? `; ${suppressed.count} lines allowed inline` : ""}.`,
      required: true,
    },
    {
      detector: "dependencies",
      status: "ran",
      detail: deps.manifests.length ? `${deps.packages} pinned packages in ${deps.manifests.length} manifest(s) checked against ${ADVISORY_DB_VERSION}.` : "No pinned dependencies found in supported lockfiles or manifests.",
      required: true,
    },
    { detector: "ci_configuration", status: "ran", detail: ciFiles.length ? `${ciFiles.length} pipeline file(s) checked.` : "No pipeline files found.", required: true },
    { detector: "osv_live", status: "skipped", detail: "Live OSV lookups are off in the local preview. The pinned subset is not exhaustive.", required: false },
  ];

  const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const findings = [...unique.values()].sort((a, b) => order[a.severity] - order[b.severity] || (a.location?.path ?? "").localeCompare(b.location?.path ?? ""));
  return { findings, coverage, files: files.length, bytes, skipped, suppressed: suppressed.count };
}

/**
 * Read a local checkout for the CLI. Symlinks are never followed and the canonical path must stay inside root.
 */
export async function readDirectory(root: string): Promise<{ files: SourceFile[]; skipped: number }> {
  const canonicalRoot = await realpath(root);
  const files: SourceFile[] = [];
  let skipped = 0;
  let total = 0;
  const walk = async (directory: string): Promise<void> => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const absolute = join(directory, entry.name);
      const rel = relative(canonicalRoot, absolute).split(sep).join("/");
      if (entry.isSymbolicLink()) {
        skipped += 1;
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name)) continue;
        await walk(absolute);
        continue;
      }
      if (!entry.isFile() || isIgnoredPath(rel)) continue;
      const info = await lstat(absolute);
      if (info.size > LIMITS.maxFileBytes || files.length >= LIMITS.maxFiles || total + info.size > LIMITS.maxTotalBytes) {
        skipped += 1;
        continue;
      }
      const resolved = await realpath(absolute);
      if (!resolved.startsWith(canonicalRoot + sep) && resolved !== canonicalRoot) {
        skipped += 1;
        continue;
      }
      total += info.size;
      files.push({ path: rel, content: await readFile(absolute, "utf8") });
    }
  };
  await walk(canonicalRoot);
  return { files, skipped };
}

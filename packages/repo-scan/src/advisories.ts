/**
 * Pinned advisory subset (signalward-advisories-2026.11). It is deliberately small and offline so scans are
 * deterministic. It is not exhaustive: enable OSV lookups for full dependency coverage.
 */
export const ADVISORY_DB_VERSION = "signalward-advisories-2026.11";

export type Advisory = {
  id: string;
  aliases: string[];
  ecosystem: "npm" | "pypi";
  name: string;
  severity: "medium" | "high" | "critical";
  summary: string;
  /** Affected when introduced <= v < fixed. Missing introduced means "from the first release". */
  ranges?: { introduced?: string; fixed: string }[];
  /** Exact affected releases, used for compromised or malicious publishes. */
  versions?: string[];
  fixedIn: string;
};

export const ADVISORIES: Advisory[] = [
  { id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], ecosystem: "npm", name: "lodash", severity: "high", summary: "Command injection through the template function.", ranges: [{ fixed: "4.17.21" }], fixedIn: "4.17.21" },
  { id: "GHSA-xvch-5gv4-984h", aliases: ["CVE-2021-44906"], ecosystem: "npm", name: "minimist", severity: "critical", summary: "Prototype pollution through crafted arguments.", ranges: [{ fixed: "1.2.6" }], fixedIn: "1.2.6" },
  { id: "GHSA-wf5p-g6vw-rhxx", aliases: ["CVE-2023-45857"], ecosystem: "npm", name: "axios", severity: "medium", summary: "The XSRF-TOKEN cookie is sent to third-party hosts.", ranges: [{ introduced: "0.8.1", fixed: "0.28.0" }, { introduced: "1.0.0", fixed: "1.6.0" }], fixedIn: "1.6.0" },
  { id: "GHSA-qwph-4952-7xr6", aliases: ["CVE-2022-23540"], ecosystem: "npm", name: "jsonwebtoken", severity: "medium", summary: "Insecure default algorithm handling can allow signature bypass.", ranges: [{ fixed: "9.0.0" }], fixedIn: "9.0.0" },
  { id: "GHSA-mh6f-8j2x-4483", aliases: [], ecosystem: "npm", name: "event-stream", severity: "critical", summary: "Release 3.3.6 shipped the malicious flatmap-stream dependency.", versions: ["3.3.6"], fixedIn: "4.0.0" },
  { id: "GHSA-mh6f-8j2x-4483", aliases: [], ecosystem: "npm", name: "flatmap-stream", severity: "critical", summary: "Malicious package that targeted cryptocurrency wallets.", versions: ["0.1.1"], fixedIn: "remove" },
  { id: "GHSA-pjwm-rvh2-c87w", aliases: [], ecosystem: "npm", name: "ua-parser-js", severity: "critical", summary: "Hijacked releases installed credential-stealing malware.", versions: ["0.7.29", "0.8.0", "1.0.0"], fixedIn: "0.7.30" },
  { id: "GHSA-97m3-w2cp-4xx6", aliases: ["CVE-2022-23812"], ecosystem: "npm", name: "node-ipc", severity: "critical", summary: "Sabotaged releases overwrite files on some hosts.", versions: ["10.1.1", "10.1.2"], fixedIn: "10.1.3" },
  { id: "GHSA-c2qf-rxjj-qqgw", aliases: ["CVE-2022-25883"], ecosystem: "npm", name: "semver", severity: "medium", summary: "Regular expression denial of service in range parsing.", ranges: [{ fixed: "5.7.2" }, { introduced: "6.0.0", fixed: "6.3.1" }, { introduced: "7.0.0", fixed: "7.5.2" }], fixedIn: "7.5.2" },
  { id: "GHSA-jchw-25xp-jwwc", aliases: ["CVE-2023-26159"], ecosystem: "npm", name: "follow-redirects", severity: "medium", summary: "Improper URL handling can redirect to unexpected hosts.", ranges: [{ fixed: "1.15.4" }], fixedIn: "1.15.4" },
  { id: "GHSA-j8r2-6x86-q33q", aliases: ["CVE-2023-32681"], ecosystem: "pypi", name: "requests", severity: "medium", summary: "Proxy-Authorization header leaks to destination servers on redirect.", ranges: [{ introduced: "2.3.0", fixed: "2.31.0" }], fixedIn: "2.31.0" },
  { id: "GHSA-8q59-q68h-6hv4", aliases: ["CVE-2020-14343"], ecosystem: "pypi", name: "pyyaml", severity: "critical", summary: "Arbitrary code execution through full_load and FullLoader.", ranges: [{ fixed: "5.4" }], fixedIn: "5.4" },
];

function parts(version: string): number[] {
  return version.replace(/^[v=]/, "").split(/[-+]/)[0]!.split(".").map((part) => Number.parseInt(part, 10) || 0);
}

export function compareVersions(a: string, b: string): number {
  const left = parts(a);
  const right = parts(b);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const diff = (left[index] ?? 0) - (right[index] ?? 0);
    if (diff) return diff;
  }
  // A prerelease sorts before its release.
  const leftPre = a.includes("-");
  const rightPre = b.includes("-");
  return leftPre === rightPre ? 0 : leftPre ? -1 : 1;
}

export function advisoriesFor(ecosystem: Advisory["ecosystem"], name: string, version: string): Advisory[] {
  const lower = name.toLowerCase();
  return ADVISORIES.filter((advisory) => {
    if (advisory.ecosystem !== ecosystem || advisory.name !== lower) return false;
    if (advisory.versions?.includes(version)) return true;
    return (advisory.ranges ?? []).some(
      (range) => (!range.introduced || compareVersions(version, range.introduced) >= 0) && compareVersions(version, range.fixed) < 0,
    );
  });
}

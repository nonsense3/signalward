import type { Finding } from "../../contracts/src/index.ts";
import { finding } from "../../fraud-scan/src/rules.ts";

/**
 * Passive domain intelligence. Inspired by Veriq's RDAP domain-age check: it queries the domain's
 * registration record (not the suspicious page) and flags freshly registered names, which dominate
 * short-lived phishing. Uses only fetch so it runs on Node and Cloudflare Workers; fails open.
 */
export async function domainAgeFinding(domain: string, options: { timeoutMs?: number } = {}): Promise<Finding | null> {
  const host = String(domain).trim().toLowerCase().replace(/^\.|\.$/g, "");
  if (!host || !/^[a-z0-9.-]+\.[a-z]{2,24}$/.test(host)) return null;
  try {
    const response = await fetch(`https://rdap.org/domain/${encodeURIComponent(host)}`, {
      headers: { Accept: "application/rdap+json" },
      redirect: "follow",
      signal: AbortSignal.timeout(options.timeoutMs ?? 4000),
    });
    if (!response.ok) return null;
    const data = (await response.json()) as { events?: { eventAction?: string; eventDate?: string }[] };
    const registration = (data.events ?? []).find((event) => event.eventAction === "registration");
    if (!registration?.eventDate) return null;
    const registered = Date.parse(registration.eventDate);
    if (!Number.isFinite(registered)) return null;
    const days = Math.floor((Date.now() - registered) / 86_400_000);
    if (days < 0 || days > 180) return null; // only young domains are a signal
    const severity = days <= 7 ? "high" : days <= 30 ? "medium" : "low";
    const date = registration.eventDate.slice(0, 10);
    return finding({
      ruleId: "url.domain_age",
      category: "domain",
      severity,
      confidence: "high",
      title: `Domain registered ${days} day${days === 1 ? "" : "s"} ago`,
      description: `${host} was first registered on ${date}, which is recent.`,
      impact: "Freshly registered domains are heavily used for short-lived phishing and scam infrastructure.",
      remediation: "Treat a brand-new domain with suspicion, especially alongside brand or credential signals.",
      evidence: [{ label: "Domain", value: host }, { label: "Registered", value: date }, { label: "Age", value: `${days} days` }],
    });
  } catch {
    return null; // RDAP unavailable, timed out, or domain not found — skip silently
  }
}

export type UrlHausHostResult = {
  status: "checked" | "unavailable";
  detail: string;
  finding?: Finding;
};

/**
 * Check only the submitted hostname, never its path or query string. This gives URLhaus
 * enough context for host reputation while avoiding disclosure of per-user URL tokens and paths.
 */
export async function urlHausHostFinding(host: string, authKey: string, options: { timeoutMs?: number } = {}): Promise<UrlHausHostResult> {
  const normalizedHost = host.trim().toLowerCase().replace(/\.$/, "");
  if (!normalizedHost || normalizedHost.length > 253 || !/^[a-z0-9.-]+$/.test(normalizedHost)) {
    return { status: "unavailable", detail: "Host is not eligible for URLhaus lookup." };
  }
  try {
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/host/", {
      method: "POST",
      headers: { "Auth-Key": authKey, "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ host: normalizedHost }),
      signal: AbortSignal.timeout(options.timeoutMs ?? 4000),
    });
    if (!response.ok) return { status: "unavailable", detail: `URLhaus host lookup returned HTTP ${response.status}.` };
    const data = await response.json() as {
      query_status?: string;
      host?: string;
      url_count?: string | number;
      firstseen?: string;
      urlhaus_reference?: string;
      blacklists?: { spamhaus_dbl?: string; surbl?: string };
      urls?: { url?: string; url_status?: string; date_added?: string; threat?: string }[] | null;
    };
    if (data.query_status === "no_results") return { status: "checked", detail: `URLhaus has no host record for ${normalizedHost}.` };
    if (data.query_status !== "ok") return { status: "unavailable", detail: `URLhaus returned status ${String(data.query_status ?? "unknown")}.` };

    const dbl = data.blacklists?.spamhaus_dbl?.toLowerCase() ?? "not listed";
    const surbl = data.blacklists?.surbl?.toLowerCase() ?? "not listed";
    const spamhausStatuses = new Set([
      "spammer_domain", "phishing_domain", "botnet_cc_domain", "abused_legit_spam",
      "abused_legit_malware", "abused_legit_phishing", "abused_legit_botnetcc", "abused_redirector",
    ]);
    const spamhausListed = spamhausStatuses.has(dbl);
    const surblListed = surbl === "listed";
    const knownAbuse = spamhausListed || surblListed;
    const listedValues = [spamhausListed ? `Spamhaus DBL: ${dbl}` : "", surblListed ? "SURBL: listed" : ""].filter(Boolean);
    const count = Number(data.url_count ?? 0);
    const hostMalwareRecord = (data.urls ?? []).find((item) => {
      if (!item.url) return false;
      try {
        const listed = new URL(item.url);
        const submitted = new URL(`https://${normalizedHost}`); // Exact path is intentionally not sent to URLhaus.
        return listed.hostname.toLowerCase() === submitted.hostname.toLowerCase() && item.threat === "malware_download";
      } catch {
        return false;
      }
    });

    if (!knownAbuse && !hostMalwareRecord) {
      return { status: "checked", detail: `URLhaus checked ${normalizedHost}; no listed URL or blacklist match was returned${count ? ` (${count} host URL record(s) were reported)` : ""}.` };
    }

    // Host queries cannot prove that the exact submitted path is malicious. Reserve high
    // confidence for an explicit phishing-domain or botnet C&C listing on the queried host.
    const highConfidence = dbl === "phishing_domain" || dbl === "botnet_cc_domain";
    const severity = highConfidence ? "high" : "medium";
    const reference = data.urlhaus_reference && /^https:\/\/urlhaus\.abuse\.ch\//.test(data.urlhaus_reference)
      ? data.urlhaus_reference
      : "https://urlhaus.abuse.ch/";
    const evidence = [
      { label: "Host", value: normalizedHost },
      ...(listedValues.length ? [{ label: "Threat listings", value: listedValues.join("; ") }] : []),
      ...(hostMalwareRecord ? [{ label: "Host malware URL record", value: `${hostMalwareRecord.url_status ?? "status unknown"}; added ${hostMalwareRecord.date_added ?? "date unknown"}` }] : []),
      ...(data.firstseen ? [{ label: "First seen", value: data.firstseen.slice(0, 40) }] : []),
      { label: "Source record", value: reference },
    ];
    return {
      status: "checked",
      detail: `URLhaus returned host reputation for ${normalizedHost}.`,
      finding: finding({
        ruleId: "url.urlhaus_host_reputation",
        category: "intelligence",
        severity,
        confidence: highConfidence ? "high" : "medium",
        title: "Host appears in live threat-intelligence data",
        description: `URLhaus returned a host-level signal: ${listedValues.join(", ") || "one or more malware URLs were reported for this host"}. This does not prove that the submitted path is malicious; its path and query were not sent to the provider.`,
        impact: "This hostname has a current or historical association with reported phishing, malware, or abusive infrastructure.",
        remediation: "Do not open the link. Verify the destination through an independently trusted source.",
        evidence,
      }),
    };
  } catch (error) {
    return { status: "unavailable", detail: `URLhaus lookup failed${error instanceof Error ? ` (${error.name})` : ""}.` };
  }
}

export { parseUrlRiskModelB64, scoreUrlRiskModel, urlRiskFeatures, URL_MODEL_FEATURES } from "./model.ts";
export type { UrlModelScore, UrlRiskModel } from "./model.ts";
export { suricataAlertFinding } from "./suricata.ts";

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

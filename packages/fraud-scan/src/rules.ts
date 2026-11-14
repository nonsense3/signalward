import { createHash } from "node:crypto";
import type { Confidence, Evidence, Finding, FindingCategory, Severity } from "../../contracts/src/index.ts";
import { BRANDS, HIGH_ABUSE_TLDS, URL_SHORTENERS, isOfficialDomain, sharedHostingPlatform, type Brand } from "./domains.ts";
import { levenshtein, scriptsIn, shannonEntropy, skeleton } from "./text.ts";
import { normalizeTarget, registrableLabel, type UrlEvidence } from "./url.ts";

export type FindingInput = {
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  impact: string;
  remediation: string;
  evidence: Evidence[];
  confidence?: Confidence;
};

export function finding(input: FindingInput): Finding {
  const fingerprint = createHash("sha256").update(`${input.ruleId}|${input.title}|${input.evidence.map((item) => item.value).join("|")}`).digest("hex");
  return { id: `SW-${fingerprint.slice(0, 10).toUpperCase()}`, ...input, confidence: input.confidence ?? "medium" };
}

const CREDENTIAL_WORDS = ["login", "log-in", "signin", "sign-in", "verify", "verification", "account", "secure", "update", "kyc", "wallet", "confirm", "password", "banking", "unlock", "suspend", "suspended", "recover", "billing", "auth", "otp", "refund", "claim"];
const REDIRECT_PARAMS = new Set(["url", "redirect", "redirect_uri", "redirect_url", "redir", "next", "continue", "dest", "destination", "u", "r", "target", "goto", "returnurl", "return", "return_to", "out", "link", "to"]);
const GLUE_WORDS = ["secure", "security", "login", "signin", "verify", "verification", "support", "help", "service", "services", "online", "account", "accounts", "update", "auth", "india", "my", "web", "official", "app", "pay", "bank", "banking", "customer", "care", "team", "center", "centre", "desk", "portal", "kyc", "net", "info", "alert", "alerts", "notice", "refund", "reward", "rewards", "claim", "billing", "id", "user", "mail", "unlock", "confirm", "wallet", "gift", "prize", "delivery", "track", "tracking", "parcel", "in", "co", "e", "m", "go", "get"].sort((a, b) => b.length - a.length);

function isBrandPlusGlue(label: string, token: string): boolean {
  let rest = label.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (!rest.includes(token)) return false;
  rest = rest.replace(token, "").replace(/\d+/g, "");
  for (const word of GLUE_WORDS) rest = rest.split(word).join("");
  return rest.length === 0;
}

const tokensOf = (label: string) => label.toLowerCase().split(/[^a-z0-9\u00c0-\uffff]+/).filter(Boolean);

function decodeSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

type BrandSignal = { brand: Brand; kind: "exact_token" | "lookalike" | "subdomain" | "path" | "homograph" };

export function brandSignals(u: UrlEvidence): BrandSignal[] {
  if (u.isIp) return [];
  const signals: BrandSignal[] = [];
  const suffixLabels = (u.registrableDomain ?? "").split(".").length;
  const unicodeRegistrable = u.unicodeHostname.split(".").slice(-suffixLabels).join(".");
  const label = registrableLabel({ registrableDomain: unicodeRegistrable || u.registrableDomain, publicSuffix: u.publicSuffix });
  const labelTokens = tokensOf(label);
  const labelSkeleton = skeleton(label);
  const subTokens = tokensOf(u.subdomain ?? "");
  const pathTokens = tokensOf(decodeSafe(u.path));
  for (const brand of BRANDS) {
    if (isOfficialDomain(brand, u.registrableDomain, u.hostname)) continue;
    let matched: BrandSignal["kind"] | null = null;
    for (const token of brand.tokens) {
      if (labelTokens.includes(token) || (token.length >= 3 && isBrandPlusGlue(label, token))) {
        matched = "exact_token";
        break;
      }
      if (token.length >= 5) {
        const candidates = [labelSkeleton, ...labelTokens.map(skeleton)];
        if (candidates.some((candidate) => candidate === token || (candidate.includes(token) && isBrandPlusGlue(candidate, token)))) {
          matched = /[^a-z0-9-]/.test(label) ? "homograph" : "lookalike";
          break;
        }
        if (token.length >= 6) {
          const tolerance = token.length >= 8 ? 2 : 1;
          if (candidates.some((candidate) => candidate.length >= 5 && Math.abs(candidate.length - token.length) <= tolerance && levenshtein(candidate, token) <= tolerance)) {
            matched = "lookalike";
            break;
          }
        }
      }
    }
    if (!matched && brand.tokens.some((token) => subTokens.includes(token) || (token.length >= 5 && (u.subdomain ?? "").includes(token)))) matched = "subdomain";
    if (!matched && brand.tokens.some((token) => token.length >= 4 && pathTokens.includes(token))) matched = "path";
    if (matched) signals.push({ brand, kind: matched });
  }
  return signals;
}

/** Lexical URL rules. They never contact the destination and run for every link, including those inside messages. */
export function analyzeUrlLexical(u: UrlEvidence, context = ""): Finding[] {
  const findings: Finding[] = [];
  const prefix = context ? `${context}: ` : "";
  const hostEvidence = { label: "Host", value: u.unicodeHostname === u.hostname ? u.hostname : `${u.unicodeHostname} (${u.hostname})` };

  if (u.hadUserinfo) {
    findings.push(finding({ ruleId: "url.userinfo_deception", category: "phishing", severity: "high", confidence: "high",
      title: `${prefix}Link hides its real destination before an @ sign`,
      description: `The link contains text before an "@" sign. Browsers ignore that part and connect to ${u.hostname}.`,
      impact: "Attackers use this to make a link look like it belongs to a trusted site.",
      remediation: "Do not open the link. The real destination is the host after the @ sign.", evidence: [hostEvidence, { label: "Submitted", value: u.input.slice(0, 160) }] }));
  }
  if (u.isIp) {
    findings.push(finding({ ruleId: u.isPrivateIp ? "url.private_ip" : "url.ip_literal", category: "phishing", severity: "medium",
      title: u.isPrivateIp ? `${prefix}Link points to a private network address` : `${prefix}Link points to a raw IP address`,
      description: `The destination is ${u.hostname} instead of a domain name.`,
      impact: u.isPrivateIp ? "Links to internal addresses in external messages can target routers, admin panels or metadata services." : "Legitimate organisations rarely send raw IP links; they avoid domain reputation checks.",
      remediation: "Navigate to the organisation's site by typing its known domain.", evidence: [hostEvidence] }));
  }
  if (u.hostname.split(".").some((label) => label.startsWith("xn--"))) {
    const mixed = u.unicodeHostname.split(".").some((label) => scriptsIn(label).size > 1);
    findings.push(finding({ ruleId: "url.punycode", category: "phishing", severity: mixed ? "high" : "low", confidence: mixed ? "high" : "medium",
      title: mixed ? `${prefix}Domain mixes alphabets (homograph pattern)` : `${prefix}Internationalised domain name`,
      description: mixed ? `${u.unicodeHostname} combines characters from different alphabets and is encoded as ${u.hostname}.` : `The domain uses non-ASCII characters and is encoded as ${u.hostname}.`,
      impact: mixed ? "Mixed-script domains can look identical to a trusted brand." : "Unicode domains are legitimate but can imitate other names.",
      remediation: "Compare the encoded form with the domain you expect before entering anything.", evidence: [hostEvidence] }));
  }
  for (const signal of brandSignals(u)) {
    const kindText: Record<BrandSignal["kind"], string> = {
      exact_token: `contains the brand name "${signal.brand.tokens[0]}"`,
      lookalike: `closely resembles "${signal.brand.tokens[0]}" (typosquatting)`,
      homograph: `imitates "${signal.brand.tokens[0]}" with lookalike characters`,
      subdomain: `places "${signal.brand.tokens[0]}" in a subdomain`,
      path: `mentions "${signal.brand.tokens[0]}" in the path`,
    };
    findings.push(finding({ ruleId: `url.brand_${signal.kind}`, category: "phishing", severity: signal.kind === "path" ? "medium" : "high", confidence: signal.kind === "path" ? "low" : "medium",
      title: `${prefix}Possible ${signal.brand.name} impersonation`,
      description: `${u.registrableDomain ?? u.hostname} ${kindText[signal.kind]}, but ${signal.brand.name} does not operate it. Official domains include ${signal.brand.domains.slice(0, 3).join(", ")}.`,
      impact: `Recipients may believe they are on a ${signal.brand.name} site and disclose credentials or payment details.`,
      remediation: `Open ${signal.brand.name} by typing ${signal.brand.domains[0]} yourself.`,
      evidence: [hostEvidence, { label: "Registrable domain", value: u.registrableDomain ?? u.hostname }, { label: "Claimed brand", value: signal.brand.name }] }));
  }
  if (u.publicSuffix && HIGH_ABUSE_TLDS.has(u.publicSuffix.split(".").pop() ?? "")) {
    findings.push(finding({ ruleId: "url.high_abuse_tld", category: "domain", severity: "low", confidence: "low",
      title: `${prefix}Top-level domain frequently abused`, description: `.${u.publicSuffix} domains appear disproportionately in public phishing feeds.`,
      impact: "A weak signal on its own; many legitimate sites use this TLD.", remediation: "Treat as context alongside other findings.", evidence: [{ label: "TLD", value: `.${u.publicSuffix}` }] }));
  }
  const subLabels = u.subdomain ? u.subdomain.split(".").filter(Boolean) : [];
  if (subLabels.length >= 4) {
    findings.push(finding({ ruleId: "url.deep_subdomains", category: "phishing", severity: "medium",
      title: `${prefix}Unusually deep subdomain chain`, description: `The host has ${subLabels.length} subdomain levels before ${u.registrableDomain}.`,
      impact: "Long hostnames push the real domain out of view on mobile address bars.", remediation: "Read the hostname from the right; the owner is the registrable domain.", evidence: [hostEvidence] }));
  }
  const lowerUrl = decodeSafe(`${u.hostname}${u.path}`).toLowerCase();
  const credentialHits = CREDENTIAL_WORDS.filter((word) => lowerUrl.includes(word));
  if (credentialHits.length >= 2 || (credentialHits.length >= 1 && findings.some((item) => item.ruleId.startsWith("url.brand_")))) {
    findings.push(finding({ ruleId: "url.credential_keywords", category: "phishing", severity: "low", confidence: "low",
      title: `${prefix}Account or verification wording in the link`, description: `The link contains ${credentialHits.map((word) => `"${word}"`).join(", ")}.`,
      impact: "Phishing links use account wording to look procedural.", remediation: "Sign in only through the official app or a bookmark.", evidence: [{ label: "Keywords", value: credentialHits.join(", ") }] }));
  }
  if (u.scheme === "http" && credentialHits.length >= 1) {
    findings.push(finding({ ruleId: "url.cleartext_credential_path", category: "phishing", severity: "medium",
      title: `${prefix}Sign-in wording over unencrypted HTTP`, description: "The link uses plain HTTP while referring to account or sign-in actions.",
      impact: "Anything typed on the page can be read or changed in transit.", remediation: "Never enter credentials on an HTTP page.", evidence: [{ label: "URL", value: u.normalized.slice(0, 160) }] }));
  }
  try {
    for (const [key, value] of new URL(u.normalized).searchParams) {
      if (!REDIRECT_PARAMS.has(key.toLowerCase())) continue;
      const nested = /^https?:\/\//i.test(value) || /^[a-z0-9-]+(\.[a-z0-9-]+)+\//i.test(value) ? normalizeTarget(value) : null;
      if (nested?.ok && nested.value.registrableDomain !== u.registrableDomain) {
        findings.push(finding({ ruleId: "url.embedded_redirect", category: "redirect", severity: "medium",
          title: `${prefix}Link carries an embedded redirect to another domain`, description: `The "${key}" parameter forwards visitors to ${nested.value.hostname}.`,
          impact: "Open redirects let attackers borrow a trusted domain to reach a malicious one.", remediation: `Assess ${nested.value.hostname} directly before following the link.`,
          evidence: [{ label: "Parameter", value: key }, { label: "Embedded destination", value: nested.value.normalized.slice(0, 160) }] }));
      }
    }
  } catch {
    // normalized URLs always parse
  }
  if (URL_SHORTENERS.has(u.hostname) || (u.registrableDomain && URL_SHORTENERS.has(u.registrableDomain))) {
    findings.push(finding({ ruleId: "url.shortener", category: "redirect", severity: "low", confidence: "high",
      title: `${prefix}Shortened link hides the destination`, description: `${u.hostname} is a URL-shortening service.`,
      impact: "The final destination cannot be judged from the link text.", remediation: "Expand the link with a preview service before opening it.", evidence: [hostEvidence] }));
  }
  const platform = sharedHostingPlatform(u.hostname);
  if (platform && findings.some((item) => item.ruleId.startsWith("url.brand_"))) {
    findings.push(finding({ ruleId: "url.brand_on_shared_hosting", category: "phishing", severity: "medium",
      title: `${prefix}Brand content on a free hosting platform`, description: `The site is published on ${platform}, where anyone can create pages.`,
      impact: "Phishing kits use free platforms to borrow their reputation and TLS certificates.", remediation: "Verify through the brand's own domain.", evidence: [{ label: "Platform", value: platform }] }));
  }
  if (u.port !== null && u.port !== 443 && u.port !== 80) {
    findings.push(finding({ ruleId: "url.nonstandard_port", category: "domain", severity: "low", confidence: "low",
      title: `${prefix}Non-standard port`, description: `The link connects to port ${u.port}.`, impact: "Public sites seldom use custom ports.", remediation: "Treat as context alongside other findings.", evidence: [{ label: "Port", value: String(u.port) }] }));
  }
  const label = registrableLabel(u);
  const digits = (label.match(/\d/g) ?? []).length;
  if (label.length >= 12 && !label.includes("-") && shannonEntropy(label) > 3.7 && (digits >= 3 || /[bcdfghjklmnpqrstvwxz]{5,}/.test(label))) {
    findings.push(finding({ ruleId: "url.random_domain", category: "domain", severity: "low", confidence: "low",
      title: `${prefix}Randomly generated-looking domain`, description: `"${label}" has high character randomness.`,
      impact: "Generated domains are used for disposable phishing infrastructure.", remediation: "Treat as context alongside other findings.", evidence: [{ label: "Label", value: label }] }));
  }
  return findings;
}

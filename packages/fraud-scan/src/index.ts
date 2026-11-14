import { createHmac } from "node:crypto";
import type { Finding, IndicatorType } from "../../contracts/src/index.ts";
import { AUTHORITY_TERMS, PROSE_TLDS, findBrandMentions, isOfficialDomain, type Brand } from "./domains.ts";
import { analyzeUrlLexical, finding } from "./rules.ts";
import { truncate } from "./text.ts";
import { normalizeTarget, type UrlEvidence } from "./url.ts";

export { normalizeTarget, refang, type UrlEvidence } from "./url.ts";
export { analyzeUrlLexical } from "./rules.ts";

export const MESSAGE_LIMIT = 20_000;

/** A raw indicator exists only inside the scan. Callers convert it to a keyed tag and drop `normalized`. */
export type RawIndicator = { type: IndicatorType; display: string; normalized: string };

/**
 * Keyed indicator tag: HMAC-SHA-256(workspaceKey, type ":" normalized). Two workspaces produce unrelated tags
 * for the same phone number, so tags can be stored and matched without revealing or linking the raw value.
 */
export function indicatorTag(key: Uint8Array, keyVersion: string, type: IndicatorType, normalized: string): string {
  return `${keyVersion}:${createHmac("sha256", key).update(`${type}:${normalized}`).digest("base64url").slice(0, 32)}`;
}

const UPI_HANDLES = new Set(["okaxis", "oksbi", "okhdfcbank", "okicici", "ybl", "ibl", "axl", "paytm", "upi", "apl", "yapl", "ptyes", "ptsbi", "pthdfc", "ptaxis", "fbl", "airtel", "freecharge", "kotak", "icici", "sbi", "hdfcbank", "axisbank", "pnb", "boi", "barodampay", "idfcbank", "indus", "rbl", "yesbank", "naviaxis", "superyes", "waicici", "wasbi", "waaxis", "wahdfcbank"]);

const redactEmail = (value: string) => {
  const [local = "", domain = ""] = value.split("@");
  return `${local.slice(0, 1)}***@${domain}`;
};
const redactPhone = (value: string) => {
  const digits = value.replace(/\D/g, "");
  return `${digits.length > 10 ? `+${digits.slice(0, digits.length - 10)} ` : ""}******${digits.slice(-4)}`;
};
const redactUpi = (value: string) => {
  const [local = "", handle = ""] = value.split("@");
  return `${local.slice(0, 2)}***@${handle}`;
};
const redactMiddle = (value: string, keep = 4) => `${value.slice(0, keep + 2)}…${value.slice(-keep)}`;

export type Extraction = { indicators: RawIndicator[]; links: UrlEvidence[]; redactedText: string };

/** Extract inert indicators. Links are recorded, never fetched. Personal identifiers are redacted for display. */
export function extractIndicators(text: string): Extraction {
  const indicators: RawIndicator[] = [];
  const links: UrlEvidence[] = [];
  const seen = new Set<string>();
  let redacted = text;
  const add = (type: IndicatorType, display: string, normalized: string) => {
    const key = `${type}:${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    indicators.push({ type, display, normalized });
  };
  const mask = (raw: string, shown: string) => {
    redacted = redacted.split(raw).join(shown);
  };

  for (const match of text.matchAll(/\b[a-z0-9._%+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi)) {
    add("email", redactEmail(match[0]), match[0].toLowerCase());
    mask(match[0], redactEmail(match[0]));
  }
  for (const match of text.matchAll(/\b([a-z0-9._-]{2,64})@([a-z]{2,32})\b(?!\.[a-z0-9])/gi)) {
    if (!UPI_HANDLES.has((match[2] ?? "").toLowerCase())) continue;
    add("upi", redactUpi(match[0]), match[0].toLowerCase());
    mask(match[0], redactUpi(match[0]));
  }

  const candidates = new Set<string>();
  for (const match of text.matchAll(/\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>"'`)\]]+/gi)) candidates.add(match[0]);
  for (const match of text.matchAll(/(?<![@\w.-])(?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}[a-z0-9\u00a1-\uffff])?(?:\.|\[\.\]))+[a-z]{2,24}(?:\/[^\s<>"'`)\]]*)?/gi)) {
    const candidate = match[0];
    if ([...candidates].some((existing) => existing.includes(candidate))) continue;
    const host = candidate.split("/")[0] ?? "";
    const tld = host.split(/\.|\[\.\]/).pop()?.toLowerCase() ?? "";
    if (!PROSE_TLDS.has(tld) || /^(e\.g|i\.e|etc|mr|mrs|dr|no)\./i.test(candidate)) continue;
    candidates.add(candidate);
  }
  for (const candidate of candidates) {
    const cleaned = candidate.replace(/[.,;:!?]+$/, "");
    const normalized = normalizeTarget(cleaned);
    if (!normalized.ok) continue;
    links.push(normalized.value);
    add("url", truncate(cleaned, 120), normalized.value.normalized);
    if (normalized.value.registrableDomain) add("domain", normalized.value.registrableDomain, normalized.value.registrableDomain);
  }

  const withoutUrls = [...candidates].reduce((value, url) => value.split(url).join(" "), text);
  for (const match of withoutUrls.matchAll(/\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g)) {
    const compact = match[0].replace(/\s/g, "");
    if (compact.length < 15 || compact.length > 34 || !ibanChecksumOk(compact)) continue;
    add("iban", redactMiddle(compact), compact);
    mask(match[0], redactMiddle(compact));
  }
  for (const match of withoutUrls.matchAll(/(?<![\w.])(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{2,5}\)?[\s-]?)?\d{3,5}[\s-]?\d{4,6}(?![\w])/g)) {
    const digits = match[0].replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 13) continue;
    add("phone", redactPhone(match[0]), digits.slice(-10));
    mask(match[0], redactPhone(match[0]));
  }
  for (const match of text.matchAll(/\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|T[1-9A-HJ-NP-Za-km-z]{33})\b/g)) {
    if (!/\d/.test(match[0]) || !/[a-z]/i.test(match[0])) continue;
    add("crypto_wallet", redactMiddle(match[0]), match[0]);
    mask(match[0], redactMiddle(match[0]));
  }
  for (const match of text.matchAll(/\b[A-Z]{4}0[A-Z0-9]{6}\b/g)) add("ifsc", match[0], match[0]);
  for (const match of withoutUrls.matchAll(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g)) add("ipv4", match[0], match[0]);
  for (const match of text.matchAll(/(?:₹|rs\.?|inr|usd|\$|€|£)\s?\d[\d,]*(?:\.\d{1,2})?/gi)) add("amount", match[0].trim(), match[0].replace(/\s/g, "").toLowerCase());

  redacted = redacted.replace(/\b\d{12,19}\b/g, (value) => `****${value.slice(-4)}`);
  return { indicators, links, redactedText: redacted };
}

function ibanChecksumOk(iban: string): boolean {
  const rearranged = `${iban.slice(4)}${iban.slice(0, 4)}`.toUpperCase();
  let remainder = 0;
  for (const char of rearranged) {
    const value = /\d/.test(char) ? char : String(char.charCodeAt(0) - 55);
    for (const digit of value) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

/** Text that tries to instruct an automated analyser. Treated as data and flagged. */
const AI_INSTRUCTION = /\b(ignore|disregard|forget) (all |any |the )?(previous|prior|above|earlier) (instructions|prompts|rules)|\b(you are now|new instructions:|system prompt)|\b(classify|mark|label|report|rate) (this|the) (site|page|message|email|url|link) as (safe|legitimate|benign|low risk)\b/gi;
const REQUEST_VERBS = /(share|send|provide|enter|confirm|reply|tell|update|submit|give|forward|verify|type|fill|read out)/i;
const NEGATION = /(never|do not|don't|dont|not|no one|nobody|will never|won't|wont)\b[^.!?\n]{0,40}$/i;

type Cue = { cue: string; label: string; severity: "low" | "medium" | "high"; patterns: RegExp[]; requiresRequest?: boolean };

const CUES: Cue[] = [
  { cue: "urgency", label: "Urgency or deadline pressure", severity: "low", patterns: [/\b(urgent(ly)?|immediately|act now|right away|asap|today only|last chance|final (notice|warning|reminder)|within \d+\s*(hours?|hrs?|minutes?|mins?)|expires? (today|tonight|soon)|limited time|deadline)\b/gi] },
  { cue: "threat_of_loss", label: "Threat of account suspension or penalty", severity: "medium", patterns: [/\b(account|card|kyc|sim|service|pan|aadhaa?r|wallet|connection|electricity)\b[^.!?\n]{0,40}\b(suspend(ed)?|block(ed)?|deactivat(ed|ion)|terminat(ed|ion)|frozen|freeze|locked|disabled|closed|disconnect(ed)?)\b/gi, /\b(legal action|arrest warrant|fir (has been )?(registered|filed)|penalty|fine of)\b/gi] },
  { cue: "credential_request", label: "Request for passwords, OTPs, PINs or recovery phrases", severity: "high", requiresRequest: true, patterns: [/\b(otp|one[- ]time (password|code)|pin(?![\s-]?code)|cvv|password|passcode|login (details|credentials)|net ?banking (id|credentials)|verification code|seed phrase|recovery phrase|secret phrase|private key|mpin|upi pin)\b/gi] },
  { cue: "payment_request", label: "Request to send money", severity: "low", patterns: [/\b(pay|transfer|send|deposit|remit|wire)\b[^.!?\n]{0,40}(₹|rs\.?|inr|usd|\$|€|£|fee|amount|charges?|money|payment)/gi] },
  { cue: "fee_request", label: "Upfront fee or deposit demanded", severity: "medium", patterns: [/\b(registration fee|processing fee|security deposit|refundable (deposit|fee)|clearance fee|customs (duty|charge)|delivery charge|activation fee|verification fee|release fee|unlock fee)\b/gi] },
  { cue: "gift_card_payment", label: "Payment requested in gift cards or crypto", severity: "high", patterns: [/\b(gift ?cards?|google play (card|code)s?|itunes (card|code)s?|steam (card|code)s?|amazon (pay )?(gift )?vouchers?)\b/gi, /\b(pay|send|transfer)\b[^.!?\n]{0,30}\b(usdt|bitcoin|btc|eth|crypto)\b/gi] },
  { cue: "prize_lure", label: "Prize, lottery or reward lure", severity: "medium", patterns: [/\b(you('ve| have)? won|winner|lottery|lucky draw|jackpot|claim your (prize|reward|gift)|cash ?prize|selected for a (reward|prize))\b/gi] },
  { cue: "job_lure", label: "Unsolicited job or easy-income offer", severity: "low", patterns: [/\b(work from home|part[- ]time (job|work)|earn (₹|rs\.?|\$)?\s?[\d,]+\s*(\/|per)?\s*(day|daily|hour|week)|no experience (required|needed)|immediate joining|task[- ]based (job|earning))\b/gi] },
  { cue: "investment_lure", label: "Guaranteed-return investment pitch", severity: "high", patterns: [/\b(guaranteed (returns?|profits?)|double your (money|investment)|\d+\s?% (daily|weekly|monthly) (returns?|profits?)|risk[- ]free (returns?|investment)|vip trading group)\b/gi] },
  { cue: "remote_access", label: "Request to install remote-access software", severity: "high", patterns: [/\b(anydesk|teamviewer|quick ?support|rustdesk|ultraviewer|airdroid|remote (access|desktop|support) app)\b/gi] },
  { cue: "kyc_update", label: "KYC or account-verification demand", severity: "medium", patterns: [/\b(re-?kyc|kyc|know your customer|pan card|aadhaa?r)\b[^.!?\n]{0,60}\b(update|verify|verification|complete|pending|expired?|link)\b/gi] },
  { cue: "secrecy", label: "Instruction to keep the request secret", severity: "low", patterns: [/\b(keep (this|it) (confidential|secret)|do not (tell|inform) (anyone|your family|the bank)|don'?t tell anyone)\b/gi] },
  { cue: "ai_manipulation", label: "Hidden instructions aimed at automated scanners", severity: "medium", patterns: [AI_INSTRUCTION] },
  { cue: "authority", label: "Invokes police, government or regulator authority", severity: "low", patterns: [new RegExp(`\\b(${AUTHORITY_TERMS.map((term) => term.replace(/\s+/g, "\\s+")).join("|")})\\b`, "gi")] },
];

const PROTECTIVE = [/\b(never|do not|don't) share (your |this )?(otp|pin|password|cvv|code)/gi, /\bwe (will )?never ask (you )?for\b/gi, /\bif (this|it) wasn'?t you\b/gi, /\bignore this (message|email) if\b/gi];

export type CueMatch = { cue: string; label: string; severity: "low" | "medium" | "high"; matches: string[] };

export function detectCues(text: string): { cues: CueMatch[]; protective: string[] } {
  const cues: CueMatch[] = [];
  for (const definition of CUES) {
    const matches: string[] = [];
    for (const pattern of definition.patterns) {
      pattern.lastIndex = 0;
      for (const match of text.matchAll(pattern)) {
        const index = match.index ?? 0;
        if (definition.requiresRequest) {
          // Judge the request within its own sentence: "Your OTP is 1234. Never share it" is a notice.
          const start = Math.max(...[".", "!", "?", "\n"].map((mark) => text.lastIndexOf(mark, index - 1))) + 1;
          const ends = [".", "!", "?", "\n"].map((mark) => text.indexOf(mark, index + match[0].length)).filter((position) => position >= 0);
          const sentence = text.slice(start, ends.length ? Math.min(...ends) : text.length);
          if (NEGATION.test(text.slice(start, index)) || !REQUEST_VERBS.test(sentence)) continue;
        }
        matches.push(truncate(match[0].trim(), 80));
      }
    }
    if (matches.length) cues.push({ cue: definition.cue, label: definition.label, severity: definition.severity, matches: [...new Set(matches)].slice(0, 5) });
  }
  const protective = PROTECTIVE.flatMap((pattern) => [...text.matchAll(pattern)].map((match) => match[0]));
  return { cues, protective: [...new Set(protective)].slice(0, 5) };
}

const IMPACT: Record<string, string> = {
  urgency: "Urgency alone is common in genuine notices; it matters combined with sensitive requests.",
  credential_request: "No legitimate bank, employer or service asks for OTPs, PINs, passwords or recovery phrases by message.",
  payment_request: "Payment requests matter when they name an unfamiliar destination such as a personal UPI ID, IBAN or wallet.",
  fee_request: "Upfront fees to receive a job, prize, parcel or refund define advance-fee fraud.",
  gift_card_payment: "Gift cards and crypto transfers are irreversible, which is why scammers demand them.",
  remote_access: "Remote-access apps give the caller control of the device and its banking apps.",
  investment_lure: "Guaranteed high returns are the hallmark of investment fraud.",
  threat_of_loss: "Threats of suspension or penalties rush the reader past verification.",
  prize_lure: "Unexpected prizes are used to collect fees or personal details.",
  kyc_update: "Banks do not complete KYC through links in messages.",
  secrecy: "Isolating the target from family or the bank is a manipulation tactic.",
  ai_manipulation: "Genuine messages have no reason to address automated scanners. The text is treated as data and cannot change the verdict.",
  job_lure: "Unsolicited income offers are a common opener for task and recruitment scams.",
};
const ADVICE: Record<string, string> = {
  credential_request: "Never share OTPs, PINs, passwords or recovery phrases with anyone.",
  remote_access: "Do not install apps at a stranger's request. Remove any already installed and call your bank.",
  payment_request: "Do not pay. Verify the request through an independent channel.",
  fee_request: "Do not pay. Verify the request through an independent channel.",
  gift_card_payment: "Do not pay. Verify the request through an independent channel.",
  urgency: "Take time to verify before acting.",
};

export type MessageAnalysis = {
  findings: Finding[];
  indicators: RawIndicator[];
  redactedExcerpt: string;
  senderDomain: string | null;
  claimedBrands: string[];
  protectiveLanguage: string[];
  cues: string[];
};

function isClaimedSender(brand: Brand, text: string): boolean {
  const lower = text.toLowerCase();
  return brand.tokens.some((token) => new RegExp(`(team|from|dear customer|regards|support)[^.\\n]{0,40}${token}|${token}[^.\\n]{0,20}(team|support|bank|customer care)`).test(lower));
}

/**
 * Analyse a pasted message. Urgent language alone never exceeds a low-severity cue; elevated findings require
 * a sensitive request, an identity mismatch or a risky link.
 */
export function analyzeMessage(input: { text: string; sender?: string | undefined; subject?: string | undefined }): MessageAnalysis {
  const fullText = [input.subject, input.text].filter(Boolean).join("\n").slice(0, MESSAGE_LIMIT);
  const extraction = extractIndicators(fullText);
  const { cues, protective } = detectCues(fullText);
  const senderHost = input.sender?.includes("@") ? input.sender.split("@").pop()?.trim().toLowerCase() ?? "" : "";
  const senderNormalized = senderHost ? normalizeTarget(senderHost) : null;
  const senderDomain = senderNormalized?.ok ? senderNormalized.value.registrableDomain : null;
  const brands = findBrandMentions(fullText);
  const findings: Finding[] = [];
  const has = (cue: string) => cues.find((item) => item.cue === cue);

  const paymentDestination = extraction.indicators.some((indicator) => ["upi", "crypto_wallet", "ifsc", "iban"].includes(indicator.type));
  for (const cue of cues) if (cue.cue === "payment_request" && paymentDestination) cue.severity = "medium";

  for (const cue of cues) {
    if (cue.cue === "authority") continue;
    findings.push(finding({ ruleId: `message.${cue.cue}`, category: "message", severity: cue.severity, confidence: cue.severity === "low" ? "low" : "medium",
      title: cue.label, description: `The message contains ${cue.matches.map((match) => `"${match}"`).join(", ")}.`,
      impact: IMPACT[cue.cue] ?? "A social-engineering cue that warrants caution.",
      remediation: ADVICE[cue.cue] ?? "Verify the claim through an official channel you find yourself.",
      evidence: cue.matches.map((match) => ({ label: "Matched text", value: match })) }));
  }

  const pressure = has("urgency") ?? has("threat_of_loss");
  const directedPayment = paymentDestination ? has("payment_request") : undefined;
  const sensitive = has("credential_request") ?? has("fee_request") ?? has("gift_card_payment") ?? directedPayment;
  if (pressure && sensitive) {
    findings.push(finding({ ruleId: "message.pressure_plus_sensitive_request", category: "message", severity: "high", confidence: "medium",
      title: "Pressure tactics combined with a sensitive request",
      description: "The message pairs urgency or threats with a request for credentials or money.",
      impact: "Creating panic so the reader acts before verifying is the defining pattern of social-engineering fraud.",
      remediation: "Pause. Contact the organisation through a number or app you already trust.",
      evidence: [{ label: "Pressure", value: pressure.matches[0] ?? "" }, { label: "Request", value: sensitive.matches[0] ?? "" }] }));
  }
  const paidJob = has("fee_request") ?? directedPayment ?? has("gift_card_payment");
  if (has("job_lure") && paidJob) {
    findings.push(finding({ ruleId: "message.job_fee", category: "message", severity: "high", confidence: "high",
      title: "Job offer that requires the applicant to pay", description: "The message offers work or income and asks for a fee, deposit or transfer.",
      impact: "Legitimate employers do not charge candidates to be hired.", remediation: "Do not pay. Verify the employer through its official careers page.",
      evidence: [{ label: "Offer", value: has("job_lure")?.matches[0] ?? "" }, { label: "Payment", value: paidJob.matches[0] ?? "" }] }));
  }
  if (has("authority") && (has("threat_of_loss") || sensitive)) {
    findings.push(finding({ ruleId: "message.authority_impersonation", category: "message", severity: "high", confidence: "medium",
      title: "Authority figure used to demand action", description: `The message invokes ${has("authority")?.matches[0]} together with threats or a payment or credential request.`,
      impact: "Police, courts and regulators do not collect fines or credentials through messages.", remediation: "Do not respond. Report it to the official agency or national cybercrime helpline.",
      evidence: [{ label: "Authority", value: has("authority")?.matches[0] ?? "" }] }));
  }

  extraction.links.slice(0, 10).forEach((link, index) => findings.push(...analyzeUrlLexical(link, `Link ${index + 1} (${link.hostname})`)));

  for (const brand of brands.slice(0, 3)) {
    const offDomain = extraction.links.filter((link) => link.registrableDomain && !isOfficialDomain(brand, link.registrableDomain, link.hostname));
    const official = extraction.links.filter((link) => link.registrableDomain && isOfficialDomain(brand, link.registrableDomain, link.hostname));
    if (offDomain.length && !official.length) {
      findings.push(finding({ ruleId: "message.brand_link_mismatch", category: "phishing", severity: "high", confidence: "high",
        title: `Claims to be from ${brand.name} but links elsewhere`,
        description: `The message mentions ${brand.name}, yet its links go to ${offDomain.map((link) => link.registrableDomain).slice(0, 3).join(", ")}, which ${brand.name} does not operate.`,
        impact: "Mismatched links move recipients to credential-harvesting pages.", remediation: `Do not use the link. Open ${brand.domains[0]} or the official app yourself.`,
        evidence: [{ label: "Claimed", value: brand.name }, ...offDomain.slice(0, 3).map((link) => ({ label: "Link domain", value: link.registrableDomain ?? "" }))] }));
    }
    if (senderDomain && !isOfficialDomain(brand, senderDomain) && isClaimedSender(brand, fullText)) {
      findings.push(finding({ ruleId: "message.sender_mismatch", category: "phishing", severity: "medium",
        title: `Sender domain does not belong to ${brand.name}`, description: `The message presents itself as ${brand.name} but was sent from ${senderDomain}.`,
        impact: "Display names are easy to forge; the sending domain is harder to fake.", remediation: "Treat the message as unverified.",
        evidence: [{ label: "Sender domain", value: senderDomain }] }));
    }
  }

  return {
    findings,
    indicators: extraction.indicators,
    redactedExcerpt: truncate(extraction.redactedText, 600),
    senderDomain,
    claimedBrands: brands.map((brand) => brand.name),
    protectiveLanguage: protective,
    cues: cues.map((cue) => cue.cue),
  };
}

/** Synthetic samples for the console and the policy demo. All identifiers are fictitious. */
export const SAMPLE_MESSAGES = {
  scam: {
    sender: "alerts@hdfc-secure-kyc.top",
    subject: "URGENT: KYC pending, account will be blocked",
    text: "Dear customer, your HDFC Bank account will be blocked within 24 hours because your KYC is pending. Update KYC now at https://hdfc-secure-kyc.top/verify and share the OTP you receive with our officer. To avoid a penalty, pay the Rs 499 verification fee to refundcell@ybl. Do not tell anyone at the branch.",
  },
  benign: {
    sender: "no-reply@hdfcbank.com",
    subject: "Your one-time password",
    text: "Your OTP for the transaction of Rs 1,250 at a merchant is 482913. It is valid for 5 minutes. Never share your OTP with anyone. HDFC Bank will never ask for it. If this wasn't you, call the number on the back of your card.",
  },
} as const;

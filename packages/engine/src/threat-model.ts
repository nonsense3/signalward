import type { DetectorCoverage, Finding, Report, ThreatAssessment, ThreatScenario } from "../../contracts/src/index.ts";

type Definition = Omit<ThreatScenario, "status" | "signal" | "confidence" | "findingIds"> & {
  matches: (finding: Finding) => boolean;
  detector: string | null;
  alwaysUnassessed?: boolean;
};

const hasRule = (prefix: string) => (finding: Finding) => finding.ruleId.startsWith(prefix);
const hasCategory = (...categories: Finding["category"][]) => (finding: Finding) => categories.includes(finding.category);

const REPOSITORY: Definition[] = [
  {
    id: "TM-REPO-SECRET", actor: "External repository reader or attacker with repository access",
    boundary: "Source control boundary: developer or CI writes source and configuration into a repository visible to collaborators and automation.",
    targetAsset: "Credential and the cloud, source control, or production resources it authorizes.",
    attackPath: "Find a committed credential in source or history, validate it, then use its permissions to read data or alter services.",
    preconditions: "The detected value is live, usable, and visible to the attacker; the credential has permissions beyond a disposable test scope.",
    controls: ["Secret-pattern scanning over included text files", "High-severity secret findings block the repository verdict"],
    mitigations: ["Revoke and rotate the credential immediately.", "Audit its access logs and remove it from repository history and build artifacts.", "Move future credentials to a managed secret store with least privilege."],
    residualRisk: "Pattern matching can miss formats and encoded values. Scanning the current snapshot cannot remove copies from history, forks, logs, or caches.",
    impact: "critical", matches: hasCategory("secret"), detector: "secrets",
  },
  {
    id: "TM-REPO-SUPPLY-CHAIN", actor: "Compromised maintainer, malicious package publisher, or attacker controlling a release",
    boundary: "Dependency boundary: package metadata and lockfiles identify code that will execute in developer, build, or production environments.",
    targetAsset: "Build integrity, application data, CI credentials, and runtime service identity.",
    attackPath: "Introduce or exploit an affected dependency; its code executes during installation, build, or application runtime with the process privileges available to it.",
    preconditions: "The affected version is installed and the vulnerable code path or malicious install behavior is reachable.",
    controls: ["Supported lockfiles and exact manifest versions are checked against a pinned advisory subset"],
    mitigations: ["Upgrade to the advisory's fixed version and regenerate the lockfile.", "Review the package release and transitive dependency tree.", "Use least-privilege CI tokens and isolate builds from production secrets."],
    residualRisk: "The local advisory set is not exhaustive or live. Version matching does not prove exploitability, reachability, or package provenance.",
    impact: "high", matches: hasCategory("dependency"), detector: "dependencies",
  },
  {
    id: "TM-REPO-CI-TRUST", actor: "Untrusted pull-request author or issue submitter",
    boundary: "CI trust boundary: attacker-controlled event fields or checkout content may cross into a privileged workflow runner.",
    targetAsset: "CI runner, repository write permissions, release pipeline, and secrets injected into jobs.",
    attackPath: "Place shell metacharacters in an event field or supply a commit that a privileged workflow checks out; obtain code execution in the runner and use its token or secrets.",
    preconditions: "The flagged expression is evaluated in an executable step or untrusted code reaches a privileged trigger with meaningful permissions.",
    controls: ["Static checks for untrusted event interpolation, privileged checkout, broad token permissions, mutable actions, and remote scripts"],
    mitigations: ["Pass untrusted values through environment variables and quote them in scripts.", "Use read-only token permissions by default and separate privileged release jobs.", "Pin third-party actions to full commit SHAs."],
    residualRisk: "The linter is not a YAML execution engine; it may miss indirection, reusable workflows, generated configuration, or runtime permission changes.",
    impact: "high", matches: hasRule("ci."), detector: "ci_configuration",
  },
  {
    id: "TM-REPO-CODE-LOGIC", actor: "External user exploiting an application logic or authorization flaw",
    boundary: "Application boundary: source code becomes a deployed service that accepts requests and accesses data or privileged services.",
    targetAsset: "Application data, tenant boundaries, and service credentials.",
    attackPath: "Send crafted requests to an unmodeled logic flaw such as broken authorization, injection, or unsafe deserialization and reach protected data or execution.",
    preconditions: "The application contains a flaw not covered by the repository detectors and deploys it on a reachable path.",
    controls: ["Repository scan covers selected secret, dependency, and CI patterns; it does not execute the application"],
    mitigations: ["Run code review and application-specific security tests for authentication, authorization, and input handling.", "Map exposed endpoints and sensitive data flows before release."],
    residualRisk: "Application logic and runtime attack paths are outside the current scanner's detection scope.",
    impact: "high", matches: () => false, detector: null, alwaysUnassessed: true,
  },
];

const MESSAGE: Definition[] = [
  {
    id: "TM-MSG-CREDENTIAL-HARVEST", actor: "Social engineer impersonating a service, employer, or trusted contact",
    boundary: "Human trust boundary: an inbound message asks a recipient to take an action or follow a link outside the application.",
    targetAsset: "Recipient passwords, one-time codes, recovery factors, identity data, or account access.",
    attackPath: "Use urgency, authority, or a sensitive request to persuade the recipient to disclose a credential or authentication code.",
    preconditions: "The recipient believes the message and responds before independently verifying the request.",
    controls: ["Deterministic social-engineering and sensitive-request rules", "Protective wording and negation cues are considered"],
    mitigations: ["Never share passwords, PINs, one-time codes, or recovery phrases in response to a message.", "Verify the request using a known phone number or official app."],
    residualRisk: "Language rules can miss novel phrasing and can misread context; they cannot prevent a recipient from replying.",
    impact: "high", matches: (f) => f.ruleId.startsWith("message.") && /credential|otp|password|sensitive_request|pin|code/i.test(`${f.ruleId} ${f.title}`), detector: "social_engineering_cues",
  },
  {
    id: "TM-MSG-IMPERSONATION", actor: "Brand impersonator or sender using a lookalike domain",
    boundary: "Sender identity boundary: display names and claimed organizations are untrusted until checked against an authenticated identity source.",
    targetAsset: "Recipient trust and any account, payment, or personal data the claimed organization can request.",
    attackPath: "Claim a trusted brand or authority while using a sender domain or embedded destination that does not match the organization's known domain.",
    preconditions: "The message names a brand or includes sender metadata; recipient relies on the claim instead of an independently known contact route.",
    controls: ["Brand mention and sender-domain consistency rules when sender metadata is supplied", "Embedded links receive lexical analysis without being opened"],
    mitigations: ["Check the sender's full domain and navigate through a saved bookmark or official app.", "Do not use contact details or links supplied by the suspicious message."],
    residualRisk: "A sender address is not authenticated by this check. SPF, DKIM, DMARC, mailbox compromise, and organizational ownership are not verified.",
    impact: "high", matches: (f) => f.ruleId === "message.authority_impersonation" || f.ruleId === "message.sender_mismatch" || f.ruleId === "message.brand_link_mismatch" || f.ruleId.startsWith("url.brand_"), detector: "identity_consistency",
  },
  {
    id: "TM-MSG-PAYMENT-FRAUD", actor: "Fraud operator posing as a recruiter, vendor, government office, or known contact",
    boundary: "Payment decision boundary: a message can influence the recipient, but the scanner has no authority over the recipient's bank or payment system.",
    targetAsset: "Recipient funds, payment credentials, and financial identifiers.",
    attackPath: "Create urgency or a credible pretext, then direct payment to a mule account, gift card, crypto wallet, or fabricated fee.",
    preconditions: "The recipient pays before verifying the beneficiary and the request through an independent channel.",
    controls: ["Payment, upfront-fee, gift-card, and crypto-request cues", "Financial indicators are redacted for display and keyed for workspace-local correlation"],
    mitigations: ["Pause payment and independently verify the beneficiary and purpose.", "Contact the institution using a number from its official site or card."],
    residualRisk: "The application cannot hold or reverse funds; indirect payment language and mule-account changes can evade text rules.",
    impact: "high", matches: (f) => f.ruleId.startsWith("message.") && /payment|fee|gift|crypto|transfer|refund|invoice|bank/i.test(`${f.ruleId} ${f.title}`), detector: "social_engineering_cues",
  },
  {
    id: "TM-MSG-SENDER-AUTH", actor: "Attacker spoofing or taking over a sender mailbox",
    boundary: "Email authentication boundary: sender text supplied to the scan is a claim and does not establish control of the sending domain.",
    targetAsset: "Trust in the sender identity and subsequent recipient actions.",
    attackPath: "Spoof a sender address or compromise a legitimate mailbox, then send a request that appears to come from a known organization or person.",
    preconditions: "The message is email and its authentication headers or provider account state are available for verification.",
    controls: ["Optional claimed sender domain is compared with mentioned brands"],
    mitigations: ["Verify SPF, DKIM, and DMARC results from trusted mail headers.", "Confirm unusual requests through a second, previously established channel."],
    residualRisk: "The scanner receives only a sender string; it does not inspect mail headers, DMARC alignment, or mailbox compromise signals.",
    impact: "high", matches: (f) => f.ruleId === "message.sender_mismatch" || f.ruleId === "message.brand_link_mismatch", detector: "identity_consistency",
  },
  {
    id: "TM-MSG-INDICATOR-REUSE", actor: "Repeat fraud operator reusing infrastructure against the same workspace",
    boundary: "Workspace intelligence boundary: only indicators previously observed by this account can be correlated.",
    targetAsset: "Workspace recipients and their account or financial data.",
    attackPath: "Reuse a previously blocked URL, domain, wallet, or contact point in another message to target users in the same workspace.",
    preconditions: "The relevant indicator was captured earlier and remains stable enough to match after normalization.",
    controls: ["Per-account HMAC tags", "Workspace-local sightings and blocklist lookup"],
    mitigations: ["Review the linked prior report and add confirmed indicators to the workspace blocklist.", "Notify affected recipients through a trusted channel."],
    residualRisk: "There is no cross-workspace reputation feed; changed infrastructure and first-seen indicators will not match history.",
    impact: "medium", matches: hasCategory("intelligence"), detector: "workspace_correlation",
  },
];

const URL: Definition[] = [
  {
    id: "TM-URL-BRAND-DECEPTION", actor: "Phisher operating a lookalike domain or deceptive hostname",
    boundary: "Browser navigation boundary: the submitted string is inspected locally; destination ownership and served content are not contacted.",
    targetAsset: "User credentials, browser session, and trust in the impersonated organization.",
    attackPath: "Use a homograph, brand-like hostname, URL user information, or misleading path to make an attacker-controlled destination appear legitimate.",
    preconditions: "A recipient follows the URL and trusts its visible text or apparent brand.",
    controls: ["URL normalization, IDN/homograph checks, brand-domain comparison, and lexical heuristics", "No request is sent to the submitted URL"],
    mitigations: ["Open the organization through a bookmark or official app instead of this link.", "Check the registrable domain, not just the path or subdomain."],
    residualRisk: "Lexical similarity does not establish domain ownership or page behavior; clean-looking URLs can still serve malicious content.",
    impact: "high", matches: (f) => f.ruleId.startsWith("url.brand_") || ["url.punycode", "url.userinfo_deception", "url.deep_subdomains", "url.credential_keywords"].includes(f.ruleId), detector: "link_lexical",
  },
  {
    id: "TM-URL-REDIRECT", actor: "Phisher abusing an open redirect or URL-shortening service",
    boundary: "Redirect boundary: URL parameters and shorteners can point beyond the visible or trusted host.",
    targetAsset: "Recipient browser session and credentials entered at the final destination.",
    attackPath: "Place an attacker-controlled destination in a redirect parameter or hide it behind a shortening service, then send a trusted-looking link.",
    preconditions: "The redirector accepts the destination and the recipient follows the link.",
    controls: ["Known redirect parameters are checked for cross-domain destinations", "Known URL shorteners are flagged"],
    mitigations: ["Inspect the final destination with an approved safe-analysis tool before distribution.", "Do not authenticate after following an unexpected redirect."],
    residualRisk: "Redirect chains are not followed, and shortener destinations can change. The final destination is not established by this report.",
    impact: "high", matches: hasCategory("redirect"), detector: "link_lexical",
  },
  {
    id: "TM-URL-LIVE-DESTINATION", actor: "Operator hosting malware, credential theft, or exploit content",
    boundary: "Network inspection boundary: the scanner intentionally performs no DNS, TLS, HTTP, or page request to the target.",
    targetAsset: "Recipient device, browser, credentials, and network reachable from that device.",
    attackPath: "Serve malicious content from a domain whose lexical appearance does not trigger a rule, or change content after this scan.",
    preconditions: "The recipient opens the URL and the destination serves malicious or compromised content at that time.",
    controls: ["No-fetch design avoids SSRF and prevents the scanner from executing or contacting untrusted destinations"],
    mitigations: ["Treat a low-risk lexical result as unverified; use an isolated reputation or sandbox service if live inspection is required.", "Keep endpoint protection and browser isolation enabled."],
    residualRisk: "DNS reputation, certificate context, redirect behavior, page content, downloads, and current site compromise are not inspected.",
    impact: "high", matches: () => false, detector: "network_inspection", alwaysUnassessed: true,
  },
  {
    id: "TM-URL-INDICATOR-REUSE", actor: "Repeat fraud operator reusing a previously observed destination",
    boundary: "Workspace intelligence boundary: URL and domain tags are correlated only within one account.",
    targetAsset: "Workspace users and the accounts they access through links.",
    attackPath: "Reuse a previously blocked domain or URL in another campaign message to reach a workspace user.",
    preconditions: "The destination was previously scanned by this workspace and still normalizes to the same indicator.",
    controls: ["Normalized URL and registrable-domain HMAC tags", "Workspace-local blocklist and sighting counts"],
    mitigations: ["Review prior sightings and block confirmed indicators.", "Share confirmed malicious indicators with the appropriate incident response team."],
    residualRisk: "No global reputation or cross-account sharing exists; new domains and rapidly rotated paths may be unseen.",
    impact: "medium", matches: hasCategory("intelligence"), detector: "workspace_correlation",
  },
];

const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;
const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 } as const;

function scenarioStatus(definition: Definition, coverage: readonly DetectorCoverage[]): ThreatScenario["status"] {
  if (definition.alwaysUnassessed) return "not_assessed";
  const detector = definition.detector ? coverage.find((item) => item.detector === definition.detector) : null;
  if (definition.detector && (!detector || detector.status !== "ran")) return "not_assessed";
  return "no_signal";
}

export function buildThreatAssessment(input: {
  kind: Report["kind"];
  verdict: Report["verdict"];
  findings: readonly Finding[];
  coverage: readonly DetectorCoverage[];
}): ThreatAssessment {
  const definitions = input.kind === "repository" ? REPOSITORY : input.kind === "message" ? MESSAGE : URL;
  const scenarios: ThreatScenario[] = definitions.map((definition) => {
    const related = input.findings.filter(definition.matches).sort((a, b) => RANK[b.severity] - RANK[a.severity]);
    const status = related.length ? "observed" : scenarioStatus(definition, input.coverage);
    const signal = related.length ? RANK[related[0]!.severity] >= 3 ? "high" : RANK[related[0]!.severity] === 2 ? "medium" : "low" : "none";
    const confidence = related.length
      ? related.reduce((best, item) => CONFIDENCE_RANK[item.confidence] > CONFIDENCE_RANK[best] ? item.confidence : best, related[0]!.confidence)
      : "low";
    const coverageNote = definition.detector ? input.coverage.find((item) => item.detector === definition.detector) : null;
    return {
      id: definition.id,
      actor: definition.actor,
      boundary: definition.boundary,
      targetAsset: definition.targetAsset,
      attackPath: definition.attackPath,
      preconditions: definition.preconditions,
      controls: [...definition.controls, ...(coverageNote && coverageNote.status !== "ran" ? [`Detector limitation: ${coverageNote.detail}`] : [])],
      mitigations: definition.mitigations,
      residualRisk: definition.residualRisk,
      status,
      signal,
      impact: definition.impact,
      confidence,
      findingIds: related.map((finding) => finding.id),
    };
  });

  const limitations = input.coverage.filter((item) => item.status !== "ran").map((item) => `${item.detector.replace(/_/g, " ")}: ${item.detail}`);
  limitations.push("A no-signal status means the listed detector ran without a matching finding; it is not proof that the threat is absent.");
  limitations.push("Signal strength describes observed evidence, not probability or likelihood.");
  return {
    method: "deterministic-scenarios-v2",
    scope: `${input.kind} scan threat model for the ${input.kind === "repository" ? "repository and build pipeline" : input.kind === "message" ? "message recipient and sender claims" : "submitted URL and recipient navigation"}; policy verdict: ${input.verdict}. Scenarios are explicit, fixed threat hypotheses with evidence status.`,
    coverageLimitations: [...new Set(limitations)],
    scenarios,
  };
}

# SignalWard Threat Model

**Status:** Initial design baseline  
**Reviewed against:** repository state on 2026-11-14  
**Scope:** the local CLI and single-process web application, with optional Supabase and Gemini integrations.

This document describes what SignalWard is designed to protect, where trust changes, the attacker capabilities considered, controls present in the code, and risks that remain. It is a repository-grounded baseline, not a claim of security certification or an independent penetration test. Update it when data flows, integrations, or enforcement behavior change.

## System and trust boundaries

```text
Untrusted repo / message / URL
          |
          v
Browser or CLI --(authenticated HTTPS in deployment)--> SignalWard API
                                                          |       |
                                                          |       +--> optional Gemini API
                                                          +----------> local files or Supabase Auth/Postgres
          ^                                                       |
          +---------------- report + signed receipt <-------------+
                                                                  |
                                                    public receipt key set
```

1. **Input boundary:** repository files, message text, sender claims, and URLs are attacker-controlled data. Scanners parse them as data; submitted URLs are not opened.
2. **Client/API boundary:** browsers and CLI callers are not trusted. Web API routes authenticate requests, constrain bodies, check origin for state changes, and apply in-memory rate limits.
3. **Tenant boundary:** each authenticated account is a separate workspace. Indicator keys are derived per user; Supabase rows are protected by RLS. Local mode relies on server-side account checks and file permissions.
4. **Persistence boundary:** local account/store/key files are trusted only to the extent that the host account and filesystem are protected. Supabase is an external processor; the app uses the caller's token and anon key, not a service-role key.
5. **AI boundary:** when configured, a redacted allowlisted report fact sheet is sent to Gemini for explanatory text. The model is untrusted and cannot set verdicts or actions; invalid output falls back to deterministic summaries.
6. **Receipt-verification boundary:** a receipt is trustworthy only when its Ed25519 signature validates against a public key obtained from a trusted channel. A self-provided key set alone does not establish publisher identity.

## Assets and security goals

| Asset | Goal |
|---|---|
| User credentials and sessions | Prevent guessing, theft, tampering, and cross-account use. |
| Repository contents, messages, URLs, sender identities | Keep input data from executing or causing unintended network access; limit exposure in reports and integrations. |
| Reports, findings, and receipts | Preserve integrity, make tampering detectable, and restrict access to the owning account. |
| Raw indicators (emails, phone numbers, wallets, URLs) | Avoid storing normalized raw values for correlation; prevent cross-account tag correlation. |
| Signing, session, and indicator master keys | Keep secret; restrict access; support controlled rotation. |
| Detection and mitigation decisions | Make verdicts deterministic and evidence-linked; do not let AI rewrite decisions. |
| Availability of scan/auth services | Bound input and request load; avoid unbounded work and resource use. |

## Attacker model

We consider unauthenticated internet users, a malicious authenticated tenant, a sender crafting deceptive content, a repository contributor crafting hostile files, and an attacker submitting crafted HTTP requests. They may try to bypass detection, exploit parsing or path handling, exhaust resources, tamper with reports, steal or replay sessions, abuse account recovery, infer another tenant's data, or manipulate model summaries. A malicious dependency/provider or compromised application host is also relevant to deployment risk.

The design does **not** assume it can protect data after the application host, the user's authenticated browser/device, a configured external provider, or a signing key has been compromised. It does not claim to detect every malicious input or to block delivery, payment, or merges in third-party systems.

## Abuse cases, controls, and residual risk

| Abuse case | Current controls in code | Residual risk / needed operational control |
|---|---|---|
| Crafted URL targets localhost, private infrastructure, or triggers SSRF | URL analysis is lexical and does not fetch submitted links; local/reserved hostnames are refused. | There is no DNS/TLS/page reputation inspection. Keep the no-fetch invariant if adding enrichment; any fetcher needs isolated egress and DNS-rebinding defenses. |
| Malicious archive/path/symlink tricks a repository scan into reading outside the chosen root | Relative paths are validated; symlinks are refused; file count and size limits apply; ignored/binary files are skipped. | Scanner rules are heuristic and coverage is bounded; incomplete scans must not be treated as proof of safety. |
| Phishing text or claimed sender identity evades or poisons fraud verdict | Deterministic cues, brand/domain comparisons, URL rules, and workspace blocklist correlation contribute evidence. | Rules and static domain/advisory data can be stale or evaded. Identity consistency is not email authentication (SPF/DKIM/DMARC) or proof of sender ownership. |
| Cross-site request changes account state | State-changing routes require same-origin checks; cookies are HttpOnly and SameSite=Lax. | Deployment must use HTTPS and a correct host/proxy configuration. Same-origin checks are not a substitute for authorization. |
| Brute-force sign-in, signup, recovery, or scans | Request/body limits and per-process fixed-window rate limits; local auth uses scrypt, random salts, and lockout fields. | Rate limits are in-memory and per process/IP/user; horizontally scaled deployments need a shared limiter and edge abuse controls. |
| One user reads another user's reports or indicators | API queries are actor-scoped; Supabase tables use RLS; indicator keys are derived per user. | Local mode depends on host filesystem protection. RLS and authorization policy must be reviewed whenever schema/routes change. |
| Raw indicators leak through persistence or AI summarization | Correlation uses per-user HMAC-SHA-256 tags; report display values are redacted; AI receives an allowlisted fact sheet without evidence values or message contents. | Findings/reports can still contain sensitive evidence such as URLs, domains, paths, or snippets. Stored reports are not encrypted by the application; database/host access and retention require protection. |
| Report or verdict is modified after issuance | Canonical JSON digest and Ed25519 signature; receipt can be checked offline; Supabase has no report update policy. | Signing-key compromise permits forged receipts. Publish/rotate keys through a trusted channel and protect backups. A valid signature proves integrity under a key, not that scanning was complete or correct. |
| Prompt injection causes AI to alter security decision | Model receives untrusted data with explicit constraints; output schema and finding IDs are validated; verdict/actions remain deterministic. | Model summaries can still be misleading while passing basic validation. Treat them as explanations, not evidence; disable Gemini where external processing is unacceptable. |
| UI or input content executes script in the application origin | Strict CSP disallows inline scripts; text rendering should remain escaped; self-hosted asset allowlist is used. | Keep checking every new rendering path and dependency. CSP is defense in depth, not proof against XSS. |
| User expects mitigation that never occurs | Policy records actions and the UI can manage a workspace blocklist. | Quarantine, payment hold, notification, and CI commit-status actions are not connected to enforcement systems. They are report recommendations/status metadata unless an operator acts. |

## Cryptographic and privacy design

- **Sessions:** AES-256-GCM authenticated encryption, random 96-bit IV per cookie, expiry checked on open; key derived with HKDF-SHA-256.
- **Local passwords:** Node scrypt with per-account random salt. Supabase mode delegates password storage and authentication to Supabase Auth.
- **Indicator correlation:** HMAC-SHA-256 over type and normalized indicator, using an HKDF-SHA-256 key scoped to user ID and key version. Raw normalized indicator values are used transiently during scanning and should not be persisted.
- **Receipts:** SHA-256 over canonical JSON and Ed25519 signatures. Public key distribution and rotation are operational trust responsibilities.
- **Transport:** Production deployment must terminate TLS; the application does not itself establish end-to-end TLS when run behind a proxy.

These mechanisms protect specific boundaries. They do not encrypt stored reports at the application layer, prevent a compromised host from using in-memory keys, or provide secure multi-party computation over private inputs.

## Mitigation and incident response expectations

1. Treat `incomplete`/`inconclusive` as not verified safe; inspect skipped detector coverage.
2. For exposed credentials, revoke and rotate them and remove them from repository history.
3. For high-risk fraud results, independently verify through a known-good channel; block indicators only after review if appropriate.
4. On suspected session/key compromise, disable access, rotate affected secrets, invalidate sessions, and publish a new trusted receipt key set with a documented transition.
5. If stored reports contain sensitive content, use account deletion/export controls carefully and apply storage backups/retention controls at the deployment layer.

## Out of scope and known gaps

- Continuous device posture checks, service mesh identity, and centralized zero-trust policy enforcement.
- Live DNS, TLS certificate, page, and reputation inspection.
- Email-authentication verification (SPF/DKIM/DMARC) and authoritative identity proofing.
- Automated quarantine, payment holds, user notifications, and CI-provider status checks.
- Distributed/shared rate limiting, formal verification, independent penetration testing, and a complete software supply-chain attestation process.

## Review checklist

Review this model when adding an input type, network enrichment, storage field/table, external processor, authentication flow, key format/rotation path, or mitigation integration. For each change, identify the asset, boundary, attacker action, control, and residual risk; update the table and verify that product copy matches actual enforcement.

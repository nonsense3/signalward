# ◈ SignalWard

**Deterministic security workspace for repository auditing, fraud analysis, and cryptographically signed evidence receipts.**

[![node >= 24](https://img.shields.io/badge/node-%3E%3D24-brightgreen)](https://nodejs.org/)
[![zero runtime dependencies](https://img.shields.io/badge/runtime%20deps-zero-success)](package.json)
[![Ed25519 + SHA-256](https://img.shields.io/badge/signatures-Ed25519-orange)](packages/receipts)

---

## What It Does

SignalWard scans **code repositories**, **suspicious messages**, and **untrusted links**, then issues a deterministic verdict with a tamper-proof **Ed25519 receipt** — no network calls to untrusted targets, no runtime npm dependencies.

| Scanner | Detects |
|---------|---------|
| **Repository** | Leaked secrets (AWS, GitHub, Stripe, private keys, …), vulnerable dependencies, insecure CI/CD workflows |
| **Message** | Social-engineering cues, brand impersonation, payment/credential phishing, prompt-injection attempts |
| **URL** | Typosquatting, homoglyphs, high-abuse TLDs, open redirects, URL shorteners — all without opening the link |

Each account gets a profile dashboard, live activity, an indicator blocklist, and an in-browser receipt verifier.

---

## Architecture

```
Inputs (repo · message · URL)
        │
   ┌────┴────┐
   CLI      Web        ← apps/cli  ·  apps/web
   └────┬────┘
        │
    Scan Engine        ← packages/engine
   ┌────┼────┐
repo  fraud   url      ← packages/repo-scan · packages/fraud-scan
   └────┼────┘
        │
 Deterministic Policy  ← packages/policy
        │
 Ed25519 Receipts      ← packages/receipts

Web layer              ← apps/web/src
  env · auth · store · ai · errors · security · api
  (Supabase Auth + Postgres RLS, or local accounts)
```

All indicator values (emails, phones, UPI handles, wallets) are redacted and converted to per-account **HMAC-SHA-256 tags** via HKDF — accounts can't correlate each other's data, and row-level security keeps every report, blocklist and profile private to its owner.

---

## Quick Start

```sh
cp .env.example .env               # then fill in the values below
node apps/cli/signalward.ts keys   # prints fresh SignalWard secrets
node apps/cli/signalward.ts doctor # validates .env and checks Supabase / Gemini
npm run dev
```

Open the URL printed in the terminal. Port 3000 is tried first and a free port is chosen if it is busy; set `PORT` to override. In development, missing secrets are generated under `.signalward/` (git-ignored); in production they are required.

- **`/`** — Signal Observatory (landing page)
- **`/auth`** — sign in, sign up, OAuth, magic link, password reset
- **`/scan`** — Scanner Console (repository · message · link · activity)
- **`/account`** — profile dashboard
- **`/verify`** — independent in-browser receipt verifier

```sh
npm test   # deterministic policy tests
```

---

## Accounts & Authentication

SignalWard runs with **Supabase Auth** when configured, or **local accounts** for offline development.

- **Email + password**, with strength checks and account lockout after repeated failures
- **Single sign-on**: Continue with **GitHub** or **Google** (Supabase OAuth)
- **Magic link**: passwordless email sign-in
- **Password reset** by email
- Sessions are stored in an **AES-256-GCM encrypted, HttpOnly cookie**; Supabase tokens are refreshed server-side
- Local account and workspace records are encrypted at rest; local sign-out and password changes revoke all active sessions for that account, and open activity streams close on revocation

OAuth and magic link require Supabase. Enable the GitHub and Google providers in your Supabase dashboard and add `<PUBLIC_URL>/auth/callback` as a redirect URL.

---

## CLI

```sh
node apps/cli/signalward.ts scan .                         # scan a repository
node apps/cli/signalward.ts watch .                        # rescan when repository files change
node apps/cli/signalward.ts scan /path/to/repo --json --out ./artifacts
node apps/cli/signalward.ts url "https://hdfc-secure-kyc.top/verify"   # zero-fetch URL check
node apps/cli/signalward.ts verify ./artifacts/<id>.receipt.json \
  --report ./artifacts/<id>.report.json --keys ./artifacts/signalward-keys.json
node apps/cli/signalward.ts keys     # generate SignalWard secrets
node apps/cli/signalward.ts keys rotate-indicators # rotate HMAC tags with retained-key overlap
node apps/cli/signalward.ts keys rotate-reports # rotate report encryption with retained-key overlap
node apps/cli/signalward.ts doctor   # validate configuration and connectivity
```

**Exit codes:** `0` pass/valid · `1` block/high-risk/invalid · `2` incomplete/error

## CI Gate

`.github/workflows/signalward-security.yml` scans every pull request and push with read-only repository permissions. A high-severity secret finding returns a non-zero exit code and fails the check. To make that check prevent merges, require **SignalWard repository security scan** in the repository's branch protection or ruleset settings.

---

## API

Scans and account routes require a signed-in session. Public keys are served at `GET /.well-known/signalward-keys.json`.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/auth/signin` · `/api/auth/signup` | Email + password |
| `GET`  | `/api/auth/oauth/:provider` | Start GitHub or Google sign-in |
| `POST` | `/api/auth/magic-link` · `/api/auth/recover` | Passwordless and password reset |
| `GET`  | `/api/me` · `PATCH /api/me/profile` | Profile and session |
| `POST` | `/api/scans/repository` · `/message` · `/url` | Run a scan |
| `GET`  | `/api/reports` · `/api/reports/:id` | Reports and signed receipts |
| `POST` | `/api/verify` | Verify a receipt against trusted keys |
| `GET`/`POST`/`DELETE` | `/api/blocklist` | Manage indicator tags |
| `GET`  | `/api/events` | SSE stream for real-time status |

Every error returns `{ error: { code, message, field?, requestId } }`.

---

## Project Structure

```
signalward/
├── apps/
│   ├── cli/signalward.ts          CLI (scan · url · verify · keys · doctor)
│   └── web/
│       ├── server.mjs             HTTP server, static allowlist, security headers
│       ├── src/env.ts             .env loading & strict validation
│       ├── src/auth.ts            Supabase + local auth, OAuth, magic link
│       ├── src/store.ts           Supabase (RLS) and local data stores
│       ├── src/ai.ts              Optional server-side report summaries
│       ├── src/api.ts             REST API, sessions, rate limits
│       ├── src/security.ts        Encrypted cookies, HKDF, origin checks
│       └── public/                Observatory, console, account, verifier
├── packages/
│   ├── contracts/                 Shared report & receipt schemas
│   ├── engine/                    Scan orchestration & workspace context
│   ├── fraud-scan/                Cues, brand DB, indicator extraction
│   ├── policy/                    Deterministic verdict & action mapping
│   ├── receipts/                  Canonical JSON, SHA-256, Ed25519
│   └── repo-scan/                 Secret rules, dependency audit, CI linter
├── supabase/migrations/           Schema + row-level security
└── tests/policy.test.ts
```

---

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SIGNALWARD_SESSION_SECRET` | production | Encrypts session cookies (32+ bytes, base64) |
| `SIGNALWARD_INDICATOR_KEY` | production | 32-byte HKDF master for per-account indicator tags |
| `SIGNALWARD_INDICATOR_KEY_VERSION` | optional | Active indicator-key version (defaults to `k1`) |
| `SIGNALWARD_PREVIOUS_INDICATOR_KEYS` | optional | Secret key history used to preserve indicator matches during rotations; maximum three previous keys |
| `SIGNALWARD_SIGNING_KEY` | production | Base64 PKCS#8 DER Ed25519 receipt key |
| `SIGNALWARD_REPORT_ENCRYPTION_KEY` | production | Exactly 32 random bytes, base64; encrypts stored report payloads with AES-256-GCM |
| `SIGNALWARD_PREVIOUS_REPORT_ENCRYPTION_KEYS` | optional | Secret history of up to three previous report-encryption keys, used during rotation |
| `SIGNALWARD_PREVIOUS_SIGNING_KEYS` | optional | Base64url JSON public-key history retained for receipt verification after key rotation |
| `PUBLIC_URL` | production | Origin for auth redirects and secure cookies |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY` | for Supabase | Auth + database (anon key only, never service-role) |
| `GEMINI_API_KEY`, `GEMINI_MODEL` | optional | Plain-language report summaries; falls back to rules |
| `PORT`, `HOST`, `AUTH_PROVIDER`, `ALLOW_SIGNUP` | optional | Server and auth behaviour |

Run `node apps/cli/signalward.ts doctor` to check everything at once.

Rotate the receipt signing key with `node apps/cli/signalward.ts keys rotate`. Deploy both values it prints: the replacement private key and the previous public-key history. The public key endpoint and offline key exports include the active key plus retained previous keys, so older receipts continue to verify. Keep retired public keys for as long as their receipts must remain verifiable; the configured history supports up to 32 retired keys.

Rotate the indicator key with `node apps/cli/signalward.ts keys rotate-indicators`. Deploy all three values it prints together. During overlap, SignalWard reads and records tags under the active key and retained previous keys; this preserves existing sightings and blocklist matches. Previous indicator keys are secrets. Removing one ends matching for tags created with that version, so retain it until those records are deliberately retired.

Stored report payloads and local-account/workspace records use AES-256-GCM. Local account and workspace encryption derive separate keys from the report key with HKDF and distinct contexts. Back up `SIGNALWARD_REPORT_ENCRYPTION_KEY` securely; reports or local records encrypted with lost active and retained keys cannot be recovered. Rotate with `node apps/cli/signalward.ts keys rotate-reports` and deploy both values it prints. Local reports, account records and workspace data are re-encrypted under the active key on startup; Supabase reports are re-encrypted with the active key when opened or exported. Keep prior keys until all reports/local records encrypted with them have been re-encrypted or deleted. New Supabase reports are encrypted at the application layer. Previously stored Supabase rows remain marked as legacy plaintext until opened or exported through the app's one-way encryption migration.

---

## Supabase setup

1. Create a project and copy its URL and anon key into `.env`.
2. Run every SQL file in `supabase/migrations/` in timestamp order. This creates `profiles`, `reports`, `indicator_sightings` and `blocklist`, enables row-level security, and adds report encryption and key-rotation support.
3. Enable the **GitHub** and **Google** auth providers, and add `<PUBLIC_URL>/auth/callback` to the redirect URLs.
4. Run `node apps/cli/signalward.ts doctor` to confirm the tables exist.

---

## Security Properties

- **Deterministic verdicts** — policy is pure code, no model or probability involved
- **Zero-fetch URL analysis** — untrusted links are never opened
- **Privacy-preserving indicators** — raw values are redacted; only keyed HMAC tags are stored
- **Tenant isolation** — per-account HKDF keys and Postgres row-level security
- **Non-repudiable receipts** — Ed25519 signatures over Canonical JSON, verifiable offline
- **Hardened sessions** — AES-256-GCM encrypted HttpOnly cookies, same-origin checks, rate limits
- **Strict CSP** — no inline scripts; all assets self-hosted
- **Safe file intake** — path traversal blocked, symlinks refused, binary files skipped

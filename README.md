# ◈ SignalWard

**Security workspace for repository auditing, fraud analysis, and signed evidence receipts.**

[![node >= 24](https://img.shields.io/badge/node-%3E%3D24-brightgreen)](https://nodejs.org/)
[![zero runtime deps](https://img.shields.io/badge/dependencies-zero-success)](package.json)
[![Ed25519 receipts](https://img.shields.io/badge/signatures-Ed25519-orange)](packages/receipts)
[![deploy to Workers](https://img.shields.io/badge/deploy-Cloudflare%20Workers-f38020)](wrangler.jsonc)

---

## What It Does

SignalWard scans **repositories**, **messages**, and **URLs**, then issues a deterministic verdict with a tamper-proof **Ed25519 receipt**. No external npm dependencies. No outbound requests to untrusted targets.

| Scanner | Detects |
|---------|---------|
| **Repository** | Leaked secrets (AWS, GitHub, Stripe, private keys, …), vulnerable dependencies, insecure CI/CD workflows |
| **Message** | Social-engineering cues, brand impersonation, credential/payment phishing, AI prompt injection |
| **URL** | Typosquatting, homoglyphs, high-abuse TLDs, open redirects — plus optional live threat intel (URLhaus, RDAP domain age, trained ML model) |

Every indicator (email, phone, UPI, wallet, IBAN) is redacted and stored only as a workspace-keyed **HMAC-SHA-256 tag** — workspaces can't correlate each other's data.

---

## Quick Start

```sh
# 1. Generate secrets
node apps/cli/signalward.ts keys        # paste output into .env

# 2. Start the server (Node.js >= 24, zero install)
npm run dev

# 3. Validate your setup
node apps/cli/signalward.ts doctor
```

- **`/`** — Signal Observatory landing page
- **`/scan`** — Scanner console (repo, message, URL, verify, activity)
- **`/account`** — User profile & data export

```sh
npm test   # run policy tests
```

---

## CLI

```sh
# Scan a local checkout
signalward scan .
signalward scan /path/to/repo --json --out ./artifacts

# Scan a GitHub repo by URL (public, or private with --token)
signalward scan owner/repo
signalward scan https://github.com/owner/repo --ref main --token ghp_...

# Watch a directory and re-scan on changes
signalward watch .

# Inspect a URL (zero-fetch lexical analysis + optional threat intel)
signalward url "https://hdfc-secure-kyc.top/verify"

# Ingest Suricata EVE alerts
signalward suricata --stdin < /var/log/suricata/eve.json

# Verify a receipt offline
signalward verify ./artifacts/<id>.receipt.json \
  --report ./artifacts/<id>.report.json \
  --keys ./artifacts/signalward-keys.json

# MCP server (Model Context Protocol over stdio)
signalward mcp

# Key management
signalward keys                    # generate fresh secrets
signalward keys rotate             # rotate signing key, retain old public keys
signalward keys rotate-indicators  # rotate indicator master key with overlap
signalward keys rotate-reports     # rotate report encryption key
```

**Exit codes:** `0` pass/valid · `1` block/high-risk/invalid · `2` incomplete/error

> All commands are run as `node apps/cli/signalward.ts <command>`.

---

## Deploy to Cloudflare Workers

SignalWard ships a Workers entry (`worker.mjs` + `wrangler.jsonc`). Workers mode requires Supabase for auth and storage.

```sh
# Set secrets
wrangler secret put SUPABASE_URL
wrangler secret put SUPABASE_ANON_KEY
wrangler secret put PUBLIC_URL
wrangler secret put SIGNALWARD_SESSION_SECRET
wrangler secret put SIGNALWARD_INDICATOR_KEY
wrangler secret put SIGNALWARD_SIGNING_KEY
wrangler secret put SIGNALWARD_REPORT_ENCRYPTION_KEY

# Deploy
npx wrangler deploy
```

> SSE live events are not available on Workers; the console operates without them.

---

## API

Session-based REST API. Public keys at `GET /.well-known/signalward-keys.json`.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/auth/*` | Sign up, sign in, OAuth, magic link, refresh, password change |
| `POST` | `/api/scans/repository` | Scan uploaded files, synthetic samples, or a GitHub URL |
| `POST` | `/api/scans/message` | Analyse text for fraud signals |
| `POST` | `/api/scans/url` | Lexically inspect a URL with optional threat intel |
| `GET`  | `/api/reports` | List reports |
| `GET`  | `/api/reports/:id` | Full report + receipt + AI brief |
| `POST` | `/api/verify` | Verify a receipt |
| `POST` | `/api/blocklist` | Add/remove indicator tags |
| `GET`  | `/api/events` | SSE stream for real-time updates |
| `GET/PATCH` | `/api/account/profile` | User profile |
| `POST` | `/api/account/export` | Export all reports |
| `POST` | `/api/account/erase` | Delete all user data |

---

## Project Structure

```
signalward/
├── apps/
│   ├── cli/signalward.ts             CLI + MCP server + Suricata ingestion
│   └── web/
│       ├── server.mjs                HTTP server (Node)
│       ├── src/
│       │   ├── api.ts                REST API & scan orchestration
│       │   ├── auth.ts               Supabase OAuth / local password auth
│       │   ├── store.ts              Local file store + Supabase Postgres store
│       │   ├── ai.ts                 Gemini-powered report briefs (optional)
│       │   ├── env.ts                Strict config validation
│       │   ├── security.ts           CSRF, rate limits, HKDF, cookie encryption
│       │   └── storage-crypto.ts     AES-256-GCM report encryption at rest
│       └── public/                   Observatory, console, auth, account, verify pages
├── packages/
│   ├── contracts/                    Shared TypeScript schemas (v1)
│   ├── engine/                       Scan orchestration, threat model scenarios
│   ├── fraud-scan/                   Social engineering cues, brand DB, indicators
│   ├── policy/                       Deterministic verdict & action mapping
│   ├── receipts/                     Canonical JSON, SHA-256, Ed25519 signing
│   ├── repo-scan/                    Secret rules, dependency audit, CI linter
│   ├── repo-fetch/                   GitHub tarball download & extraction
│   └── url-intel/                    RDAP domain age, URLhaus, trained ML model, Suricata
├── scripts/
│   └── train_url_model.py            Train logistic URL risk model from labeled CSV
├── supabase/migrations/              Postgres schema (profiles, reports, sightings, blocklist)
├── worker.mjs                        Cloudflare Workers entry
├── wrangler.jsonc                    Workers config
├── .github/workflows/                CI security gate
└── tests/policy.test.ts
```

---

## Configuration

Copy `.env.example` to `.env`, then run `signalward keys` to generate secrets.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port (auto-selects if busy) |
| `PUBLIC_URL` | `http://127.0.0.1:3000` | Origin for cookies and auth redirects |
| `SIGNALWARD_SESSION_SECRET` | auto | 32-byte session cookie encryption key |
| `SIGNALWARD_INDICATOR_KEY` | auto | 32-byte HKDF master for indicator tags |
| `SIGNALWARD_SIGNING_KEY` | auto | Ed25519 PKCS#8 key for receipt signing |
| `SIGNALWARD_REPORT_ENCRYPTION_KEY` | auto | 32-byte AES-256-GCM key for stored reports |
| `SUPABASE_URL` | — | Supabase project URL (enables persistent storage) |
| `SUPABASE_ANON_KEY` | — | Supabase anon/publishable key |
| `AUTH_PROVIDER` | `auto` | `supabase`, `local`, or `auto` |
| `GEMINI_API_KEY` | — | Optional; enables AI report briefs |
| `URLHAUS_AUTH_KEY` | — | Optional; enables live host reputation lookups |
| `SIGNALWARD_URL_MODEL_B64` | — | Optional; base64url-encoded trained URL risk model |

Key rotation commands (`keys rotate`, `rotate-indicators`, `rotate-reports`) produce the `SIGNALWARD_PREVIOUS_*` variables needed for zero-downtime rollover.

---

## Security Properties

- **Deterministic verdicts** — pure code policy, no model can alter a verdict
- **Zero-fetch URL analysis** — untrusted links are never opened
- **Privacy-preserving indicators** — raw values redacted; only keyed HMAC tags stored
- **Non-repudiable receipts** — Ed25519 over Canonical JSON, verifiable offline or in-browser
- **Report encryption at rest** — AES-256-GCM with key rotation support
- **CSRF protection** — `Sec-Fetch-Site` + `Origin` validation on every mutation
- **Memory-safe file intake** — path traversal blocked, symlinks refused, binaries skipped
- **Structured threat model** — deterministic scenario assessment attached to every report

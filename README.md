# ◈ SignalWard

**Deterministic security workspace for repository auditing, fraud analysis, and cryptographically signed evidence receipts.**

[![node >= 24](https://img.shields.io/badge/node-%3E%3D24-brightgreen)](https://nodejs.org/)
[![zero dependencies](https://img.shields.io/badge/dependencies-zero-success)](package.json)
[![Ed25519 + SHA-256](https://img.shields.io/badge/signatures-Ed25519-orange)](packages/receipts)

---

## What It Does

SignalWard scans **code repositories**, **suspicious messages**, and **untrusted links**, then issues a deterministic verdict with a tamper-proof **Ed25519 receipt** — no external services, no network calls to untrusted targets, zero npm dependencies.

| Scanner | Detects |
|---------|---------|
| **Repository** | Leaked secrets (AWS, GitHub, Stripe, private keys, …), vulnerable dependencies, insecure CI/CD workflows |
| **Message** | Social-engineering cues, brand impersonation, payment/credential phishing, AI prompt injection attempts |
| **URL** | Typosquatting, homoglyphs, high-abuse TLDs, open redirects, URL shorteners — all without opening the link |

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
repo  fraud   url      ← packages/repo-scan  ·  packages/fraud-scan
   └────┼────┘
        │
 Deterministic Policy  ← packages/policy
        │
 Ed25519 Receipts      ← packages/receipts
```

All indicator values (emails, phones, UPI handles, wallets) are redacted and converted to workspace-keyed **HMAC-SHA-256 tags** via HKDF — workspaces can't correlate each other's data.

---

## Quick Start

```sh
# Start the web console (Node.js >= 24, no install needed)
npm run dev
```

Open the URL printed in the terminal. Port 3000 is tried first; set `PORT` to override.

- **`/`** — Signal Observatory (landing page)
- **`/scan`** — Scanner Console (repository, message, URL, verify, activity)

```sh
# Run tests
npm test
```

---

## CLI

```sh
# Scan a repository
node apps/cli/signalward.ts scan .
node apps/cli/signalward.ts scan /path/to/repo --json --out ./artifacts

# Inspect a URL (zero-fetch, lexical only)
node apps/cli/signalward.ts url "https://hdfc-secure-kyc.top/verify"

# Verify a receipt offline
node apps/cli/signalward.ts verify ./artifacts/<id>.receipt.json \
  --report ./artifacts/<id>.report.json \
  --keys ./artifacts/signalward-keys.json
```

**Exit codes:** `0` pass/valid · `1` block/high-risk/invalid · `2` incomplete/error

---

## API

All endpoints require a workspace session (`POST /api/session`). Public keys are served at `GET /.well-known/signalward-keys.json`.

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/scans/repository` | Scan uploaded files or synthetic samples |
| `POST` | `/api/scans/message` | Analyse a message for fraud signals |
| `POST` | `/api/scans/url` | Lexically inspect a URL |
| `GET`  | `/api/reports` | List reports in the workspace |
| `GET`  | `/api/reports/:id` | Full report + signed receipt |
| `POST` | `/api/verify` | Verify a receipt against trusted keys |
| `POST` | `/api/blocklist` | Add/remove indicator tags |
| `GET`  | `/api/events` | SSE stream for real-time updates |

---

## Project Structure

```
signalward/
├── apps/
│   ├── cli/signalward.ts          CLI (scan · url · verify)
│   └── web/
│       ├── server.mjs             HTTP server
│       ├── src/api.ts             REST API & session management
│       ├── src/security.ts        CSRF, rate limiting, HKDF secrets
│       └── public/                Observatory & console frontend
├── packages/
│   ├── contracts/                 Shared TypeScript schemas (v1)
│   ├── engine/                    Scan orchestration & workspace context
│   ├── fraud-scan/                Social engineering cues, brand DB, indicators
│   ├── policy/                    Deterministic verdict & action mapping
│   ├── receipts/                  Canonical JSON, SHA-256, Ed25519 signing
│   └── repo-scan/                 Secret rules, dependency audit, CI linter
└── tests/policy.test.ts
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port (auto-selects if busy) |
| `SIGNALWARD_STATE_DIR` | `.signalward/` | Key & secret storage directory |
| `SIGNALWARD_SIGNING_KEY` | auto-generated | Base64 PKCS#8 DER Ed25519 private key |
| `SIGNALWARD_SESSION_SECRET` | auto-generated | 32-byte session HMAC secret |
| `SIGNALWARD_INDICATOR_KEY` | auto-generated | 32-byte HKDF master for indicator tags |

---

## Security Properties

- **Deterministic verdicts** — policy is pure code, no model or probability involved
- **Zero-fetch URL analysis** — untrusted links are never opened
- **Privacy-preserving indicators** — raw values are redacted; only keyed HMAC tags are stored
- **Non-repudiable receipts** — Ed25519 signatures over Canonical JSON, verifiable offline
- **Strict origin checks** — CSRF protection via `Sec-Fetch-Site` and `Origin` validation
- **Memory-only state** — workspace data lives in-process and is wiped on session end
- **Safe file intake** — path traversal blocked, symlinks refused, binary files skipped

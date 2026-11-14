# SignalWard

> **Deterministic Zero-Trust Security Workspace for Repository Auditing, Social-Engineering Fraud Analysis, and Cryptographically Signed Ed25519 Evidence Receipts.**

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D24-brightgreen.svg)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-zero%20external-success.svg)](package.json)
[![Cryptography](https://img.shields.io/badge/signatures-Ed25519%20%2B%20SHA--256-orange.svg)](packages/receipts)

---

## Table of Contents

- [Overview](#overview)
- [Core Invariants](#core-invariants)
- [System Architecture](#system-architecture)
- [Monorepo Structure](#monorepo-structure)
- [Scanners & Capabilities](#scanners--capabilities)
  - [1. Repository Scanner](#1-repository-scanner)
  - [2. Fraud & Message Reviewer](#2-fraud--message-reviewer)
  - [3. Link & Domain Scanner](#3-link--domain-scanner)
- [Cryptographic Receipts & Verification](#cryptographic-receipts--verification)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Web Interface & Console](#web-interface--console)
  - [Running Unit Tests](#running-unit-tests)
- [Command-Line Interface (CLI)](#command-line-interface-cli)
  - [Repository Scan](#repository-scan)
  - [URL Inspection](#url-inspection)
  - [Receipt Verification](#receipt-verification)
  - [CI/CD Integration Example](#cicd-integration-example)
- [HTTP REST & SSE API](#http-rest--sse-api)
- [Configuration & Environment Variables](#configuration--environment-variables)
- [Security & Threat Model](#security--threat-model)

---

## Overview

Modern software development and team operations face two intertwined threats: compromised codebase integrity (leaked credentials, malicious dependencies, and insecure CI/CD pipelines) and social-engineering fraud (phishing, spoofed authority notices, and payment diversion).

**SignalWard** bridges these domains with a unified, zero-trust security workstation. It evaluates code repositories, suspicious communications, and untrusted links entirely in-memory and outputs deterministic, auditable verdicts accompanied by tamper-proof, digitally signed **evidence receipts**.

---

## Core Invariants

SignalWard is built around four non-negotiable architectural guarantees:

1. **Deterministic, Verifiable Policy**  
   Verdicts are produced strictly by auditable rule functions (`packages/policy`). No probabilistic model or LLM hallucination can alter a verdict or downgrade a high-severity secret or phishing detection into a pass. The exact same input will always generate the exact same verdict and actions.
2. **Privacy-Preserving Keyed Threat Intelligence**  
   Raw sensitive indicators (emails, phone numbers, UPI handles, bank accounts, crypto wallets) are redacted and converted to workspace-keyed HMAC-SHA-256 tags (`k1:<tag>`) derived via HKDF-SHA256. Workspaces cannot correlate each other's data, yet within a single workspace, campaigns and repeated indicators are instantly detected and blocklisted.
3. **Non-Repudiable Cryptographic Receipts**  
   Every report is hashed into a SHA-256 digest over Canonical JSON and signed using **Ed25519** (`signalward.receipt/v1`). Anyone can verify the authenticity, timestamp, and verdict offline or in a browser without relying on or contacting the issuing server.
4. **Zero-Fetch, Safe-by-Design Execution**  
   Untrusted links and URLs are analyzed lexically (TLD analysis, homoglyphs, brand typosquatting, open redirect patterns). **SignalWard never issues outbound HTTP requests to untrusted targets**, ensuring analysts are protected from tracking pixels, IP logging, and remote exploits.

---

## System Architecture

```
                      ┌────────────────────────────────────────┐
                      │              Inputs                    │
                      │  • Git Repositories / In-Memory Files  │
                      │  • Suspicious Messages / Emails / SMS  │
                      │  • Untrusted URLs / Defanged Links     │
                      └───────────────────┬────────────────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
         ┌─────────────────────┐                     ┌─────────────────────┐
         │     CLI Tool        │                     │   Web Application   │
         │ (apps/cli/signalward)│                     │    (apps/web)       │
         │  • CI/CD Pipelines  │                     │  • Web Observatory  │
         │  • Local Checkouts  │                     │  • Scanner Console  │
         └──────────┬──────────┘                     └──────────┬──────────┘
                    │                                           │
                    └─────────────────────┬─────────────────────┘
                                          │
                                          ▼
                      ┌────────────────────────────────────────┐
                      │             Scan Engine                │
                      │         (packages/engine)              │
                      └─────┬─────────────┬──────────────┬─────┘
                            │             │              │
           ┌────────────────┘             │              └────────────────┐
           ▼                              ▼                               ▼
┌─────────────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
│  Repository Scanner │        │    Fraud Scanner    │        │     URL Scanner     │
│(packages/repo-scan) │        │(packages/fraud-scan)│        │(packages/fraud-scan)│
│ • Secrets & Entropy │        │ • NLP Social Cues   │        │ • URL Refanging     │
│ • Lockfile Audits   │        │ • Brand Impersonation│       │ • TLD & Homoglyphs  │
│ • CI/CD Vulnerab.   │        │ • HKDF Tagged IoCs  │        │ • Zero Egress Eval  │
└──────────┬──────────┘        └──────────┬──────────┘        └──────────┬──────────┘
           │                              │                              │
           └──────────────────────┬───────┴──────────────────────────────┘
                                  ▼
                      ┌────────────────────────┐
                      │   Deterministic Policy │
                      │   (packages/policy)    │
                      │   • Evaluates Verdict  │
                      │   • Maps Mitigations   │
                      └───────────┬────────────┘
                                  ▼
                      ┌────────────────────────┐
                      │   Ed25519 Receipts     │
                      │  (packages/receipts)   │
                      │   • Canonical JSON     │
                      │   • SHA-256 Digest     │
                      │   • Cryptographic Sign │
                      └────────────────────────┘
```

---

## Monorepo Structure

Built as a lightweight, zero-external-dependency pnpm workspace utilizing native Node.js capabilities:

```
signalward/
├── apps/
│   ├── cli/                   # SignalWard CLI (scan, url, verify commands)
│   │   └── signalward.ts
│   └── web/                   # Zero-dependency native HTTP server & frontend
│       ├── server.mjs         # HTTP server, asset routing, port fallback
│       ├── src/
│       │   ├── api.ts         # REST API, workspace sessions, SSE events
│       │   └── security.ts    # Rate limiting, Same-Origin checks, HKDF secrets
│       └── public/            # Interactive Web Observatory and Scanner Console
│           ├── index.html     # Interactive 3D particle observatory landing page
│           ├── scan.html      # Full-featured scanner console UI
│           ├── console.js     # Console state management & SSE listener
│           ├── scene.js       # High-performance canvas particle field
│           └── verify.js      # In-browser WebCrypto Ed25519 receipt verifier
├── packages/
│   ├── contracts/             # Schemas and shared TypeScript interfaces (v1)
│   ├── engine/                # Orchestration layer, stages, workspace context
│   ├── fraud-scan/            # Social engineering cues, brand detection, indicators
│   ├── policy/                # Deterministic policy engine and action mapping
│   ├── receipts/              # Canonical JSON, SHA-256 digests, Ed25519 signatures
│   └── repo-scan/             # Secret detection, dependency audits, CI workflow linter
├── tests/
│   └── policy.test.ts         # Core policy test suite
├── package.json
└── pnpm-workspace.yaml
```

---

## Scanners & Capabilities

### 1. Repository Scanner

Designed to prevent credential leakage and supply chain sabotage before code merges:

- **High-Fidelity Secret Detection**:
  - AWS access key IDs (`AKIA`, `ASIA`) and secret keys.
  - Private key blocks (RSA, EC, DSA, OpenSSH, PGP).
  - GitHub Personal Access Tokens and fine-grained PATs (`ghp_`, `github_pat_`).
  - GitLab personal access tokens (`glpat-`).
  - Slack bot/user tokens and incoming webhooks.
  - Stripe live secret keys (`sk_live_`, `rk_live_`).
  - Google API keys (`AIza...`).
  - Database connection strings containing embedded passwords (PostgreSQL, MySQL, MongoDB, Redis, AMQP).
  - High-entropy generic credential assignments (`entropy >= 3.3 bits`).
  - **Inline Suppression**: False positives in test fixtures can be explicitly suppressed using `signalward:allow`.
- **Dependency Vulnerability Auditing**:
  - Inspects `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, and `requirements.txt`.
  - Matches dependencies and pinned versions against a built-in curated advisory database without sending your manifest to third-party services.
- **CI/CD Pipeline Security Auditing**:
  - **Script Injection**: Expansion of untrusted context expressions (e.g. `${{ github.event.issue.title }}`) inside shell `run:` steps.
  - **Privileged Checkout**: Dangerous pull request triggers (`pull_request_target`, `workflow_run`) checking out untrusted head commits.
  - **Overprivileged Tokens**: Workflows granting `permissions: write-all`.
  - **Unpinned Actions**: Third-party GitHub actions pinned to mutable branch or tag names rather than immutable commit SHAs.
  - **Pipe-to-Shell**: Unverified downloads executing via `curl | sh` or `wget | bash`.
  - **Secret Echoing**: Build steps explicitly echoing secrets into log output.

### 2. Fraud & Message Reviewer

Engineered for SOC analysts, incident response teams, and users reviewing suspicious emails, SMS messages, or chat transcripts:

- **Social-Engineering Linguistic Analysis**:
  - Urgent deadlines and pressure tactics.
  - Threats of service termination, account freezes, or legal penalties.
  - Credential requests (passwords, PINs, OTPs, seed phrases) paired with sentence-level negation filters (distinguishing warnings from attacks).
  - Upfront fee schemes and advance-fee lures.
  - Demands for untraceable payment (cryptocurrency, gift cards).
  - Remote-access software prompts (AnyDesk, TeamViewer, QuickSupport, RustDesk).
  - **AI Scanner Evasion Defense**: Detects and flags adversarial prompt injections attempting to command automated classifiers to mark content as benign.
- **Brand & Impersonation Consistency**:
  - Curated database of 30+ major financial and technology institutions (PayPal, Microsoft, Google, Apple, Amazon, HDFC Bank, SBI, ICICI, Binance, etc.).
  - Cross-references brand mentions against links and sending domains, immediately raising high-severity alerts when brand identities diverge.
- **Inert Indicator Extraction & Anonymization**:
  - Automatically extracts and redacts emails, telephone numbers, UPI handles, crypto addresses, IBANs (validated via mod-97 check), IFSC codes, and IPv4 addresses.
  - Retains only privacy-preserving HMAC-SHA-256 tags for correlation.

### 3. Link & Domain Scanner

A zero-fetch static analysis engine for untrusted URLs:

- **URL Normalization**: Refangs defanged links (`hxxp://`, `example[.]com`), strips embedded credentials, and decodes Punycode/IDN homoglyphs.
- **Lexical & Structural Checks**:
  - Identifies brand names placed inside subdomains or paths of third-party domains.
  - Flags high-abuse TLDs (`.zip`, `.mov`, `.top`, `.xyz`, `.icu`, `.cfd`, etc.).
  - Detects open redirect parameters (`?redirect=`, `?url=`, `?next=`).
  - Flags URL shorteners (`bit.ly`, `tinyurl.com`, `t.co`, etc.) and shared user-content hosting platforms.
  - Zero egress: Evaluated offline without opening network connections to external hosts.

---

## Cryptographic Receipts & Verification

SignalWard introduces auditable, tamper-evident **verdict receipts** (`signalward.receipt/v1`).

```json
{
  "schema": "signalward.receipt/v1",
  "algorithm": "Ed25519",
  "payload": {
    "reportId": "rpt_1gK_YjYdV9Cr",
    "workspace": "ws_local_cli",
    "kind": "repository",
    "reportDigest": "sha256:1ac92ce22249aa19aae9116c2a3487b8158839ceaf797a807fe01e77b7d3d328",
    "scope": { "kind": "repository", "files": 43, "bytes": 128420, "skipped": 0, "label": "signalward" },
    "policyVersion": "signalward-policy-2026.11.2",
    "verdict": "pass",
    "action": "pass_commit_status",
    "findingIds": [],
    "issuedAt": "2026-11-14T04:39:41.210Z",
    "keyId": "sw-ed25519-130f7931e712"
  },
  "signature": "V0F_c10mH...base64url..."
}
```

### Verification Steps
1. **Schema Check**: Conforms to `signalward.receipt/v1` and algorithm is `Ed25519`.
2. **Key Trust**: The `keyId` corresponds to an authorized public key in `/.well-known/signalward-keys.json`.
3. **Payload Signature**: The Ed25519 signature validates against the Canonical JSON string of `payload`.
4. **Report Integrity (Optional)**: If the report JSON is provided, its SHA-256 digest over Canonical JSON must match `reportDigest`.

---

## Getting Started

### Prerequisites

- **Node.js >= 24** (utilizes native TypeScript execution and native Web Crypto).
- No external npm packages required for runtime.

### Web Interface & Console

Start the built-in HTTP server:

```sh
npm run dev
# or: npm start
```

The server binds to port `3000` (or selects an available local port if `3000` is in use):

- **Signal Observatory (Visual Interface)**: `http://localhost:3000/`
- **Scanner Console**: `http://localhost:3000/scan`

### Running Unit Tests

Run policy and verdict evaluation tests using the native Node.js test runner:

```sh
npm test
```

---

## Command-Line Interface (CLI)

The CLI tool (`apps/cli/signalward.ts`) executes the identical scanning rules and policy verification as the web console.

### Repository Scan

Scan the current repository or a target path:

```sh
# Human-readable output
node apps/cli/signalward.ts scan .

# JSON output (prints full report and receipt)
node apps/cli/signalward.ts scan /path/to/repo --json

# Save report, receipt, and trusted public keys to a directory
node apps/cli/signalward.ts scan . --out ./artifacts
```

### URL Inspection

Inspect an untrusted link without opening it:

```sh
node apps/cli/signalward.ts url "https://hdfc-secure-kyc.top/verify"
```

### Receipt Verification

Verify an issued receipt offline against trusted keys and its report:

```sh
# Verify receipt signature with local keys
node apps/cli/signalward.ts verify ./artifacts/<id>.receipt.json

# Verify receipt and validate matching report digest
node apps/cli/signalward.ts verify ./artifacts/<id>.receipt.json \
  --report ./artifacts/<id>.report.json \
  --keys ./artifacts/signalward-keys.json
```

### Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| `0` | **PASS / VALID** — Scan passed with no blocking findings, or receipt signature is valid. |
| `1` | **BLOCK / HIGH RISK / INVALID** — High/critical secret detected, fraud pattern identified, or signature invalid. |
| `2` | **INCOMPLETE / ERROR** — Partial scan coverage (skipped files), bad CLI arguments, or runtime failure. |

### CI/CD Integration Example

Add SignalWard as a gatekeeper in your GitHub Actions pipeline (`.github/workflows/security-gate.yml`):

```yaml
name: SignalWard Gate
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
      - name: Run SignalWard Scan
        run: |
          node apps/cli/signalward.ts scan . --out ./security-receipts
      - name: Archive Security Receipt
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: signalward-receipts
          path: ./security-receipts
```

---

## HTTP REST & SSE API

SignalWard exposes an isolated HTTP API powered by session cookies (`sw_session`):

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/.well-known/signalward-keys.json` | Returns public Ed25519 keys (`JWK` set) for receipt verification. |
| `POST` | `/api/session` | Establishes or resumes a workspace session; sets an `HttpOnly` cookie. |
| `POST` | `/api/session/end` | Immediately terminates session and wipes all workspace data from memory. |
| `GET` | `/api/session` | Returns current workspace ID, key version, and stats. |
| `POST` | `/api/scans/repository` | Scans in-memory snapshot of files or runs synthetic samples (`vulnerable`, `remediated`). |
| `POST` | `/api/scans/message` | Scans text, email headers, or SMS messages for fraud signals. |
| `POST` | `/api/scans/url` | Lexically analyzes a URL or domain. |
| `GET` | `/api/reports` | Returns recent scan summaries for the active workspace. |
| `GET` | `/api/reports/:id` | Returns full report and Ed25519 receipt by ID. |
| `POST` | `/api/verify` | Validates a receipt and report against trusted public keys. |
| `GET` | `/api/blocklist` | Lists blocked indicator tags for the current workspace. |
| `POST` | `/api/blocklist` | Adds or removes an indicator tag to/from the workspace blocklist. |
| `GET` | `/api/events` | Server-Sent Events (SSE) stream for real-time console updates. |

---

## Configuration & Environment Variables

All settings fall back to secure local defaults inside `.signalward/`:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `PORT` | Local HTTP server port. If busy and unset, an open port is chosen automatically. | `3000` |
| `SIGNALWARD_STATE_DIR` | Directory storing local cryptographic keys and master secrets. | `.signalward/` |
| `SIGNALWARD_SIGNING_KEY` | Base64-encoded PKCS#8 DER Ed25519 private key for signing receipts. | Auto-generated in state dir |
| `SIGNALWARD_SESSION_SECRET`| Base64-encoded 32-byte secret for workspace session HMAC signing. | Auto-generated in state dir |
| `SIGNALWARD_INDICATOR_KEY` | Base64-encoded 32-byte master key for HKDF workspace tag derivation. | Auto-generated in state dir |

---

## Security & Threat Model

- **Safe Path Traversal & Symlinks**: The repository intake enforces strict path normalization (`safeRelativePath`), ignores symlinks pointing outside the repository root, skips binary files, and caps total files and byte counts.
- **CSRF & Origin Isolation**: All state-modifying API endpoints require strict same-origin verification (`Sec-Fetch-Site: same-origin` and matching `Origin` headers).
- **Defense in Depth**: Strict security headers are dispatched with every response:
  - `Content-Security-Policy: default-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none';`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Cross-Origin-Opener-Policy: same-origin`
- **Memory Hygiene**: Workspace state is stored strictly in memory and automatically cleared when a session ends or expires (`SESSION_TTL_SECONDS = 12h`).

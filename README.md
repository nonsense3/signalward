<div align="center">
  <img src="./signalward%20logo%20bk.png" alt="SignalWard logo" width="240">
  <h1>SignalWard</h1>
  <p><strong>Scan repositories, suspicious messages, and links, then independently verify the resulting reports.</strong></p>
</div>

## Problem

An exposed credential can hide in an ordinary commit, and a payment scam can arrive in a convincing message or lookalike URL. Developers and reviewers need to know what triggered a warning, which action to take, and whether the report they received matches the original.

## Solution

| Scanner | Checks and output |
| --- | --- |
| **Repository** | Flags exposed AWS keys, GitHub tokens, Stripe keys, private keys, curated dependency advisories, and selected CI/CD risks. Findings show the affected file and remediation with credential values redacted. |
| **Message** | Flags impersonation, pressure tactics, payment and credential requests, and prompt-injection patterns. Account-scoped tags help recognize repeated indicators. |
| **Link** | Checks lookalike domains, mixed scripts, shortened URLs, and embedded redirects without opening the destination. Results include local ML scoring and historical dataset matches where available. |

### Machine learning and Gemini

SignalWard runs an eight-feature logistic regression classifier trained in Kaggle on labeled benign and phishing URLs. The local scanner also checks exact URLs against **651,191 historical records**. The original model evaluated **118,624 held-out URLs**, with **75.46% precision**, **21.24% recall**, and a **1.51% false-positive rate**. The bundled score is advisory.

When the dataset has no usable match, optional Gemini analysis evaluates the hostname and local signals. URL paths and query parameters stay local in Gemini requests. Optional RDAP and URLhaus checks add domain and host context.

## Demo links

- 🌐 [Live SignalWard app](https://signalward.axiomjisu.tech)
- ▶️ [Watch the demo on YouTube](https://youtu.be/h4Q3m30gLqI)

## Tech stack

[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node.js 24+](https://img.shields.io/badge/Node.js-24%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Supabase](https://img.shields.io/badge/Supabase-3FCF8E?logo=supabase&logoColor=white)](https://supabase.com/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?logo=cloudflare&logoColor=white)](./wrangler.jsonc)

TypeScript and Node.js power the web API and CLI. The frontend uses browser JavaScript, CSS, and WebGL. Hosted accounts use Supabase Auth and PostgreSQL Row-Level Security. The local app has zero runtime npm dependencies.

## Architecture

~~~mermaid
flowchart LR
    Web[Web console] --> Engine[Shared scan engine]
    CLI[CLI and local MCP] --> Engine
    Engine --> Checks[Rules, historical data, and local ML]
    Engine -. optional .-> Intel[Gemini, RDAP, and URLhaus]
    Checks --> Policy[Verdict and remediation]
    Intel --> Policy
    Policy --> Receipt[Report and signed receipt]
    Receipt --> Verify[Browser or CLI verifier]
    Web --> Store[Supabase Auth and Postgres]
~~~

SignalWard uses HKDF and HMAC-SHA-256 for account-scoped indicator tags and AES-256-GCM for stored report encryption. Each receipt binds the report’s SHA-256 digest to an Ed25519 signature. The verifier checks the signature against a trusted public key and compares the digest with the supplied report.

| Path | Responsibility |
| --- | --- |
| [apps/web](./apps/web) | Web console, API, identity, and storage |
| [apps/cli](./apps/cli) | Terminal scans, directory watching, MCP over stdio, Suricata ingestion, and offline verification |
| [packages](./packages) | Scanners, policy, URL intelligence, and receipt cryptography |
| [supabase/migrations](./supabase/migrations) | Hosted database schema and access policies |

## Setup and run

Use **Node.js 24 or later**.

~~~powershell
git clone https://github.com/nonsense3/signalward.git
cd signalward
Copy-Item .env.example .env
npm run dev
~~~

Open the URL printed in the terminal. Use the scan console to inspect repositories, messages, and links. Open the Verify tab to check a signed report.

~~~sh
node apps/cli/signalward.ts scan .
node apps/cli/signalward.ts url "https://example.com/"
node apps/cli/signalward.ts mcp
node apps/cli/signalward.ts doctor
npm test
~~~

For type checking, run npm ci followed by npm run typecheck. For hosted mode, apply the [Supabase migrations](./supabase/migrations), configure Supabase Auth, and set the production secrets listed in [the environment template](./.env.example). Generate SignalWard secrets with node apps/cli/signalward.ts keys. Optional settings cover Gemini, Search grounding, URLhaus, a trained model override, and a read-only GitHub token for public repositories.

## Disclosures

- **AI and data** — Google Gemini is optional at runtime. OpenAI Codex assisted with development and documentation. The bundled classifier was trained in Kaggle using the [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset). A [training script](./scripts/train_url_model.py) is available for labeled CSV input.
- **Infrastructure** — Supabase provides hosted authentication and storage. Cloudflare Workers is a supported deployment target. URLhaus and RDAP provide optional enrichment.
- **Design and fonts** — Visual references include [Lusion](https://lusion.co/), [Lusion Labs](https://labs.lusion.co/), and [Igloo Inc.](https://www.igloo.inc/). The [bundled fonts and licenses](./apps/web/public/fonts) include Mona Sans, Hubot Sans, and Monaspace.

## Track

**Cybersecurity** — repository exposure detection, fraud review, identity and account isolation, privacy-preserving indicator matching, and independently verifiable scan reports.

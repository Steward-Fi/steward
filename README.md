# Steward

The governance layer for autonomous AI agents.

Encrypted wallets · Credential vault · API proxy · Policy enforcement · Spend tracking

[![npm](https://img.shields.io/npm/v/@stwd/sdk)](https://www.npmjs.com/package/@stwd/sdk)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![API](https://img.shields.io/badge/API-live-brightgreen)](https://api.steward.fi)
[![Docs](https://img.shields.io/badge/docs-steward.fi-blue)](https://docs.steward.fi)

---

## The Problem

AI agents need API keys, wallet keys, database credentials. Today these sit as plaintext environment variables — one prompt injection away from exfiltration. No spending controls, no audit trail, no kill switch.

## The Solution

Steward sits between agents and everything they access. Three pillars:

1. **Wallet Vault** — AES-256-GCM encrypted keys. Policy-enforced signing. 7 EVM chains + Solana.
2. **Secret Vault** — Encrypted credential storage. Agents never see real API keys.
3. **API Proxy** — Every external API call flows through Steward. Credentials injected at the proxy, not in the container. Costs tracked. Everything audited.

---

## Architecture

```
Agent Container          Steward                    External APIs
┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ STEWARD_URL │───>│ Auth (JWT)       │    │ OpenAI           │
│ STEWARD_JWT │    │ Policy Engine    │───>│ Anthropic        │
│             │    │ Secret Vault     │    │ DEXs / Chains    │
│ No API keys │    │ Wallet Vault     │    │ Any API          │
│ No priv keys│    │ Audit Log        │    └──────────────────┘
└─────────────┘    └──────────────────┘
```

The vault encrypts each agent's private key with AES-256-GCM using a key derived from the master password + agent ID. Keys never exist in plaintext outside of a signing operation. All signing happens in-process; the raw key is never sent over the wire.

Policy evaluation is stateless and synchronous. The engine receives the transaction request plus pre-fetched spend/rate context, evaluates all enabled rules, and returns per-policy pass/fail details.

---

## Quick Start

```bash
# Clone & install
git clone https://github.com/Steward-Fi/steward.git
cd steward && bun install

# Configure
cp .env.example .env
# Edit .env: set STEWARD_MASTER_PASSWORD, DATABASE_URL

# Start
bun run packages/api/src/index.ts    # API on :3200
bun run packages/proxy/src/index.ts  # Proxy on :8080
```

---

## SDK Usage

```bash
npm install @stwd/sdk
# or: bun add @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const client = new StewardClient({
  baseUrl: "http://localhost:3200",
  apiKey: "your-tenant-key",
});

// Create an agent with a wallet
const agent = await client.createWallet("my-agent", "My Trading Agent");
// → { id, walletAddress, walletAddresses: { evm, solana } }

// Sign a transaction (policy-enforced)
const result = await client.signTransaction("my-agent", {
  to: "0xDEX_ROUTER",
  value: "100000000000000000", // 0.1 ETH
  chainId: 8453, // Base
});

// Or route API calls through the proxy
const openai = new OpenAI({
  baseURL: "http://steward-proxy:8080/openai/v1",
  apiKey: "steward", // dummy, replaced by proxy
});
```

---

## Policy Types

| Type | What it does |
|------|-------------|
| `spending-limit` | Per-tx, daily, weekly caps |
| `approved-addresses` | Whitelist or blocklist destination addresses |
| `rate-limit` | Max transactions per hour / per day |
| `time-window` | Only allow transactions during defined UTC hours/days |
| `auto-approve-threshold` | Auto-approve small transactions, queue large ones for human review |
| `api-access` | Control which APIs agents can call through the proxy |
| `spend-limit` | Per-agent inference and API budgets |

Policies are composable — mix and match. Hard policies reject immediately on failure. The auto-approve threshold is the only soft gate; failure queues instead of rejects.

---

## Packages

Bun monorepo managed with [Turborepo](https://turbo.build).

| Package | Description | Status |
|---------|-------------|--------|
| `@stwd/api` | REST API (30+ endpoints) | ✅ Production |
| `@stwd/proxy` | API proxy gateway | ✅ Built |
| `@stwd/vault` | Wallet + secret encryption | ✅ Production |
| `@stwd/policy-engine` | Composable policy evaluation | ✅ Production |
| `@stwd/sdk` | TypeScript SDK (zero deps) | ✅ Published |
| `@stwd/redis` | Rate limiting + spend tracking | ✅ Built |
| `@stwd/eliza-plugin` | ElizaOS integration | ✅ Published |
| `@stwd/db` | Schema + migrations | ✅ Production |
| `@stwd/webhooks` | Event notifications | ✅ Production |
| `@stwd/shared` | Types + constants | ✅ Production |
| `web` | Dashboard + landing | ✅ Deployed |

---

## Supported Chains

Ethereum · Base · BSC · Polygon · Arbitrum · Base Sepolia · BSC Testnet · Solana

---

## Webhook Events

Configure a webhook URL on your tenant and Steward will POST on every state change:

| Event | When |
|-------|------|
| `approval_required` | Transaction queued for manual review |
| `tx_signed` | Transaction signed and broadcast |
| `tx_rejected` | Transaction rejected by a hard policy |
| `tx_failed` | Transaction failed on-chain |

---

## Links

- **Website:** [steward.fi](https://steward.fi)
- **Docs:** [docs.steward.fi](https://docs.steward.fi)
- **API:** [api.steward.fi](https://api.steward.fi)
- **npm:** [@stwd/sdk](https://www.npmjs.com/package/@stwd/sdk)
- **ElizaOS Plugin:** [@stwd/eliza-plugin](https://www.npmjs.com/package/@stwd/eliza-plugin)

---

## License

[MIT](LICENSE)

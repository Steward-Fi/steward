# Steward

The governance layer for autonomous AI agents.

Encrypted wallets · Credential vault · API proxy · Policy enforcement · Spend tracking · Embeddable UI

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
3. **Policy Engine** — Composable rules evaluated before every action. Spending limits, rate limits, address whitelists, time windows, auto-approve thresholds.

Plus an **API Proxy** that injects credentials at the edge, tracks spend, and logs every call.

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

The vault encrypts each agent's private key with AES-256-GCM using a key derived from the master password + agent ID. Keys never exist in plaintext outside of a signing operation.

Policy evaluation is stateless and synchronous. The engine receives the transaction request plus pre-fetched spend/rate context, evaluates all enabled rules, and returns per-policy pass/fail details.

Multi-tenant by design — each tenant's agents, secrets, wallets, and policies are fully isolated. A **control plane config** per tenant governs which features and policy types are exposed to end users.

---

## Quick Start

```bash
# Clone & install
git clone https://github.com/Steward-Fi/steward.git
cd steward && bun install

# Configure
cp .env.example .env
# Edit .env: set STEWARD_MASTER_PASSWORD, DATABASE_URL

# Start API + proxy
bun run packages/api/src/index.ts    # API on :3200
bun run packages/proxy/src/index.ts  # Proxy on :8080
```

### Local mode (no Postgres required)

Steward ships with a PGLite backend — full Postgres running in-process via WASM. No external database needed.

```bash
# Start in local mode — data persists to ~/.steward/data/
bun run packages/api/src/embedded.ts

# Or in-memory (reset on restart)
STEWARD_PGLITE_MEMORY=true bun run packages/api/src/embedded.ts
```

---

## SDK Usage

```bash
npm install @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const client = new StewardClient({
  baseUrl: "http://localhost:3200",
  apiKey: "your-tenant-key",
  tenantId: "my-platform",
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

if ("txHash" in result) {
  console.log("Broadcast:", result.txHash);
} else {
  // result.status === 'pending_approval' — queued for human review
}

// Route API calls through the proxy (credential injected automatically)
const openai = new OpenAI({
  baseURL: "http://steward-proxy:8080/openai/v1",
  apiKey: "steward", // dummy — replaced by proxy
});
```

---

## Embeddable React Components

```bash
npm install @stwd/react @stwd/sdk
```

```tsx
import { StewardProvider, WalletOverview, PolicyControls, ApprovalQueue } from "@stwd/react";
import "@stwd/react/styles.css";

function AgentDashboard({ client, agentId }) {
  return (
    <StewardProvider client={client} agentId={agentId}>
      <WalletOverview showQR />
      <PolicyControls />
      <ApprovalQueue />
    </StewardProvider>
  );
}
```

Components: `WalletOverview`, `TransactionHistory`, `PolicyControls`, `ApprovalQueue`, `SpendDashboard`.
All built on public hooks: `useWallet`, `useTransactions`, `usePolicies`, `useApprovals`, `useSpend`.

---

## Policy Types

| Type | What it does |
|------|-------------|
| `spending-limit` | Per-tx, daily, weekly caps |
| `approved-addresses` | Whitelist or blocklist destination addresses |
| `rate-limit` | Max transactions per hour / per day |
| `time-window` | Only allow transactions during defined UTC hours/days |
| `auto-approve-threshold` | Auto-sign small transactions; queue large ones for human review |
| `api-access` | Control which APIs agents can call through the proxy |

Policies are composable. Hard policies reject on failure. `auto-approve-threshold` is the only soft gate — failure queues instead of rejects.

---

## Webhook Events

Configure a webhook URL on your tenant and Steward will POST on every state change:

| Event | When |
|-------|------|
| `tx.pending` | Transaction queued for manual approval |
| `tx.approved` | Pending transaction approved by a human |
| `tx.denied` | Pending transaction denied |
| `tx.signed` | Transaction signed (and optionally broadcast) |
| `spend.threshold` | Spend tracking threshold crossed |
| `policy.violation` | Hard policy rejected a transaction |

Each delivery is signed with `X-Steward-Signature` (HMAC-SHA256). Configurable retries with exponential backoff.

---

## Packages

Bun monorepo managed with [Turborepo](https://turbo.build).

| Package | Description | Status |
|---------|-------------|--------|
| `@stwd/api` | REST API (30+ endpoints) | ✅ Production |
| `@stwd/proxy` | API proxy gateway with credential injection | ✅ Production |
| `@stwd/vault` | Wallet + secret encryption | ✅ Production |
| `@stwd/policy-engine` | Composable policy evaluation | ✅ Production |
| `@stwd/sdk` | TypeScript SDK (zero deps) | ✅ Published v0.3.0 |
| `@stwd/react` | Embeddable React UI components | ✅ Published v0.1.0 |
| `@stwd/eliza-plugin` | ElizaOS integration | ✅ Published v0.2.1 |
| `@stwd/redis` | Rate limiting + spend tracking via Redis | ✅ Production |
| `@stwd/webhooks` | Event delivery with retries | ✅ Production |
| `@stwd/db` | Schema + migrations + PGLite adapter | ✅ Production |
| `@stwd/shared` | Types + constants | ✅ Production |
| `web` | Dashboard + landing | ✅ Deployed |

---

## Supported Chains

Ethereum · Base · BSC · Polygon · Arbitrum · Base Sepolia · BSC Testnet · Solana

---

## Running the E2E Test Suite

```bash
# Against a live node
STEWARD_URL=http://localhost:3200 bun run scripts/e2e-integration-test.ts

# Against production (with real platform key)
STEWARD_URL=https://api.steward.fi bun run scripts/e2e-integration-test.ts
```

Covers: tenant + agent provisioning, wallet ops, policy enforcement, proxy + credential injection, Redis rate limits, secrets CRUD + rotation, cascading cleanup.

---

## Links

- **Website:** [steward.fi](https://steward.fi)
- **Docs:** [docs.steward.fi](https://docs.steward.fi)
- **API:** [api.steward.fi](https://api.steward.fi)
- **npm:** [@stwd/sdk](https://www.npmjs.com/package/@stwd/sdk) · [@stwd/react](https://www.npmjs.com/package/@stwd/react) · [@stwd/eliza-plugin](https://www.npmjs.com/package/@stwd/eliza-plugin)

---

## License

[MIT](LICENSE)

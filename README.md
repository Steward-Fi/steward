# Steward

**Agent wallet infrastructure with policy enforcement.**

AI agents need to spend money. Giving them raw private keys is insane — no limits, no oversight, no kill switch. Steward sits between the agent and its wallet, enforcing policies you define.

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Base](https://img.shields.io/badge/chain-Base-0052ff.svg)](https://base.org)
[![API](https://img.shields.io/badge/API-live-brightgreen)](https://api.steward.fi)
[![X](https://img.shields.io/badge/X-@Steward__Fi-black)](https://x.com/Steward_Fi)
[![Website](https://img.shields.io/badge/website-steward.fi-blue)](https://steward.fi)

---

## How It Works

```
Agent/Platform  →  Steward SDK  →  Policy Engine  →  Vault (AES-256-GCM)  →  Chain
                                        ↓
                                  Approval Queue  →  Dashboard / Webhook
```

1. Agent requests a transaction through the Steward SDK
2. Policy engine evaluates the request — spending limits, approved addresses, rate limits, time windows, auto-approve thresholds
3. **All hard policies pass** → signed and broadcast immediately
4. **Soft policy fails** (auto-approve threshold) → queued for human approval
5. **Hard policy fails** → rejected immediately, webhook fired

---

## Quick Start

```bash
git clone https://github.com/Steward-Fi/steward
cd steward
cp .env.example .env  # edit with your postgres URL + master password
docker compose up -d
```

The API is now running at `http://localhost:3200`.

---

## SDK Usage

```bash
npm install @stwd/sdk
# or: bun add @stwd/sdk
```

```typescript
import { StewardClient } from '@stwd/sdk';

const steward = new StewardClient({
  baseUrl: 'http://localhost:3200',
  tenantId: 'my-platform',
  apiKey: 'my-key',
});

// Create a wallet for an agent
const agent = await steward.createWallet('agent-1', 'Trading Bot');
console.log(agent.walletAddress); // 0x...

// Set policies
await steward.setPolicies(agent.id, [
  {
    id: 'limit',
    type: 'spending-limit',
    enabled: true,
    config: {
      maxPerTx:   '100000000000000000',  // 0.1 ETH
      maxPerDay:  '1000000000000000000', // 1 ETH
      maxPerWeek: '5000000000000000000', // 5 ETH
    },
  },
  {
    id: 'addrs',
    type: 'approved-addresses',
    enabled: true,
    config: { mode: 'whitelist', addresses: ['0xDEX...'] },
  },
]);

// Sign a transaction — returns txHash or queues for approval
const result = await steward.signTransaction(agent.id, {
  to: '0xDEX...',
  value: '50000000000000000', // 0.05 ETH
  chainId: 8453,              // Base
});

if ('txHash' in result) {
  console.log('Signed:', result.txHash);
} else {
  console.log('Queued for approval:', result.status); // 'pending_approval'
}
```

---

## Policy Types

| Type | What it does |
|------|-------------|
| `spending-limit` | Cap per transaction, per day, per week (wei) |
| `approved-addresses` | Whitelist or blocklist destination addresses |
| `rate-limit` | Max transactions per hour / per day |
| `time-window` | Only allow transactions during defined UTC hours |
| `auto-approve-threshold` | Auto-sign below threshold; queue above for human review |

Policies are composable — mix and match. Hard policies (all except `auto-approve-threshold`) reject immediately on failure. The auto-approve threshold is the only soft gate; failure queues instead of rejects.

---

## Webhook Events

Configure a webhook URL on your tenant and Steward will POST on every state change:

| Event | When |
|-------|------|
| `approval_required` | Transaction queued for manual review |
| `tx_signed` | Transaction signed and broadcast |
| `tx_rejected` | Transaction rejected by a hard policy |
| `tx_failed` | Transaction failed on-chain |

```json
{
  "type": "approval_required",
  "tenantId": "my-platform",
  "agentId": "agent-1",
  "data": {
    "txId": "...",
    "to": "0x...",
    "value": "50000000000000000",
    "policyResults": [...]
  },
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

---

## Live Demo

- **Dashboard:** https://steward.fi/dashboard
- **API:** https://api.steward.fi
- **On-chain proof:** https://basescan.org/tx/0x8d7592b93cad0983b481451c6d0c05900a1c6d74ee7eadbcdc7533a77ae45dc0

---

## Packages

This is a Bun monorepo managed with [Turborepo](https://turbo.build).

| Package | Description |
|---------|-------------|
| [`@stwd/api`](packages/api) | Hono REST API — agents, policies, approvals, signing |
| [`@stwd/vault`](packages/vault) | AES-256-GCM encrypted keystore + transaction signing via viem |
| [`@stwd/policy-engine`](packages/policy-engine) | Composable policy evaluation engine |
| [`@stwd/sdk`](packages/sdk) | TypeScript HTTP client for agents and integrations (`npm i @stwd/sdk`) |
| [`@stwd/db`](packages/db) | Drizzle ORM schema, migrations, and Postgres client |
| [`@stwd/auth`](packages/auth) | Timing-safe API key validation and tenant middleware |
| [`@stwd/webhooks`](packages/webhooks) | Webhook dispatch and retry queue |
| [`@stwd/shared`](packages/shared) | Shared types, interfaces, and constants |
| `web` | Next.js landing page and dashboard at steward.fi |

---

## Development

```bash
# Install all dependencies
bun install

# Copy env and fill in values
cp .env.example .env

# Start everything (API + Postgres via Docker, web in dev mode)
bun run dev
```

Environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `STEWARD_MASTER_PASSWORD` | ✅ | 256-bit hex secret for vault encryption |
| `PORT` | — | API port (default: 3200) |
| `RPC_URL` | — | EVM RPC endpoint (default: Base mainnet) |
| `CHAIN_ID` | — | Chain ID (default: 8453) |
| `STEWARD_DEFAULT_TENANT_KEY` | — | Dev API key for the default tenant |

---

## Architecture

The vault encrypts each agent's private key with `AES-256-GCM` using a key derived from the master password + agent ID. Keys never exist in plaintext outside of a signing operation. All signing happens in-process; the raw key is never sent over the wire.

Policy evaluation is stateless and synchronous. The engine receives the transaction request plus pre-fetched spend/rate context, evaluates all enabled rules, and returns an `EvaluationResult` with per-policy pass/fail details.

---

## License

[MIT](LICENSE)

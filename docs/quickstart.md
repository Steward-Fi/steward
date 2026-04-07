# Quickstart

Get Steward running locally in under 5 minutes using embedded mode (no external database required).

## Prerequisites

- [Bun](https://bun.sh) v1.0+
- Node 20+ (for type-checking tools)
- Git

## 1. Clone and Install

```bash
git clone https://github.com/your-org/steward-fi
cd steward-fi
bun install
```

## 2. Set a Master Password

Steward uses a single master password to derive encryption keys for every agent wallet. In embedded/local mode, you can set it inline or via `.env`.

```bash
export STEWARD_MASTER_PASSWORD="your-secret-password-here"
```

For development you can also copy and edit the example env:

```bash
cp .env.example .env
# Edit .env and set STEWARD_MASTER_PASSWORD
```

> **Keep this password safe.** Every private key in the vault is derived from it. There is no recovery path if it is lost.

## 3. Start the Server (Embedded Mode)

Embedded mode uses PGLite — a Postgres-compatible database that runs entirely in memory (or on disk). No Postgres installation required.

```bash
bun run start:local
```

The API starts on `http://localhost:3200`. You should see:

```
✅ Steward API running on port 3200 (embedded/PGLite mode)
```

To persist data between restarts, set a data directory:

```bash
PGLITE_DATA_DIR=~/.steward/data bun run start:local
```

## 4. Create a Tenant

Tenants are the top-level isolation unit. Each tenant has its own API key, agents, and policies.

```bash
curl -s -X POST http://localhost:3200/tenants \
  -H "Content-Type: application/json" \
  -d '{
    "id": "my-app",
    "name": "My App",
    "apiKeyHash": "my-dev-api-key-plain"
  }' | jq
```

Response:

```json
{
  "ok": true,
  "data": {
    "id": "my-app",
    "name": "My App",
    "createdAt": "2026-04-06T00:00:00.000Z"
  }
}
```

> In the `POST /tenants` request, you can pass a raw string as `apiKeyHash` — the API will hash it for you if it doesn't look like a pre-hashed value (64 hex chars). For production you should pre-hash using PBKDF2.

## 5. Create an Agent

```bash
curl -s -X POST http://localhost:3200/agents \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: my-app" \
  -H "X-Steward-Key: my-dev-api-key-plain" \
  -d '{
    "id": "trading-bot",
    "name": "Trading Bot"
  }' | jq
```

Response:

```json
{
  "ok": true,
  "data": {
    "id": "trading-bot",
    "name": "Trading Bot",
    "tenantId": "my-app",
    "walletAddress": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
    "walletAddresses": {
      "evm": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
      "solana": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
    },
    "createdAt": "2026-04-06T00:00:00.000Z"
  }
}
```

Steward automatically generates AES-256-GCM encrypted EVM and Solana keypairs. Private keys are never returned.

## 6. Set Policies

Steward uses **default-deny** — without policies, all signing requests are rejected. Set policies before trying to sign.

```bash
curl -s -X PUT http://localhost:3200/agents/trading-bot/policies \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: my-app" \
  -H "X-Steward-Key: my-dev-api-key-plain" \
  -d '[
    {
      "id": "spend-limit",
      "type": "spending-limit",
      "enabled": true,
      "config": {
        "maxPerTx": "100000000000000000",
        "maxPerDay": "500000000000000000"
      }
    },
    {
      "id": "auto-approve",
      "type": "auto-approve-threshold",
      "enabled": true,
      "config": {
        "threshold": "50000000000000000"
      }
    }
  ]' | jq
```

## 7. Sign a Transaction

```bash
curl -s -X POST http://localhost:3200/vault/trading-bot/sign \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: my-app" \
  -H "X-Steward-Key: my-dev-api-key-plain" \
  -d '{
    "to": "0xRecipientAddress",
    "value": "10000000000000000",
    "chainId": 84532,
    "broadcast": false
  }' | jq
```

If the transaction passes all policies, you get back a signed tx:

```json
{
  "ok": true,
  "data": {
    "signedTx": "0x02f8...",
    "caip2": "eip155:84532"
  }
}
```

If the value exceeds the auto-approve threshold, you get a `202 pending_approval` response instead:

```json
{
  "ok": false,
  "status": "pending_approval",
  "results": [
    {
      "policyId": "auto-approve",
      "type": "auto-approve-threshold",
      "passed": false,
      "reason": "Value 100000000000000000 exceeds auto-approve threshold 50000000000000000"
    }
  ]
}
```

## 8. Sign a Message

```bash
curl -s -X POST http://localhost:3200/vault/trading-bot/sign-message \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: my-app" \
  -H "X-Steward-Key: my-dev-api-key-plain" \
  -d '{
    "message": "Hello from Steward"
  }' | jq
```

Response:

```json
{
  "ok": true,
  "data": {
    "signature": "0x..."
  }
}
```

## 9. Using the TypeScript SDK

Instead of raw curl, install the SDK:

```bash
npm install @stwd/sdk
# or
bun add @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const steward = new StewardClient({
  baseUrl: "http://localhost:3200",
  apiKey: "my-dev-api-key-plain",
  tenantId: "my-app",
});

// Create an agent
const agent = await steward.createWallet("my-agent", "My Agent");
console.log(agent.walletAddresses); // { evm: "0x...", solana: "..." }

// Set policies
await steward.setPolicies("my-agent", [
  {
    id: "spend-limit",
    type: "spending-limit",
    enabled: true,
    config: { maxPerTx: "100000000000000000" },
  },
]);

// Sign a transaction
const result = await steward.signTransaction("my-agent", {
  to: "0xRecipient",
  value: "10000000000000000",
  chainId: 84532,
  broadcast: false,
});

if ("signedTx" in result) {
  console.log("Signed:", result.signedTx);
} else if (result.status === "pending_approval") {
  console.log("Queued for approval");
}
```

## Next Steps

- [Architecture](./architecture.md) — Understand the two-mode design and package layout
- [Authentication](./auth.md) — Add user login (passkeys, magic links, SIWE)
- [Policy Engine](./policies.md) — Full policy reference and use-case examples
- [Deployment](./deployment.md) — Run Steward in production with Docker

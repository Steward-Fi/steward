# Milady & Waifu.fun Integration Guide

> How milady-cloud and waifu.fun integrate with Steward for autonomous agent wallet management.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        milady-cloud                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
│  │  Agent A  │  │  Agent B  │  │  Agent C  │  │  Agent D  │          │
│  │ (trader)  │  │(launcher) │  │ (farmer)  │  │ (manual)  │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘           │
│       │              │              │              │                 │
│       └──────────────┼──────────────┼──────────────┘                │
│                      │              │                                │
│               ┌──────▼──────────────▼──────┐                        │
│               │     @stwd/sdk (client)      │                        │
│               └────────────┬───────────────┘                        │
└────────────────────────────┼────────────────────────────────────────┘
                             │  HTTPS  (X-Steward-Tenant / X-Steward-Key)
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                      Steward API                                    │
│                                                                     │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  Hono API   │  │ PolicyEngine │  │   Webhooks    │              │
│  │  (REST)     │  │  (evaluate)  │  │ (dispatcher)  │              │
│  └─────┬──────┘  └──────┬───────┘  └──────┬───────┘               │
│        │                │                  │                        │
│  ┌─────▼────────────────▼──────────────────▼───────┐               │
│  │                    Vault                         │               │
│  │  ┌─────────┐  ┌───────────┐  ┌──────────────┐  │               │
│  │  │ KeyStore │  │  Signing   │  │  Balance     │  │               │
│  │  │(encrypt) │  │(decrypt →  │  │  (viem RPC)  │  │               │
│  │  │          │  │ sign → wipe│  │              │  │               │
│  │  └─────────┘  └───────────┘  └──────────────┘  │               │
│  └─────────────────────────────────────────────────┘               │
│                                                                     │
│  ┌─────────────────────────────────────────────────┐               │
│  │              PostgreSQL (Drizzle ORM)            │               │
│  │  agents │ encrypted_keys │ policies │ transactions│              │
│  └─────────────────────────────────────────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
                             │
                             │  Webhooks (POST)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     waifu.fun / milady-cloud                        │
│                     Webhook Receiver                                │
│  Events: tx_signed │ tx_rejected │ approval_required │ tx_failed   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 1. How milady-cloud Integrates Steward

### Agent Provisioning

Every milady agent receives a Steward-managed wallet when provisioned. The wallet's private key is encrypted at rest and never exposed to the agent container.

```typescript
import { StewardClient } from "@stwd/sdk";

const steward = new StewardClient({
  baseUrl: "https://api.steward.fi",
  apiKey: "stw_your_tenant_key",
  tenantId: "milady-cloud",
});

// Called during agent lifecycle bootstrap
async function provisionMiladyAgent(agentId: string, name: string) {
  // 1. Create wallet
  const agent = await steward.createWallet(agentId, name, `milady:${agentId}`);
  console.log(`Wallet created: ${agent.walletAddress}`);

  // 2. Apply policy template based on agent type
  const policies = getPolicyTemplate("trader"); // or "launcher", "farmer"
  await steward.setPolicies(agentId, policies);

  return agent;
}
```

### Policy Templates by Agent Type

#### Trader Agent
Moderate limits, whitelisted DEX contracts, rate limiting.

```typescript
import { parseEther } from "viem";
import type { PolicyRule } from "@stwd/sdk";

function traderPolicies(dexRouter: string): PolicyRule[] {
  return [
    {
      id: "trader-spend",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("0.5").toString(),
        maxPerDay: parseEther("5.0").toString(),
        maxPerWeek: parseEther("20.0").toString(),
      },
    },
    {
      id: "trader-addresses",
      type: "approved-addresses",
      enabled: true,
      config: {
        mode: "whitelist",
        addresses: [dexRouter],
      },
    },
    {
      id: "trader-rate",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 10,
        maxTxPerDay: 50,
      },
    },
    {
      id: "trader-auto",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("0.05").toString(),
      },
    },
  ];
}
```

#### Launcher Agent
Stricter limits — only interacts with factory contracts.

```typescript
function launcherPolicies(factoryAddress: string): PolicyRule[] {
  return [
    {
      id: "launcher-spend",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("1.0").toString(),
        maxPerDay: parseEther("2.0").toString(),
        maxPerWeek: parseEther("5.0").toString(),
      },
    },
    {
      id: "launcher-addresses",
      type: "approved-addresses",
      enabled: true,
      config: {
        mode: "whitelist",
        addresses: [factoryAddress],
      },
    },
    {
      id: "launcher-rate",
      type: "rate-limit",
      enabled: true,
      config: {
        maxTxPerHour: 2,
        maxTxPerDay: 5,
      },
    },
  ];
}
```

#### Farmer Agent
Conservative — small automated txs, time-windowed, low rate.

```typescript
function farmerPolicies(vaultAddresses: string[]): PolicyRule[] {
  return [
    {
      id: "farmer-spend",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: parseEther("0.1").toString(),
        maxPerDay: parseEther("0.5").toString(),
        maxPerWeek: parseEther("2.0").toString(),
      },
    },
    {
      id: "farmer-addresses",
      type: "approved-addresses",
      enabled: true,
      config: {
        mode: "whitelist",
        addresses: vaultAddresses,
      },
    },
    {
      id: "farmer-time",
      type: "time-window",
      enabled: true,
      config: {
        allowedHours: [{ start: 0, end: 24 }], // 24/7 for yield farming
        allowedDays: [0, 1, 2, 3, 4, 5, 6],
      },
    },
    {
      id: "farmer-auto",
      type: "auto-approve-threshold",
      enabled: true,
      config: {
        threshold: parseEther("0.01").toString(),
      },
    },
  ];
}
```

### Webhook Integration

Register a webhook URL to receive real-time notifications for all agent activity:

```typescript
// Register webhook during tenant setup
await fetch("https://api.steward.fi/tenants/milady-cloud/webhook", {
  method: "PUT",
  headers: {
    "Content-Type": "application/json",
    "X-Steward-Tenant": "milady-cloud",
    "X-Steward-Key": "stw_your_key",
  },
  body: JSON.stringify({
    webhookUrl: "https://milady-cloud.example.com/steward/webhooks",
  }),
});
```

Handle incoming events:

```typescript
// Express/Hono webhook receiver
app.post("/steward/webhooks", async (req, res) => {
  const event = req.body; // WebhookEvent

  switch (event.type) {
    case "tx_signed":
      console.log(`✅ Agent ${event.agentId} tx signed: ${event.data.txHash}`);
      // Update agent dashboard, log trade
      break;

    case "approval_required":
      console.log(`⏳ Agent ${event.agentId} needs approval: ${event.data.txId}`);
      // Notify operator, send to approval UI
      break;

    case "tx_rejected":
      console.log(`🚫 Agent ${event.agentId} tx rejected by policy`);
      // Alert operator, potentially adjust policies
      break;

    case "tx_failed":
      console.error(`❌ Agent ${event.agentId} tx failed: ${event.data.error}`);
      // Alert, retry logic, circuit breaker
      break;
  }

  res.json({ ok: true });
});
```

---

## 2. How waifu.fun Uses Steward

waifu.fun uses the `WaifuBridge` service built into the Steward API. This service is specifically designed for waifu.fun's agent token launchpad on BSC.

### WaifuBridge Provisioning Flow

```
  waifu.fun backend                    Steward API
       │                                    │
       │  POST /agents                      │
       │  { id: "waifu-agent-42",           │
       │    name: "Milady Trader",          │
       │    platformId: "waifu.fun:42" }    │
       │ ──────────────────────────────────►│
       │                                    │ ── createAgent()
       │                                    │ ── generate keypair
       │                                    │ ── encrypt & store
       │                                    │ ── apply default policies:
       │                                    │      spending-limit (0.1 BNB/tx)
       │                                    │      approved-addresses (portal)
       │                                    │      rate-limit (6/hr, 24/day)
       │                                    │      auto-approve (<0.01 BNB)
       │  ◄──────────────────────────────── │
       │  { ok: true, data: {               │
       │    id: "waifu-agent-42",           │
       │    walletAddress: "0x...",          │
       │    ...                             │
       │  }}                                │
       │                                    │
```

### Default Policies

The WaifuBridge automatically applies these policies:

| Policy | Type | Config |
|--------|------|--------|
| `waifu-spend` | `spending-limit` | 0.1 BNB/tx, 1 BNB/day, 5 BNB/week |
| `waifu-approved` | `approved-addresses` | Whitelist: portal contract |
| `waifu-rate` | `rate-limit` | 6 tx/hour, 24 tx/day |
| `waifu-auto` | `auto-approve-threshold` | Auto-approve below 0.01 BNB |

### Balance Tracking

```typescript
// Sync agent balance on BSC
const balance = await waifuBridge.syncAgentBalance("waifu-agent-42");
// {
//   agentId: "waifu-agent-42",
//   walletAddress: "0x...",
//   balances: {
//     native: "1000000000000000000",  // 1 BNB in wei
//     nativeFormatted: "1.0",
//     chainId: 56,
//     symbol: "BNB",
//   }
// }

// For BSC Testnet
const testBalance = await waifuBridge.syncAgentBalance("waifu-agent-42", 97);
```

---

## 3. SDK Usage Examples

### Installation

```bash
npm install @stwd/sdk
# or
bun add @stwd/sdk
```

### Creating a Wallet for a New Agent

```typescript
import { StewardClient } from "@stwd/sdk";

const client = new StewardClient({
  baseUrl: "https://api.steward.fi",
  apiKey: "stw_your_api_key",
  tenantId: "your-tenant-id",
});

// Single agent
const agent = await client.createWallet(
  "agent-001",           // unique agent ID
  "My Trading Agent",    // display name
  "myplatform:001"       // optional platform identifier
);

console.log(agent.walletAddress); // "0x..."
console.log(agent.id);            // "agent-001"
console.log(agent.createdAt);     // Date object

// Batch creation (up to N agents in one call)
const result = await client.createWalletBatch(
  [
    { id: "agent-a", name: "Alpha Trader" },
    { id: "agent-b", name: "Beta Farmer" },
    { id: "agent-c", name: "Gamma Launcher" },
  ],
  traderPolicies("0xDEXRouterAddress") // optional: apply same policies to all
);

console.log(`Created: ${result.created.length}`);
console.log(`Errors: ${result.errors.length}`);
```

### Setting Policies

```typescript
import type { PolicyRule } from "@stwd/sdk";

// Read current policies
const current = await client.getPolicies("agent-001");
console.log(`Agent has ${current.length} policies`);

// Replace policies
await client.setPolicies("agent-001", [
  {
    id: "spend-limit",
    type: "spending-limit",
    enabled: true,
    config: {
      maxPerTx: "100000000000000000",   // 0.1 ETH
      maxPerDay: "1000000000000000000",  // 1 ETH
      maxPerWeek: "5000000000000000000", // 5 ETH
    },
  },
  {
    id: "approved-contracts",
    type: "approved-addresses",
    enabled: true,
    config: {
      mode: "whitelist",
      addresses: [
        "0x1234...DEXRouter",
        "0x5678...StakingVault",
      ],
    },
  },
]);
```

### Signing a Transaction

```typescript
const result = await client.signTransaction("agent-001", {
  to: "0xDEXRouterAddress",
  value: "50000000000000000", // 0.05 ETH
  data: "0x...",              // encoded calldata
  chainId: 8453,              // Base mainnet
});

if ("txHash" in result) {
  // Transaction was signed and broadcast
  console.log(`TX hash: ${result.txHash}`);
} else if (result.status === "pending_approval") {
  // Needs human approval (exceeds auto-approve threshold)
  console.log("Awaiting approval — check webhook for resolution");
  console.log("Policy results:", result.results);
}
```

### Handling Approval Webhooks

```typescript
import { createWebhookServer, registerDefaultHandlers } from "@stwd/agent-trader";

// Or build your own receiver:
app.post("/webhooks/steward", async (req, res) => {
  const event = req.body;

  switch (event.type) {
    case "approval_required": {
      const { txId, results } = event.data;
      // Show in operator dashboard, send Telegram alert, etc.
      // To approve:
      await fetch(`https://api.steward.fi/vault/${event.agentId}/approve/${txId}`, {
        method: "POST",
        headers: {
          "X-Steward-Tenant": "your-tenant",
          "X-Steward-Key": "stw_your_key",
        },
      });
      break;
    }

    case "tx_signed":
      // Track in your database
      break;

    case "tx_failed":
      // Alert + retry logic
      break;

    case "tx_rejected":
      // Log policy violation
      break;
  }

  return res.json({ ok: true });
});
```

### Checking Balance

```typescript
const balance = await client.getBalance("agent-001");
console.log(`${balance.balances.nativeFormatted} ${balance.balances.symbol}`);

// Query a specific chain
const bscBalance = await client.getBalance("agent-001", 56);
```

### Listing Agents

```typescript
const agents = await client.listAgents();
for (const agent of agents) {
  console.log(`${agent.id}: ${agent.walletAddress} (created ${agent.createdAt.toISOString()})`);
}
```

---

## 4. Supported Chains

| Chain | ID | Symbol | RPC |
|-------|----|--------|-----|
| Base | 8453 | ETH | `https://mainnet.base.org` |
| Base Sepolia | 84532 | ETH | `https://sepolia.base.org` |
| BSC | 56 | BNB | `https://bsc-dataseed.binance.org` |
| BSC Testnet | 97 | tBNB | `https://data-seed-prebsc-1-s1.bnbchain.org:8545` |

---

## 5. Policy Types Reference

| Type | Description | Config Fields |
|------|-------------|---------------|
| `spending-limit` | Caps per-tx, daily, and weekly spend | `maxPerTx`, `maxPerDay`, `maxPerWeek` (wei strings) |
| `approved-addresses` | Whitelist/blacklist of target addresses | `mode` ("whitelist" / "blacklist"), `addresses` (string[]) |
| `auto-approve-threshold` | Auto-approve txs below a value | `threshold` (wei string) |
| `time-window` | Restrict trading to specific hours/days | `allowedHours` ([{start, end}]), `allowedDays` (number[]) |
| `rate-limit` | Cap transaction frequency | `maxTxPerHour`, `maxTxPerDay` (numbers) |

---

## 6. Error Handling

The SDK throws `StewardApiError` for all API failures:

```typescript
import { StewardApiError } from "@stwd/sdk";

try {
  await client.signTransaction("agent-001", txInput);
} catch (err) {
  if (err instanceof StewardApiError) {
    switch (err.status) {
      case 400: // Bad input
        console.error("Invalid request:", err.message);
        break;
      case 403: // Policy rejection
        console.error("Rejected by policy:", err.data?.results);
        break;
      case 404: // Agent not found
        console.error("Agent not found");
        break;
      case 429: // Rate limited
        console.error("Rate limited — retry later");
        break;
      default:
        console.error(`API error (${err.status}):`, err.message);
    }
  }
}
```

---

## 7. Security Considerations

1. **Private keys are never exposed** — keys are encrypted with AES-256-GCM using the master password and only decrypted in-memory for signing.
2. **Tenant isolation** — each tenant's agents are scoped; one tenant cannot access another's wallets.
3. **API key auth** — all authenticated endpoints require `X-Steward-Key` header.
4. **Rate limiting** — 100 requests/minute per IP at the API level, plus per-agent rate limits via policies.
5. **Policy engine** — every transaction is evaluated against the agent's policy set before signing.
6. **Webhook notifications** — operators are notified of all transaction events for monitoring.

# Replacing Privy with Steward in Eliza Cloud

## Implementation Plan

**Author:** Sol (generated from codebase analysis)
**Date:** 2026-03-20
**Status:** Draft

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current Privy Integration Map](#2-current-privy-integration-map)
3. [API Mapping: Privy → Steward](#3-api-mapping-privy--steward)
4. [Database Migration](#4-database-migration)
5. [Key Migration](#5-key-migration)
6. [Steward Deployment for Cloud](#6-steward-deployment-for-cloud)
7. [Auth Flow Changes](#7-auth-flow-changes)
8. [Feature Parity + Improvements](#8-feature-parity--improvements)
9. [Phased Rollout](#9-phased-rollout)
10. [Risk Assessment](#10-risk-assessment)

---

## 1. Executive Summary

Eliza Cloud currently uses Privy for two distinct functions:

1. **User Authentication** — Privy OAuth/email/wallet login → `privy-token` cookie → session management
2. **Server-Managed Agent Wallets** — `walletApi.create()` / `walletApi.rpc()` for agent transaction signing

Steward replaces **function #2** completely (agent wallet management) and can optionally replace parts of **function #1** (wallet-based auth via SIWE). The Privy auth system (OAuth, email login, social accounts) is a separate concern and may remain or be replaced independently.

### Why Replace Privy

| Concern | Privy | Steward |
|---------|-------|---------|
| Key custody | Privy HSM (opaque) | Self-hosted AES-256-GCM vault |
| Availability | Dependent on Privy uptime | Self-hosted, fully controlled |
| Pricing | Per-wallet/API call fees | Zero marginal cost |
| Policy enforcement | None | Spending limits, rate limits, approved addresses, time windows |
| Manual approval | Not available | Built-in approval queue |
| Transaction audit | Limited | Full tx history with policy evaluation records |
| Multi-chain | EVM + Solana | EVM (7 chains) + Solana |
| Customization | Closed source | Open source, fully extensible |

---

## 2. Current Privy Integration Map

### 2.1 Files Touching Privy

#### Core Wallet Service
| File | Purpose | Privy Dependency |
|------|---------|------------------|
| `packages/lib/services/server-wallets.ts` | Wallet provisioning + RPC execution | `walletApi.create()`, `walletApi.rpc()` |
| `packages/db/schemas/agent-server-wallets.ts` | DB schema | `privy_wallet_id` column |
| `app/api/v1/user/wallets/provision/route.ts` | REST endpoint for wallet creation | Calls `provisionServerWallet()` |
| `app/api/v1/user/wallets/rpc/route.ts` | REST endpoint for RPC proxy | Calls `executeServerWalletRpc()` |

#### Authentication (Privy OAuth/Session)
| File | Purpose | Privy Dependency |
|------|---------|------------------|
| `packages/lib/auth/privy-client.ts` | Singleton Privy client + cached token verification | `PrivyClient`, `verifyAuthToken()`, `walletApi` |
| `packages/lib/auth.ts` | Central auth module | `verifyAuthTokenCached()`, `privy-token` cookie |
| `packages/lib/privy-sync.ts` | Sync Privy users to local DB | `syncUserFromPrivy()` — full user lifecycle |
| `packages/lib/auth/wallet-auth.ts` | Per-request wallet signature auth | Independent of Privy (uses viem `verifyMessage`) |
| `packages/lib/auth/waifu-bridge.ts` | Service JWT auth for waifu-core | Independent of Privy |

#### Supporting Files
| File | Purpose |
|------|---------|
| `packages/db/schemas/users.ts` | `privy_user_id` column on users table |
| `packages/db/schemas/user-identities.ts` | Privy identity projection table |
| `packages/db/repositories/users.ts` | `getByPrivyId()` queries |
| `packages/lib/eliza/user-context.ts` | User context resolution |
| `packages/lib/config/env-validator.ts` | Validates `NEXT_PUBLIC_PRIVY_APP_ID`, `PRIVY_APP_SECRET` |
| `next.config.ts` | Privy package transpilation |

### 2.2 Privy API Calls (Exhaustive)

1. **`privy.walletApi.create({ chainType })`** — Creates a server-managed wallet (EVM or Solana). Returns `{ id, address }`.
2. **`privy.walletApi.rpc({ walletId, method, params })`** — Sends an RPC request signed by the Privy-managed key.
3. **`privy.verifyAuthToken(token)`** — Validates a Privy JWT from `privy-token` cookie.
4. **`privy.getUser(idToken)` / `privy.getUser(userId)`** — Fetches full Privy user profile for JIT sync.

### 2.3 Data Flow: Agent Wallet Provisioning

```
Client (agent runtime)
  → POST /api/v1/user/wallets/provision
    → requireAuthOrApiKey(request)                    # Privy session or API key
    → provisionServerWallet()
      → privy.walletApi.create({ chainType })         # ← PRIVY CALL
      → INSERT INTO agent_server_wallets (privy_wallet_id, address, ...)
    ← { id, address, chainType, clientAddress }
```

### 2.4 Data Flow: Agent RPC (Transaction Signing)

```
Client (agent runtime)
  → POST /api/v1/user/wallets/rpc
    → verifyWalletSignature(request)                  # wallet-header auth (NOT Privy)
    → executeServerWalletRpc()
      → verifyMessage (viem) — validate client signature
      → cache.setIfNotExists (nonce check)
      → SELECT FROM agent_server_wallets WHERE client_address = ?
      → privy.walletApi.rpc({ walletId, method, params })  # ← PRIVY CALL
    ← { result }
```

---

## 3. API Mapping: Privy → Steward

### 3.1 Wallet Creation

| Privy | Steward | Notes |
|-------|---------|-------|
| `privy.walletApi.create({ chainType: "ethereum" })` | `vault.createAgent(tenantId, agentId, name, platformId, "evm")` | Steward uses tenant/agent model. Returns `AgentIdentity` with `walletAddress`. |
| `privy.walletApi.create({ chainType: "solana" })` | `vault.createAgent(tenantId, agentId, name, platformId, "solana")` | Steward supports Solana via Ed25519 keypair generation. |
| Returns `{ id, address }` | Returns `{ id, tenantId, name, walletAddress, ... }` | Map `id` → `agentId`, `address` → `walletAddress`. |

**New `provisionServerWallet()` implementation:**

```typescript
async function provisionServerWallet(params: ProvisionWalletParams) {
  const steward = getStewardClient(); // or direct Vault instance
  const agentId = `cloud-${params.characterId || params.clientAddress}`;
  const tenantId = `org-${params.organizationId}`;

  const agent = await steward.createWallet(agentId, `Agent ${agentId}`, params.clientAddress);

  // Optionally apply default policies
  await steward.setPolicies(agentId, DEFAULT_CLOUD_AGENT_POLICIES);

  const [record] = await db.insert(agentServerWallets).values({
    organization_id: params.organizationId,
    user_id: params.userId,
    character_id: params.characterId,
    steward_agent_id: agent.id,          // was: privy_wallet_id
    steward_tenant_id: tenantId,         // NEW
    address: agent.walletAddress,
    chain_type: params.chainType,
    client_address: params.clientAddress,
  }).returning();

  return record;
}
```

### 3.2 Transaction Signing (RPC Proxy)

| Privy | Steward | Notes |
|-------|---------|-------|
| `privy.walletApi.rpc({ walletId, method, params })` | `vault.signTransaction(signRequest)` | Steward handles the full sign+broadcast flow. |
| Generic RPC passthrough | Structured `SignRequest` with policy evaluation | Steward evaluates policies before signing. |
| Returns raw RPC result | Returns `{ txId, txHash }` or `{ status: "pending_approval" }` | Richer response with tx tracking. |

**The Privy RPC proxy is a raw JSON-RPC passthrough** — it sends arbitrary `method`+`params` to Privy's walletApi. Steward's model is **structured sign requests** with `{ to, value, data, chainId }`. This is a significant API shape change.

**Translation layer needed:**

```typescript
async function executeServerWalletRpc(params: ExecuteParams) {
  // ... existing nonce/signature verification stays the same ...

  const walletRecord = await db.query.agentServerWallets.findFirst({
    where: eq(agentServerWallets.client_address, params.clientAddress),
  });

  const steward = getStewardClient();

  // Map RPC method to Steward operation
  switch (params.payload.method) {
    case 'eth_sendTransaction': {
      const [txParams] = params.payload.params as [{ to: string; value: string; data?: string }];
      return steward.signTransaction(walletRecord.steward_agent_id, {
        to: txParams.to,
        value: txParams.value || '0',
        data: txParams.data,
        chainId: walletRecord.chain_type === 'evm' ? 8453 : undefined,
      });
    }
    case 'personal_sign':
    case 'eth_sign': {
      const [message] = params.payload.params as [string];
      return steward.signMessage(walletRecord.steward_agent_id, message);
    }
    // ... other methods ...
    default:
      throw new Error(`Unsupported RPC method: ${params.payload.method}`);
  }
}
```

### 3.3 Message Signing

| Privy | Steward |
|-------|---------|
| `walletApi.rpc({ method: 'personal_sign', ... })` | `vault.signMessage(tenantId, agentId, message)` |

### 3.4 Balance Queries

| Privy | Steward |
|-------|---------|
| Not available (external RPC) | `vault.getBalance(tenantId, agentId, chainId)` — built-in, multi-chain |

### 3.5 Full API Mapping Table

| Privy API | Steward API | Steward SDK Method | HTTP Endpoint |
|-----------|-------------|--------------------|----|
| `walletApi.create()` | `vault.createAgent()` | `steward.createWallet()` | `POST /agents` |
| `walletApi.rpc()` (eth_sendTransaction) | `vault.signTransaction()` | `steward.signTransaction()` | `POST /vault/:agentId/sign` |
| `walletApi.rpc()` (personal_sign) | `vault.signMessage()` | `steward.signMessage()` | `POST /vault/:agentId/sign-message` |
| `walletApi.delete()` | Not yet implemented | — | — |
| N/A | `vault.getBalance()` | `steward.getBalance()` | `GET /agents/:agentId/balance` |
| N/A | Policy CRUD | `steward.setPolicies()` | `PUT /agents/:agentId/policies` |
| N/A | Approval queue | — | `POST /vault/:agentId/approve/:txId` |
| N/A | Transaction history | `steward.getHistory()` | `GET /vault/:agentId/history` |
| N/A | Batch agent creation | `steward.createWalletBatch()` | `POST /agents/batch` |

---

## 4. Database Migration

### 4.1 Current Schema: `agent_server_wallets`

```sql
CREATE TABLE agent_server_wallets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  character_id    UUID REFERENCES user_characters(id) ON DELETE SET NULL,
  privy_wallet_id TEXT NOT NULL,               -- ← TO BE REPLACED
  address         TEXT NOT NULL,
  chain_type      TEXT NOT NULL,
  client_address  TEXT NOT NULL UNIQUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 4.2 Target Schema

```sql
ALTER TABLE agent_server_wallets
  ADD COLUMN steward_agent_id   VARCHAR(128),
  ADD COLUMN steward_tenant_id  VARCHAR(64),
  ADD COLUMN wallet_provider    VARCHAR(16) NOT NULL DEFAULT 'privy';
  -- wallet_provider: 'privy' | 'steward'

-- Index for Steward lookups
CREATE INDEX agent_server_wallets_steward_agent_idx
  ON agent_server_wallets(steward_agent_id) WHERE steward_agent_id IS NOT NULL;

CREATE INDEX agent_server_wallets_provider_idx
  ON agent_server_wallets(wallet_provider);
```

### 4.3 Migration SQL (Phase 1 — Dual Provider)

```sql
-- Migration: Add Steward columns alongside Privy
BEGIN;

ALTER TABLE agent_server_wallets
  ADD COLUMN IF NOT EXISTS steward_agent_id  VARCHAR(128),
  ADD COLUMN IF NOT EXISTS steward_tenant_id VARCHAR(64),
  ADD COLUMN IF NOT EXISTS wallet_provider   VARCHAR(16) NOT NULL DEFAULT 'privy';

-- Make privy_wallet_id nullable (existing rows keep their values)
ALTER TABLE agent_server_wallets
  ALTER COLUMN privy_wallet_id DROP NOT NULL;

-- Constraint: exactly one provider ID must be set
ALTER TABLE agent_server_wallets
  ADD CONSTRAINT wallet_provider_id_check CHECK (
    (wallet_provider = 'privy'   AND privy_wallet_id IS NOT NULL) OR
    (wallet_provider = 'steward' AND steward_agent_id IS NOT NULL)
  );

CREATE INDEX IF NOT EXISTS agent_server_wallets_steward_agent_idx
  ON agent_server_wallets(steward_agent_id) WHERE steward_agent_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS agent_server_wallets_provider_idx
  ON agent_server_wallets(wallet_provider);

COMMIT;
```

### 4.4 Migration SQL (Phase 3 — Privy Fully Removed)

```sql
BEGIN;

-- Drop Privy-specific columns
ALTER TABLE agent_server_wallets DROP COLUMN privy_wallet_id;
ALTER TABLE agent_server_wallets DROP COLUMN wallet_provider;

-- Rename steward columns to be the primary
ALTER TABLE agent_server_wallets RENAME COLUMN steward_agent_id TO agent_id;
ALTER TABLE agent_server_wallets RENAME COLUMN steward_tenant_id TO tenant_id;

-- Make them NOT NULL
ALTER TABLE agent_server_wallets ALTER COLUMN agent_id SET NOT NULL;
ALTER TABLE agent_server_wallets ALTER COLUMN tenant_id SET NOT NULL;

-- Drop the check constraint
ALTER TABLE agent_server_wallets DROP CONSTRAINT IF EXISTS wallet_provider_id_check;

COMMIT;
```

### 4.5 Drizzle Schema Update (Phase 1)

```typescript
export const agentServerWallets = pgTable("agent_server_wallets", {
  id: uuid("id").defaultRandom().primaryKey(),
  organization_id: uuid("organization_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  user_id: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  character_id: uuid("character_id").references(() => userCharacters.id, { onDelete: "set null" }),

  // Provider routing
  wallet_provider: text("wallet_provider").notNull().default("privy"), // 'privy' | 'steward'

  // Privy (legacy — nullable after migration)
  privy_wallet_id: text("privy_wallet_id"),

  // Steward (new)
  steward_agent_id: text("steward_agent_id"),
  steward_tenant_id: text("steward_tenant_id"),

  // Common
  address: text("address").notNull(),
  chain_type: text("chain_type").notNull(),
  client_address: text("client_address").notNull().unique(),
  created_at: timestamp("created_at").notNull().defaultNow(),
  updated_at: timestamp("updated_at").notNull().defaultNow(),
});
```

---

## 5. Key Migration

### 5.1 Can We Export Keys from Privy?

**No.** Privy stores keys in their HSM (Hardware Security Module). The private keys never leave Privy's infrastructure. There is no API to export raw private keys.

### 5.2 Existing Agent Wallets

Existing cloud agents with Privy-managed wallets **cannot be migrated** to Steward with the same keypair. This means:

- **Existing agents keep their Privy wallets** during the transition period
- **New agents** get Steward wallets
- When an agent is "upgraded," it gets a **new Steward wallet** with a new address

### 5.3 Handling Agents with On-Chain History

For agents that have on-chain assets or history (NFTs, tokens, ENS names):

1. **Fund transfer:** The agent's old Privy wallet sends all assets to the new Steward wallet address. This can be automated via the existing RPC proxy.
2. **Address announcement:** If the agent has published its wallet address (on-chain identity, social profiles), the new address must be announced.
3. **Gradual migration:** Leave Privy wallets active for receiving funds during transition. The cloud service can monitor both addresses.

### 5.4 Migration Script Concept

```typescript
async function migrateAgentWallet(clientAddress: string) {
  // 1. Get existing Privy wallet record
  const existing = await db.query.agentServerWallets.findFirst({
    where: eq(agentServerWallets.client_address, clientAddress),
  });

  if (!existing || existing.wallet_provider !== 'privy') return;

  // 2. Create new Steward wallet
  const tenantId = `org-${existing.organization_id}`;
  const agentId = `cloud-${existing.character_id || existing.client_address}`;
  const agent = await steward.createWallet(agentId, `Migrated Agent ${agentId}`);

  // 3. Update record to dual-provider
  await db.update(agentServerWallets)
    .set({
      steward_agent_id: agent.id,
      steward_tenant_id: tenantId,
      // Keep privy_wallet_id for asset transfer
    })
    .where(eq(agentServerWallets.id, existing.id));

  // 4. Transfer assets (optional, can be triggered separately)
  // await transferAssets(existing.privy_wallet_id, agent.walletAddress);

  // 5. Switch provider
  await db.update(agentServerWallets)
    .set({ wallet_provider: 'steward' })
    .where(eq(agentServerWallets.id, existing.id));
}
```

---

## 6. Steward Deployment for Cloud

### 6.1 Architecture Options

**Option A: Sidecar Service (Recommended)**

```
┌─────────────────────────────────┐
│         Eliza Cloud             │
│  (Next.js / Vercel / Railway)   │
│                                 │
│  ┌──────────────────────────┐   │
│  │ Wallet Routes            │   │
│  │ /api/v1/user/wallets/*   │──────────► Steward API (internal)
│  └──────────────────────────┘   │         :3200
│                                 │
└─────────────────────────────────┘
                                        ┌───────────────────┐
                                        │   Steward API     │
                                        │   (Hono/Bun)      │
                                        │                   │
                                        │ ┌───────────────┐ │
                                        │ │ Vault         │ │
                                        │ │ PolicyEngine  │ │
                                        │ │ ApprovalQueue │ │
                                        │ └───────────────┘ │
                                        │         │         │
                                        │    Neon DB        │
                                        └───────────────────┘
```

Steward runs as a separate service, accessed by Eliza Cloud via the `@stwd/sdk` `StewardClient`. Internal network only (no public exposure).

**Option B: Embedded Library (Direct Vault Import)**

```typescript
// Import Vault directly — no network hop
import { Vault } from "@stwd/vault";
import { PolicyEngine } from "@stwd/policy-engine";

const vault = new Vault({ masterPassword: process.env.STEWARD_MASTER_PASSWORD });
```

Pros: No network latency, simpler deployment. Cons: Couples Steward lifecycle to Eliza Cloud deploys.

**Recommendation: Option A (Sidecar)** for production, **Option B (Embedded)** for development/testing.

### 6.2 Database

**Shared Neon DB, separate schema/tables.**

Steward's tables (`agents`, `encrypted_keys`, `policies`, `transactions`, `approval_queue`, `tenants`) use different names from Eliza Cloud's tables. They can coexist in the same Postgres database without conflicts.

```
Same Neon DB instance
├── Eliza Cloud tables: users, organizations, agent_server_wallets, ...
└── Steward tables:     agents, encrypted_keys, policies, transactions, ...
```

Both use Drizzle ORM with separate schema definitions. The `DATABASE_URL` can be the same connection string.

### 6.3 Environment Variables

```bash
# Steward-specific
STEWARD_MASTER_PASSWORD=<32+ char secret>   # Vault encryption key
STEWARD_API_URL=http://steward:3200         # Internal URL (sidecar mode)
STEWARD_TENANT_KEY=stw_...                  # API key for Eliza Cloud tenant
DATABASE_URL=<neon connection string>        # Same as Eliza Cloud

# Optional
RPC_URL=https://mainnet.base.org            # Default chain RPC
CHAIN_ID=8453                               # Default chain ID
```

### 6.4 Scaling Considerations

- **Stateless API:** Steward API is stateless — horizontal scaling is trivial.
- **Key decryption:** scrypt derivation is CPU-bound (~50ms per sign). At high volume, consider caching the derived master key per-instance (already done in `KeyStore` constructor).
- **Database:** Neon DB handles connection pooling. Steward's DB queries are simple indexed lookups.
- **Rate limiting:** Steward has built-in IP-based rate limiting (100 req/min). For cloud use, configure per-tenant limits.

### 6.5 Deployment Target

| Environment | Deployment |
|-------------|------------|
| Development | Embedded (direct import from `@stwd/vault`) |
| Staging | Docker container on same host as Eliza Cloud |
| Production | Separate service (Railway/Fly.io/Hetzner) with internal networking |

---

## 7. Auth Flow Changes

### 7.1 User Authentication (Privy OAuth) — NOT Replaced

Privy's user authentication (OAuth, email login, social accounts, `privy-token` cookies) is **separate** from wallet management. This plan does NOT replace Privy auth.

If Privy auth is eventually replaced, Steward has its own auth system (SIWE + passkeys + email — see `packages/api/src/routes/auth.ts`), but that's a separate migration.

### 7.2 Wallet Signature Auth — No Change

The `verifyWalletSignature()` function in `packages/lib/auth/wallet-auth.ts` uses viem's `verifyMessage()` — it's **completely independent of Privy**. No changes needed.

### 7.3 RPC Proxy Changes

**Current flow:**
```
Agent → POST /api/v1/user/wallets/rpc
  → verifyWalletSignature (viem)     ← No change
  → verify payload nonce/timestamp    ← No change
  → lookup agent_server_wallets       ← Add provider routing
  → privy.walletApi.rpc()             ← REPLACE with Steward
```

**New flow:**
```
Agent → POST /api/v1/user/wallets/rpc
  → verifyWalletSignature (viem)
  → verify payload nonce/timestamp
  → lookup agent_server_wallets
  → if wallet_provider === 'steward':
      → steward.signTransaction() or steward.signMessage()
    else:
      → privy.walletApi.rpc()        # Legacy fallback during transition
```

### 7.4 Updated `server-wallets.ts`

```typescript
export async function executeServerWalletRpc({ clientAddress, payload, signature }: ExecuteParams) {
  // ... existing nonce/signature verification (unchanged) ...

  const walletRecord = await db.query.agentServerWallets.findFirst({
    where: eq(agentServerWallets.client_address, clientAddress),
  });

  if (!walletRecord) throw new ServerWalletNotFoundError();

  // Route by provider
  if (walletRecord.wallet_provider === 'steward') {
    return executeStewardRpc(walletRecord, payload);
  } else {
    return executePrivyRpc(walletRecord, payload);
  }
}

async function executeStewardRpc(wallet: AgentServerWallet, payload: RpcPayload) {
  const steward = getStewardClient();

  switch (payload.method) {
    case 'eth_sendTransaction': {
      const [tx] = payload.params as [{ to: string; value: string; data?: string; gas?: string }];
      return steward.signTransaction(wallet.steward_agent_id!, {
        to: tx.to,
        value: tx.value || '0',
        data: tx.data,
        chainId: getChainId(wallet.chain_type),
      });
    }
    case 'personal_sign':
    case 'eth_sign': {
      const [message] = payload.params as [string];
      return steward.signMessage(wallet.steward_agent_id!, message);
    }
    default:
      throw new Error(`RPC method "${payload.method}" not supported via Steward. ` +
        `Supported: eth_sendTransaction, personal_sign, eth_sign`);
  }
}

async function executePrivyRpc(wallet: AgentServerWallet, payload: RpcPayload) {
  const privy = getPrivyClient();
  return privy.walletApi.rpc({
    walletId: wallet.privy_wallet_id!,
    method: payload.method as any,
    params: payload.params as any,
  });
}
```

---

## 8. Feature Parity + Improvements

### 8.1 Features to Replicate from Privy

| Privy Feature | Steward Status | Notes |
|---------------|----------------|-------|
| EVM wallet creation | ✅ Implemented | `vault.createAgent(..., "evm")` |
| Solana wallet creation | ✅ Implemented | `vault.createAgent(..., "solana")` |
| Transaction signing (EVM) | ✅ Implemented | `vault.signTransaction()` — sends on-chain |
| Transaction signing (Solana) | ✅ Implemented | SOL transfer via `signSolanaTransaction()` |
| Message signing (EVM) | ✅ Implemented | `vault.signMessage()` via ECDSA |
| Message signing (Solana) | ✅ Implemented | Ed25519 via Node.js crypto |
| Wallet deletion | ❌ Not implemented | Need to add `vault.deleteAgent()` |
| Raw RPC passthrough | ❌ Not implemented | Steward uses structured requests, not raw JSON-RPC |
| ERC-20 token transfers | ⚠️ Partial | Works via `data` field, but no high-level helper |
| Contract interactions | ⚠️ Partial | Works via `data` field for arbitrary calldata |
| Multi-sig support | ❌ Not available | Not needed for cloud agents |

### 8.2 Steward Advantages (New Capabilities)

| Feature | Description | Value for Cloud |
|---------|-------------|-----------------|
| **Spending Limits** | Per-tx, daily, weekly wei limits | Prevent runaway agent spending |
| **Rate Limits** | Max tx per hour/day | Prevent abuse or compromised agents |
| **Approved Addresses** | Whitelist of allowed `to` addresses | Restrict agents to known contracts |
| **Auto-Approve Threshold** | Small txs auto-approved, large txs queued | Human-in-the-loop for high-value |
| **Time Windows** | Restrict signing to specific hours | Business hours only |
| **Manual Approval Queue** | Dashboard to approve/reject pending txs | Full human oversight |
| **Transaction History** | Full audit trail with policy evaluation results | Compliance & debugging |
| **Webhook Notifications** | Events for tx signed/rejected/pending | Real-time monitoring |
| **Multi-Tenant** | Isolate wallets per organization | Native org support |
| **Batch Creation** | Create multiple agents in one call | Efficient onboarding |
| **Balance Queries** | Built-in native balance check | No external RPC needed |

### 8.3 Dashboard Integration

Steward's dashboard (if deployed) provides:

1. **Agent Management** — Create, view, delete agents
2. **Policy Editor** — Configure spending limits, approved addresses per agent
3. **Approval Queue** — Approve/reject pending transactions
4. **Transaction History** — Full audit log with policy evaluation details
5. **Tenant Management** — Create/manage tenants (maps to Eliza Cloud organizations)

**Integration approach:** The Steward dashboard can be embedded as an iframe or its API can be consumed by Eliza Cloud's existing admin dashboard.

### 8.4 Default Cloud Agent Policies

```typescript
const DEFAULT_CLOUD_AGENT_POLICIES: PolicyRule[] = [
  {
    id: "cloud-spend-limit",
    type: "spending-limit",
    enabled: true,
    config: {
      maxPerTx:   parseEther("0.1").toString(),   // 0.1 ETH per tx
      maxPerDay:  parseEther("1.0").toString(),   // 1 ETH daily
      maxPerWeek: parseEther("5.0").toString(),   // 5 ETH weekly
    },
  },
  {
    id: "cloud-rate-limit",
    type: "rate-limit",
    enabled: true,
    config: {
      maxTxPerHour: 20,
      maxTxPerDay: 100,
    },
  },
  {
    id: "cloud-auto-approve",
    type: "auto-approve-threshold",
    enabled: true,
    config: {
      maxAutoApproveValue: parseEther("0.01").toString(), // Auto-approve < 0.01 ETH
    },
  },
];
```

---

## 9. Phased Rollout

### Phase 1: Steward Alongside Privy (Weeks 1-3)

**Goal:** New agents use Steward. Existing agents unchanged.

**Tasks:**
1. Deploy Steward API as sidecar service
2. Add `wallet_provider`, `steward_agent_id`, `steward_tenant_id` columns to `agent_server_wallets`
3. Create `StewardClient` wrapper in Eliza Cloud (`packages/lib/services/steward-client.ts`)
4. Update `provisionServerWallet()` to use Steward for new wallets
5. Update `executeServerWalletRpc()` with provider routing
6. Create Steward tenant for each existing Eliza Cloud organization
7. Apply default policies to all new agent wallets
8. Add feature flag: `USE_STEWARD_FOR_NEW_WALLETS=true`

**Deliverables:**
- [ ] Steward deployed and accessible from Eliza Cloud
- [ ] DB migration applied (additive, non-breaking)
- [ ] New agent wallets created via Steward
- [ ] Existing Privy wallets continue to work unchanged
- [ ] Integration tests for both providers

**Risk:** Low. Additive changes only. Privy is untouched.

### Phase 2: Migration Tooling (Weeks 3-5)

**Goal:** Provide tooling to migrate existing agents from Privy to Steward.

**Tasks:**
1. Build migration script (`scripts/migrate-privy-to-steward.ts`)
2. For each existing Privy wallet:
   a. Create corresponding Steward agent
   b. Update `agent_server_wallets` record with Steward IDs
   c. Optionally trigger asset transfer from old → new address
3. Build admin dashboard page showing migration status
4. Add per-agent migration API: `POST /api/v1/admin/wallets/:id/migrate`
5. Handle address change notifications to agent runtimes

**Deliverables:**
- [ ] Migration script tested on staging
- [ ] Admin can trigger per-agent migration
- [ ] Asset transfer automation (optional, can be manual)
- [ ] Monitoring for migrated vs unmigrated agents

**Risk:** Medium. New wallet addresses may break agent integrations that hardcode addresses.

### Phase 3: Privy Fully Removed (Weeks 5-7)

**Goal:** Remove all Privy wallet code. Privy auth may remain separately.

**Tasks:**
1. Migrate remaining Privy wallets (or mark as deprecated)
2. Remove `privy_wallet_id` column from `agent_server_wallets`
3. Remove `wallet_provider` column (all are Steward now)
4. Remove `packages/lib/auth/privy-client.ts` wallet-related code
5. Remove `@privy-io/server-auth` dependency (if auth is also replaced) or keep for auth only
6. Remove Privy wallet env vars (`PRIVY_APP_SECRET` etc.) — or keep for auth
7. Update all tests
8. Clean up feature flags

**Deliverables:**
- [ ] Zero Privy wallet API calls
- [ ] Clean schema with Steward as sole wallet provider
- [ ] Reduced dependency surface
- [ ] All tests passing

**Risk:** Low (if Phase 2 completed successfully).

### Timeline Summary

| Phase | Duration | Status |
|-------|----------|--------|
| Phase 1: Dual Provider | 2-3 weeks | Planned |
| Phase 2: Migration | 2 weeks | Planned |
| Phase 3: Privy Removal | 1-2 weeks | Planned |
| **Total** | **5-7 weeks** | |

---

## 10. Risk Assessment

### 10.1 Migration Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Privy wallets can't export keys | Certain | High | Accept: agents get new addresses. Automate asset transfer. |
| Agent runtimes hardcode wallet addresses | Medium | Medium | Notify agents of address change via existing event system. |
| Steward downtime during transition | Low | High | Keep Privy as fallback. Feature flag to route traffic. |
| Database migration breaks existing queries | Low | High | Additive migration only. No column removals until Phase 3. |
| Policy engine false-rejects valid transactions | Medium | Medium | Start with permissive defaults. Monitor rejection rate. |
| Asset loss during transfer | Low | Critical | Dry-run transfers first. Manual approval for high-value. |

### 10.2 Rollback Plan

**Phase 1 rollback:** Set `USE_STEWARD_FOR_NEW_WALLETS=false`. All new wallets go back to Privy. Existing Steward wallets remain functional.

**Phase 2 rollback:** Stop migration script. Wallets already migrated can be routed back to Privy by setting `wallet_provider = 'privy'` (if Privy wallet still exists).

**Phase 3 rollback:** Not possible once Privy columns are dropped. Ensure Phase 2 is stable for 2+ weeks before Phase 3.

### 10.3 Security Comparison

| Aspect | Privy HSM | Steward AES-256-GCM |
|--------|-----------|---------------------|
| Key storage | Hardware Security Module | Software encryption at rest |
| Encryption | HSM-backed (FIPS 140-2) | AES-256-GCM with scrypt key derivation |
| Key extraction | Impossible | Possible with master password |
| Compliance | SOC 2 Type II | Self-managed, auditable |
| Attack surface | Privy infrastructure | Your infrastructure |
| Master key rotation | Managed by Privy | Manual (re-encrypt all keys) |
| Audit trail | Limited | Full tx + policy evaluation logs |
| Access control | Privy API keys | Tenant API keys + SIWE sessions |

**Security notes:**
- Steward's AES-256-GCM is cryptographically strong but is software-based encryption, not HSM.
- The master password (`STEWARD_MASTER_PASSWORD`) is the single point of compromise. It should be stored in a secrets manager (not env vars in plaintext).
- For production, consider wrapping the master password with AWS KMS or GCP Cloud KMS for an HSM-backed envelope encryption layer.
- Steward's policy engine adds a security layer Privy doesn't have — even if an API key is compromised, spending limits and approved addresses constrain the damage.

### 10.4 RPC Method Coverage Gap

**Critical gap:** Privy's `walletApi.rpc()` is a generic JSON-RPC passthrough — it supports any Ethereum RPC method. Steward currently only supports:
- `eth_sendTransaction` (via `signTransaction`)
- `personal_sign` / `eth_sign` (via `signMessage`)

**Missing methods that agents may use:**
- `eth_signTypedData_v4` — EIP-712 typed data signing (DEX approvals, permits)
- `eth_signTransaction` — Sign without broadcast
- `eth_call` — Read-only contract calls (doesn't need signing)
- Custom methods for specific protocols

**Action item:** Audit which RPC methods cloud agents actually use (check logs) and implement them in Steward before Phase 1. At minimum, add `eth_signTypedData_v4` support.

---

## Appendix A: Steward Client Wrapper for Eliza Cloud

```typescript
// packages/lib/services/steward-client.ts

import { StewardClient } from "@stwd/sdk";

let _client: StewardClient | null = null;

export function getStewardClient(): StewardClient {
  if (!_client) {
    const baseUrl = process.env.STEWARD_API_URL;
    const apiKey = process.env.STEWARD_TENANT_KEY;

    if (!baseUrl) {
      throw new Error("STEWARD_API_URL is required");
    }

    _client = new StewardClient({
      baseUrl,
      apiKey,
      tenantId: undefined, // Set per-request based on organization
    });
  }
  return _client;
}

/**
 * Get a Steward client scoped to a specific organization's tenant.
 */
export function getStewardClientForOrg(organizationId: string): StewardClient {
  return new StewardClient({
    baseUrl: process.env.STEWARD_API_URL!,
    apiKey: process.env.STEWARD_TENANT_KEY,
    tenantId: `org-${organizationId}`,
  });
}
```

## Appendix B: Tenant Bootstrapping

Each Eliza Cloud organization needs a corresponding Steward tenant. Bootstrap script:

```typescript
// scripts/bootstrap-steward-tenants.ts

import { db } from "@/db/client";
import { organizations } from "@/db/schemas/organizations";
import { StewardClient } from "@stwd/sdk";

async function bootstrap() {
  const steward = new StewardClient({
    baseUrl: process.env.STEWARD_API_URL!,
  });

  const orgs = await db.select().from(organizations);

  for (const org of orgs) {
    const tenantId = `org-${org.id}`;
    try {
      await steward.request("/tenants", {
        method: "POST",
        body: JSON.stringify({
          id: tenantId,
          name: org.name,
          apiKeyHash: process.env.STEWARD_TENANT_KEY || "",
        }),
      });
      console.log(`Created tenant ${tenantId} for org ${org.name}`);
    } catch (e) {
      if (e.message?.includes("already exists")) continue;
      console.error(`Failed to create tenant for ${org.name}:`, e);
    }
  }
}
```

## Appendix C: Feature Flag Configuration

```typescript
// packages/lib/config/feature-flags.ts

export const FEATURE_FLAGS = {
  /** Use Steward for new wallet provisioning (Phase 1) */
  USE_STEWARD_FOR_NEW_WALLETS: process.env.USE_STEWARD_FOR_NEW_WALLETS === "true",

  /** Allow migration of existing Privy wallets (Phase 2) */
  ALLOW_PRIVY_MIGRATION: process.env.ALLOW_PRIVY_MIGRATION === "true",

  /** Completely disable Privy wallet operations (Phase 3) */
  DISABLE_PRIVY_WALLETS: process.env.DISABLE_PRIVY_WALLETS === "true",
};
```

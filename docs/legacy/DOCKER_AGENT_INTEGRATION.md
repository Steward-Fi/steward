# Steward × Docker Agent Integration Plan

> **Status:** Draft  
> **Author:** Sol (automated analysis)  
> **Date:** 2026-03-20  
> **Codebase refs:**  
> - Steward: `/home/shad0w/projects/steward-fi/packages/{api,vault,sdk,policy-engine,auth}/src/`  
> - Cloud orchestrator: `/home/shad0w/projects/eliza-cloud-v2-milady-pack/packages/lib/services/docker-sandbox-provider.ts`  
> - Container schema: `.../eliza-cloud-v2-milady-pack/packages/db/schemas/containers.ts`  
> - Existing wallet layer: `.../eliza-cloud-v2-milady-pack/packages/db/schemas/agent-server-wallets.ts` (Privy KMS)

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Architecture Overview](#2-architecture-overview)
3. [Deployment Model Evaluation](#3-deployment-model-evaluation)
4. [Integration Points](#4-integration-points)
5. [SDK Integration in Agent Image](#5-sdk-integration-in-agent-image)
6. [Migration Path](#6-migration-path)
7. [Policy Defaults](#7-policy-defaults)
8. [Security Considerations](#8-security-considerations)
9. [Implementation Phases](#9-implementation-phases)
10. [Open Questions](#10-open-questions)

---

## 1. Problem Statement

### Current State

Docker-based Milady agents receive raw private keys via environment variables:

```
# Current env vars injected by DockerSandboxProvider._createOnce()
EVM_PRIVATE_KEY=0xabc123...
SOLANA_PRIVATE_KEY=<base58 secret key>
MILADY_API_TOKEN=<uuid>
```

These are passed through the `environmentVars` parameter in `SandboxCreateConfig`, assembled into `-e` flags, and injected into `docker run` commands via SSH on remote nodes.

**Risks:**
- **Container compromise = full key theft.** Any RCE in the agent process, dependency supply chain attack, or container escape gives the attacker the raw private key.
- **Keys visible in `docker inspect`.** Anyone with Docker socket access on the node can read all environment variables.
- **No spending controls.** A compromised agent can drain its entire wallet in a single transaction.
- **No audit trail.** Transactions signed locally leave no centralized log.

### Existing Server Wallet Layer (Privy)

The cloud already has a partial solution: `agent_server_wallets` table stores Privy-managed wallets where keys reside in Privy's KMS. The agent authenticates via a local `client_address` keypair. However:
- Privy is a third-party dependency with per-wallet pricing
- No policy engine (spending limits, rate limits, address whitelists)
- No approval workflows for high-value transactions
- Tied to Privy's availability and API

### Target State

Replace raw key injection with **Steward** — our own wallet infrastructure that keeps keys encrypted in a vault process **outside the container**, enforces configurable policies before signing, and provides a full audit trail via `@stwd/sdk`.

---

## 2. Architecture Overview

### Transaction Flow

```
┌──────────────────────────────────────────────────────────┐
│  Docker Agent Container                                   │
│  ┌─────────────────────┐                                  │
│  │  Agent Process       │                                  │
│  │  (eliza runtime)     │                                  │
│  │                      │                                  │
│  │  @stwd/sdk client ───┼──── HTTP ────┐                  │
│  │                      │              │                  │
│  └─────────────────────┘              │                  │
│                                        │                  │
│  Env vars:                             │                  │
│  - STEWARD_API_URL                     │                  │
│  - STEWARD_AGENT_ID                    │                  │
│  - STEWARD_AUTH_TOKEN                  │                  │
│  (NO private keys)                     │                  │
└────────────────────────────────────────┼──────────────────┘
                                         │
                                         ▼
┌──────────────────────────────────────────────────────────┐
│  Steward Service (per-node or centralized)                │
│  ┌──────────┐  ┌───────────────┐  ┌──────────────────┐  │
│  │ Hono API │→ │ Policy Engine │→ │  Vault           │  │
│  │ :3200    │  │ (evaluate)    │  │  (decrypt→sign)  │  │
│  └──────────┘  └───────────────┘  └──────────────────┘  │
│       │                                    │             │
│       │         ┌──────────────┐          │             │
│       └────────→│ PostgreSQL   │←─────────┘             │
│                 │ (agents,     │                         │
│                 │  encrypted   │                         │
│                 │  keys, txns, │                         │
│                 │  policies)   │                         │
│                 └──────────────┘                         │
└──────────────────────────────────────────────────────────┘
                                         │
                                         ▼
                                    ┌──────────┐
                                    │ RPC Node │
                                    │ (Base,   │
                                    │  Solana) │
                                    └──────────┘
```

### Key Principles

1. **Private keys never enter the container.** They exist only in Steward's encrypted vault DB, decrypted ephemerally during signing.
2. **Every transaction goes through policy evaluation.** Spending limits, rate limits, address whitelists, time windows — all checked before the vault decrypts.
3. **Audit trail is automatic.** Every sign request (approved, rejected, pending) is recorded in the `transactions` table with policy results.
4. **SDK is thin.** `@stwd/sdk` is ~200 lines, makes HTTP calls to the Steward API. No crypto dependencies needed in the agent.

---

## 3. Deployment Model Evaluation

### Option A: Shared Steward Service Per Node ⭐ RECOMMENDED

One Steward API instance runs on each Docker node, serving all agent containers on that node.

```
Node (VPS)
├── steward-api (Docker container, port 3200)
│   └── connects to shared PostgreSQL
├── milady-agent-1 (STEWARD_API_URL=http://steward:3200)
├── milady-agent-2 (STEWARD_API_URL=http://steward:3200)
└── milady-agent-3 (STEWARD_API_URL=http://steward:3200)
```

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Security** | ★★★★☆ | Keys isolated from agents. Vault master password on host only, not in agent containers. Single attack surface per node. |
| **Latency** | ★★★★★ | Localhost HTTP calls (~1ms). No network hops for signing. |
| **Resource overhead** | ★★★★★ | One Steward process (~50MB RAM) per node regardless of agent count. |
| **Operational complexity** | ★★★★☆ | Deploy Steward once per node. Update independently of agents. |
| **Blast radius** | ★★★☆☆ | If Steward on one node is compromised, all agents on that node are affected. |
| **DB dependency** | ★★★☆☆ | Needs PostgreSQL access from each node. Can share the cloud's existing DB or run a local one. |

**Implementation:** Use a Docker network (`steward-net`) on each node. Steward and all agent containers join this network. Agents reach Steward via the Docker DNS name `steward`. No port exposure to the public internet.

### Option B: Steward Sidecar Per Container

Each agent container gets its own Steward sidecar, communicating via a shared Docker network or unix socket.

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Security** | ★★★★★ | Maximum isolation. Each agent's vault master key can differ. |
| **Latency** | ★★★★★ | Same-network HTTP. |
| **Resource overhead** | ★★☆☆☆ | 50MB × N agents per node. At 20 agents per node, that's 1GB just for sidecars. |
| **Operational complexity** | ★★☆☆☆ | Must deploy/update N sidecars. Docker Compose or pod-style linking needed. |
| **Blast radius** | ★★★★★ | One compromised sidecar only affects one agent. |
| **DB dependency** | ★★☆☆☆ | N concurrent DB connections per node. |

**Verdict:** Overkill for current scale. Consider if we hit regulatory or enterprise isolation requirements.

### Option C: Centralized Steward on shad0wbot

Single Steward instance on the management server, agents on remote nodes call it over the network.

| Aspect | Rating | Notes |
|--------|--------|-------|
| **Security** | ★★★★☆ | All keys in one vault. Single point of hardening. |
| **Latency** | ★★☆☆☆ | Network round-trip for every sign request (10-50ms within same DC, worse cross-region). |
| **Resource overhead** | ★★★★★ | Absolute minimum — one process total. |
| **Operational complexity** | ★★★★★ | One deployment. One upgrade. |
| **Blast radius** | ★☆☆☆☆ | Compromise = ALL agents across ALL nodes. Single point of failure. |
| **DB dependency** | ★★★★★ | Single DB connection pool. |

**Verdict:** Acceptable for early development/testing. Not recommended for production due to SPOF and latency.

### Recommendation: Start with Option A, degrade gracefully to C

**Phase 1:** Deploy centralized (Option C) for development and initial testing. Fastest path to validation.

**Phase 2:** Move to per-node shared service (Option A) for production. The `STEWARD_API_URL` env var makes this transparent to agents — just change the URL from `https://steward.shad0w.xyz:3200` to `http://steward:3200`.

---

## 4. Integration Points

### 4.1 Container Orchestrator Changes

**File:** `docker-sandbox-provider.ts` → `_createOnce()`

#### Current: Raw Key Injection

```typescript
// Current code in _createOnce()
const allEnv: Record<string, string> = {
  ...environmentVars,     // ← includes EVM_PRIVATE_KEY, SOLANA_PRIVATE_KEY
  AGENT_NAME: agentName,
  MILADY_API_TOKEN: environmentVars.MILADY_API_TOKEN || crypto.randomUUID(),
  // ...
};
```

#### New: Steward Provisioning + Token Injection

```typescript
// BEFORE docker run, provision a Steward wallet for this agent
const stewardClient = new StewardClient({
  baseUrl: process.env.STEWARD_API_URL || 'http://steward:3200',
  apiKey: process.env.STEWARD_PLATFORM_KEY,
});

// 1. Create agent wallet in Steward (or retrieve if exists)
let agentIdentity: AgentIdentity;
try {
  agentIdentity = await stewardClient.getAgent(agentId);
} catch {
  agentIdentity = await stewardClient.createWallet(agentId, agentName);
  
  // 2. Apply default policies for cloud agents
  await stewardClient.setPolicies(agentId, getDefaultCloudPolicies());
}

// 3. Generate a scoped auth token for this agent
const agentAuthToken = await stewardClient.generateAgentToken(agentId); // NEW API needed

// 4. Build env vars WITHOUT private keys
const allEnv: Record<string, string> = {
  ...sanitizeEnvironmentVars(environmentVars), // Strip EVM_PRIVATE_KEY, SOLANA_PRIVATE_KEY
  AGENT_NAME: agentName,
  MILADY_API_TOKEN: environmentVars.MILADY_API_TOKEN || crypto.randomUUID(),
  // Steward integration
  STEWARD_API_URL: process.env.STEWARD_API_URL || 'http://steward:3200',
  STEWARD_AGENT_ID: agentId,
  STEWARD_AUTH_TOKEN: agentAuthToken,
  STEWARD_WALLET_ADDRESS: agentIdentity.walletAddress,
  // Keep wallet address in legacy env var for backward compat
  WALLET_ADDRESS: agentIdentity.walletAddress,
  // ...
};
```

#### New Helper Functions

```typescript
/**
 * Strip raw private keys from environment variables.
 * Called during the transition period. Eventually, the upstream
 * code won't include these at all.
 */
function sanitizeEnvironmentVars(vars: Record<string, string>): Record<string, string> {
  const STRIPPED_KEYS = [
    'EVM_PRIVATE_KEY',
    'SOLANA_PRIVATE_KEY', 
    'PRIVATE_KEY',
    'WALLET_PRIVATE_KEY',
  ];
  
  const sanitized = { ...vars };
  for (const key of STRIPPED_KEYS) {
    delete sanitized[key];
  }
  return sanitized;
}
```

### 4.2 New Steward API Endpoints Needed

The existing Steward API is almost complete for this use case. We need a few additions:

#### Agent-Scoped Auth Tokens

Currently, tenant-level API keys (`X-Steward-Key`) grant access to ALL agents under that tenant. For Docker agents, we need per-agent scoped tokens so a compromised container can only sign for its own agent.

```typescript
// NEW: POST /agents/:agentId/token
// Generates a JWT scoped to a single agent
app.post("/agents/:agentId/token", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  
  const token = await new SignJWT({ 
    tenantId, 
    agentId,
    scope: "agent:sign" 
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setIssuer("steward")
    .setExpirationTime("30d") // Long-lived for containers
    .sign(JWT_SECRET);
    
  return c.json<ApiResponse<{ token: string }>>({ ok: true, data: { token } });
});
```

#### Agent-Scoped Auth Middleware

```typescript
// NEW: Middleware that validates agent-scoped JWTs
async function agentScopedAuth(c: Context, next: Next) {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return tenantAuth(c, next); // Fall back to tenant-level auth
  }
  
  const payload = await verifySessionToken(authHeader.slice(7));
  if (!payload?.agentId) {
    return tenantAuth(c, next); // Not an agent token, try tenant auth
  }
  
  // Verify the requested agent matches the token's scope
  const requestedAgent = c.req.param("agentId");
  if (requestedAgent && requestedAgent !== payload.agentId) {
    return c.json<ApiResponse>({ ok: false, error: "Token scope mismatch" }, 403);
  }
  
  // Set tenant context from token
  const tenant = await findTenant(payload.tenantId);
  if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);
  
  c.set("tenantId", payload.tenantId);
  c.set("tenant", tenant);
  await next();
}
```

#### Solana Transaction Signing via SDK

The current `signTransaction` SDK method targets EVM (`to`, `value`, `data`, `chainId`). For Solana agents, we need:

```typescript
// NEW: POST /vault/:agentId/sign-solana
// Accepts a serialized Solana transaction for signing
app.post("/vault/:agentId/sign-solana", async (c) => {
  // Accept base64-encoded serialized transaction
  // Sign with the agent's Solana keypair
  // Return signed transaction (not broadcast — agent handles submission)
});
```

Alternatively, extend the existing `/vault/:agentId/sign` endpoint to detect Solana chains (chainId 101/102) and accept Solana-specific params. The vault already handles this internally — the API just needs to pass through the right shape.

### 4.3 Environment Variables (New vs Old)

| Variable | Old (current) | New (with Steward) | Notes |
|----------|--------------|-------------------|-------|
| `EVM_PRIVATE_KEY` | Raw hex key | **REMOVED** | Never injected |
| `SOLANA_PRIVATE_KEY` | Raw base58 key | **REMOVED** | Never injected |
| `STEWARD_API_URL` | N/A | `http://steward:3200` | Steward endpoint |
| `STEWARD_AGENT_ID` | N/A | Agent's ID in Steward | Same as `agentId` |
| `STEWARD_AUTH_TOKEN` | N/A | JWT (agent-scoped) | 30-day expiry |
| `STEWARD_WALLET_ADDRESS` | N/A | Public address | For display/receiving |
| `WALLET_ADDRESS` | May or may not exist | Public address | Backward compat alias |
| `MILADY_API_TOKEN` | UUID | UUID (unchanged) | Agent API auth (unrelated to wallet) |

### 4.4 Docker Network Setup

On each Docker node, create a bridge network for Steward communication:

```bash
# One-time setup per node (idempotent)
docker network create --driver bridge steward-net 2>/dev/null || true

# Steward service
docker run -d \
  --name steward \
  --network steward-net \
  --restart unless-stopped \
  -e DATABASE_URL="$STEWARD_DB_URL" \
  -e STEWARD_MASTER_PASSWORD="$VAULT_MASTER_KEY" \
  -e RPC_URL="$EVM_RPC_URL" \
  -e CHAIN_ID=8453 \
  steward/api:latest

# Agent containers join the same network
docker run -d \
  --name milady-agent-xyz \
  --network steward-net \
  -e STEWARD_API_URL=http://steward:3200 \
  -e STEWARD_AGENT_ID=xyz \
  -e STEWARD_AUTH_TOKEN=eyJ... \
  milady/agent:cloud-full-ui
```

Update `DockerSandboxProvider._createOnce()` to add `--network steward-net` to the docker run command.

---

## 5. SDK Integration in Agent Image

### 5.1 Installing @stwd/sdk

The `@stwd/sdk` package is already published to npm. Add it to the agent image's `package.json`:

```json
{
  "dependencies": {
    "@stwd/sdk": "^0.1.1"
  }
}
```

The SDK has **zero native dependencies** — it's pure TypeScript using only `fetch()`. No special build steps needed.

### 5.2 Agent-Side Wallet Adapter

Create a wallet adapter that implements the same interface as the current local signing code, but delegates to Steward:

```typescript
// packages/milady-agent/src/wallet/steward-adapter.ts

import { StewardClient, type SignTransactionInput } from "@stwd/sdk";

export class StewardWalletAdapter {
  private client: StewardClient;
  private agentId: string;
  public readonly address: string;
  
  constructor() {
    const apiUrl = process.env.STEWARD_API_URL;
    const agentId = process.env.STEWARD_AGENT_ID;
    const authToken = process.env.STEWARD_AUTH_TOKEN;
    const address = process.env.STEWARD_WALLET_ADDRESS;
    
    if (!apiUrl || !agentId || !authToken || !address) {
      throw new Error(
        "Steward wallet not configured. Required: STEWARD_API_URL, STEWARD_AGENT_ID, STEWARD_AUTH_TOKEN, STEWARD_WALLET_ADDRESS"
      );
    }
    
    this.agentId = agentId;
    this.address = address;
    this.client = new StewardClient({
      baseUrl: apiUrl,
      apiKey: authToken, // SDK uses X-Steward-Key header; we'll update to support Bearer
    });
  }
  
  /**
   * Sign and broadcast an EVM transaction via Steward.
   * Returns txHash on success, throws on policy rejection.
   */
  async sendTransaction(tx: SignTransactionInput): Promise<string> {
    const result = await this.client.signTransaction(this.agentId, tx);
    
    if ('status' in result && result.status === 'pending_approval') {
      throw new Error(`Transaction requires manual approval. Policy results: ${JSON.stringify(result.results)}`);
    }
    
    return result.txHash;
  }
  
  /**
   * Sign an arbitrary message via Steward.
   */
  async signMessage(message: string): Promise<string> {
    const result = await this.client.signMessage(this.agentId, message);
    return result.signature;
  }
  
  /**
   * Get wallet balance (native token).
   */
  async getBalance(chainId?: number): Promise<string> {
    const result = await this.client.getBalance(this.agentId, chainId);
    return result.balances.nativeFormatted;
  }
}
```

### 5.3 Wallet Provider Detection

The agent runtime should auto-detect which wallet provider to use:

```typescript
// packages/milady-agent/src/wallet/index.ts

export function createWalletProvider(): WalletProvider {
  // Prefer Steward if configured
  if (process.env.STEWARD_API_URL && process.env.STEWARD_AGENT_ID) {
    return new StewardWalletAdapter();
  }
  
  // Fall back to local private key (legacy / self-hosted)
  if (process.env.EVM_PRIVATE_KEY) {
    return new LocalWalletAdapter(process.env.EVM_PRIVATE_KEY);
  }
  
  throw new Error("No wallet provider configured");
}
```

---

## 6. Migration Path

### Phase 1: Steward Service Deployment (No Agent Changes)

1. Deploy Steward API centralized on shad0wbot
2. Run Steward's DB migrations
3. Set up the `milady-cloud` tenant in Steward
4. Validate API is healthy

**Downtime:** None. Existing agents unchanged.

### Phase 2: Dual-Mode Agent Image

1. Add `@stwd/sdk` to the agent Docker image
2. Implement `StewardWalletAdapter` with the auto-detection logic above
3. Continue injecting raw keys (backward compat) but ALSO inject `STEWARD_*` env vars
4. New deployments use Steward by default; existing containers keep working with raw keys

**Downtime:** None. Rolling image update. Each new container gets both providers.

### Phase 3: Migrate Existing Agents

For each existing agent with raw keys:

```typescript
async function migrateAgentToSteward(agentId: string, existingPrivateKey: string) {
  // 1. Import the existing key into Steward's vault
  //    (NEW API: POST /vault/:agentId/import)
  await stewardApi.importKey(agentId, existingPrivateKey);
  
  // 2. Apply default policies
  await stewardApi.setPolicies(agentId, getDefaultCloudPolicies());
  
  // 3. Update the container's env vars (requires restart)
  //    - Add STEWARD_* vars
  //    - Remove EVM_PRIVATE_KEY / SOLANA_PRIVATE_KEY
  await updateContainerEnv(agentId, {
    add: { STEWARD_API_URL, STEWARD_AGENT_ID, STEWARD_AUTH_TOKEN },
    remove: ['EVM_PRIVATE_KEY', 'SOLANA_PRIVATE_KEY'],
  });
  
  // 4. Restart the container
  await restartContainer(agentId);
}
```

**Key Import API (NEW):**

```typescript
// POST /vault/:agentId/import
// Import an existing private key into the vault (one-time migration)
app.post("/vault/:agentId/import", async (c) => {
  // Platform-key auth only (not agent-scoped — agents shouldn't import keys)
  const body = await c.req.json<{ privateKey: string; chainType?: "evm" | "solana" }>();
  
  // Encrypt and store the key
  const keyStore = new KeyStore(MASTER_PASSWORD);
  const encrypted = keyStore.encrypt(body.privateKey);
  
  // Derive wallet address from the key
  const address = deriveAddress(body.privateKey, body.chainType);
  
  // Store in DB
  await db.insert(agents).values({ id: agentId, tenantId, name: agentId, walletAddress: address });
  await db.insert(encryptedKeys).values({ agentId, ...encrypted });
  
  return c.json({ ok: true, data: { walletAddress: address } });
});
```

**Can we do it without downtime?** Almost. The dual-mode agent image (Phase 2) means we can migrate the Steward side (import key + set policies) without touching the running container. The only downtime is the container restart to swap env vars. This takes ~10-30 seconds per agent.

**Zero-downtime alternative:** If the agent checks for Steward env vars on each request (not just startup), we could use `docker exec` to set the env vars at runtime. But this is fragile and non-standard. A quick restart is cleaner.

### Phase 4: Remove Raw Key Support

1. Stop injecting private keys in `DockerSandboxProvider._createOnce()`
2. Remove `LocalWalletAdapter` from the agent image (or keep as fallback for self-hosted)
3. Remove raw keys from the cloud database
4. Done

**Timeline:**

| Phase | Duration | Risk |
|-------|----------|------|
| Phase 1: Deploy Steward | 1-2 days | Low |
| Phase 2: Dual-mode image | 2-3 days | Low (additive only) |
| Phase 3: Migrate existing | 1 day | Medium (requires restarts) |
| Phase 4: Remove raw keys | 1 day | Low (cleanup) |

---

## 7. Policy Defaults

### 7.1 Default Cloud Agent Policies

Every cloud-managed agent should get these policies on creation:

```typescript
function getDefaultCloudPolicies(): PolicyRule[] {
  return [
    {
      id: "cloud-spending-limit",
      type: "spending-limit",
      enabled: true,
      config: {
        maxPerTx: "100000000000000000",    // 0.1 ETH per tx
        maxPerDay: "500000000000000000",    // 0.5 ETH per day
        maxPerWeek: "2000000000000000000",  // 2.0 ETH per week
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
        threshold: "50000000000000000",  // Auto-approve under 0.05 ETH
      },
    },
    {
      id: "cloud-approved-addresses",
      type: "approved-addresses",
      enabled: false, // Disabled by default — users opt in
      config: {
        addresses: [],
        mode: "whitelist",
      },
    },
  ];
}
```

### 7.2 Policy Tiers

Different pricing tiers could have different defaults:

| Tier | Spending Limit (daily) | Rate Limit (daily) | Auto-Approve Threshold |
|------|----------------------|--------------------|-----------------------|
| Free | 0.1 ETH | 20 tx | 0.01 ETH |
| Pro | 1.0 ETH | 200 tx | 0.1 ETH |
| Enterprise | Custom | Custom | Custom |

### 7.3 User Policy Customization (Dashboard)

Users customize policies through the Milady Cloud dashboard, which proxies to the Steward API:

```
Dashboard (React)
  → POST /api/agents/:agentId/policies (Cloud API)
    → PUT /agents/:agentId/policies (Steward API)
```

**Dashboard UI features:**
- Toggle individual policies on/off
- Adjust spending limits with a slider + manual input
- Manage address whitelist/blacklist
- Set transaction time windows (e.g., only during business hours)
- View transaction history and policy evaluation results
- Manual approval queue for transactions that exceed auto-approve threshold

**Cloud API proxy route:**

```typescript
// app/api/agents/[agentId]/policies/route.ts
export async function PUT(req: Request, { params }: { params: { agentId: string } }) {
  const session = await requireAuth(req);
  const { agentId } = params;
  
  // Verify user owns this agent
  await requireAgentOwnership(session.userId, agentId);
  
  const policies = await req.json();
  
  // Proxy to Steward
  const steward = getStewardClient();
  await steward.setPolicies(agentId, policies);
  
  return Response.json({ ok: true });
}
```

---

## 8. Security Considerations

### 8.1 Vault Master Password

The `STEWARD_MASTER_PASSWORD` is the root secret that protects all encrypted keys. It must:
- Never be in any container's environment variables
- Be set only on the Steward service process
- Be backed up securely (if lost, all keys are unrecoverable)
- Rotate periodically (requires re-encrypting all keys — future feature)

### 8.2 Network Isolation

- Steward's port (3200) should **not** be exposed to the public internet
- Use Docker networks for node-local communication
- For centralized deployment, use Tailscale/WireGuard or mutual TLS
- The Steward health endpoint (`/health`) can be exposed for monitoring

### 8.3 Agent Token Scope

- Agent-scoped JWTs should only allow: `sign`, `sign-message`, `get-balance`, `get-history`
- Agent tokens should NOT allow: `create-wallet`, `import-key`, `set-policies`, `list-agents`
- Platform keys for management operations are separate

### 8.4 Database Security

- Steward's PostgreSQL should use SSL connections
- Can share the cloud's existing Neon/Supabase DB (separate schema) or use a dedicated instance
- Encrypted keys in the DB are useless without the master password (AES-256-GCM with per-key salt)

### 8.5 Privy Migration

The existing `agent_server_wallets` (Privy) system should be kept as-is during transition. Steward and Privy can coexist:
- New agents → Steward
- Existing Privy-managed agents → Keep on Privy until explicit migration
- Eventually deprecate Privy wallet integration

---

## 9. Implementation Phases

### Phase 1: API Extensions (2 days)

- [ ] Add `POST /agents/:agentId/token` — agent-scoped JWT generation
- [ ] Add `POST /vault/:agentId/import` — key import for migration
- [ ] Add agent-scoped auth middleware to vault endpoints
- [ ] Add `POST /vault/:agentId/sign-solana` — Solana tx signing via API
- [ ] Publish `@stwd/sdk@0.2.0` with new methods (`generateAgentToken`, `importKey`)
- [ ] Tests for all new endpoints

### Phase 2: Agent Image Update (3 days)

- [ ] Create `StewardWalletAdapter` in the agent codebase
- [ ] Create `createWalletProvider()` factory with auto-detection
- [ ] Wire adapter into agent's transaction/signing code paths
- [ ] Update Dockerfile to include `@stwd/sdk`
- [ ] Integration tests with mock Steward server
- [ ] Build and push updated Docker image

### Phase 3: Orchestrator Update (2 days)

- [ ] Update `DockerSandboxProvider._createOnce()` to provision Steward wallets
- [ ] Add `sanitizeEnvironmentVars()` to strip raw keys
- [ ] Add Docker network setup to node provisioning scripts
- [ ] Deploy Steward service on shad0wbot (centralized, Phase 1 deployment model)
- [ ] Create `milady-cloud` tenant with platform key
- [ ] Test full flow: create agent → Steward wallet → container start → sign tx

### Phase 4: Migration & Hardening (2 days)

- [ ] Write migration script to import existing agent keys into Steward
- [ ] Run migration on staging
- [ ] Run migration on production with rolling restarts
- [ ] Deploy Steward per-node (move from centralized to Option A)
- [ ] Monitor: sign latency, error rates, policy rejection rates
- [ ] Dashboard UI for policy management

### Phase 5: Cleanup (1 day)

- [ ] Remove raw key injection from orchestrator
- [ ] Purge raw keys from cloud database
- [ ] Update documentation
- [ ] Deprecate Privy wallet integration (timeline TBD)

---

## 10. Open Questions

1. **Shared DB or separate?** Should Steward use the cloud's existing PostgreSQL or its own dedicated instance? Shared is simpler; separate is more isolated.

2. **Solana signing model.** The current vault signs and broadcasts EVM transactions atomically. For Solana, should Steward sign-only (return signed tx) or sign-and-broadcast? Solana transactions have blockhash expiry, so agent-side broadcast might be more reliable.

3. **Multi-chain per agent.** Should one Steward agent have both an EVM and Solana wallet? Currently `createAgent` takes an optional `chainType` parameter but creates only one wallet type. Some agents need both.

4. **Token refresh.** Agent-scoped JWTs expire after 30 days. Should the agent auto-refresh, or should the orchestrator rotate tokens on a schedule?

5. **Backup vault.** If the Steward service goes down, agents can't sign. Should we have a warm standby? Or is the blast radius acceptable given container restarts are ~30s?

6. **Self-hosted agents.** Users who self-host (not on Milady Cloud) might want Steward too. Should the SDK support a "local vault" mode where keys are in a local encrypted file instead of a remote API?

7. **ERC-8004 integration.** The Steward schema has an `erc8004TokenId` field on agents. When/how does this get set? Is it relevant for cloud agents?

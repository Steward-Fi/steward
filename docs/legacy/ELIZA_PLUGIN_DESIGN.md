# Eliza Plugin Design: `@stwd/eliza-plugin`

> Connects ElizaOS agents to Steward for managed wallet operations — signing, balances, policies, and approval flows.

## Overview

The plugin replaces raw key signing in the agent runtime with Steward-mediated wallet operations. It's **opt-in**: agents without Steward configured fall back to whatever wallet provider they already use. When active, every transaction routes through Steward's policy engine before signing.

```
Agent decides to act
  → plugin intercepts via action/provider
  → StewardClient calls Steward API
  → Policy engine evaluates (spending limits, approved addresses, rate limits, etc.)
  → Approved: sign + broadcast → return tx receipt
  → Rejected: return rejection reason → agent can explain to user
  → Pending: return "awaiting manual approval" → agent polls or waits for webhook
```

---

## 1. Package Structure

```
packages/eliza-plugin/
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── src/
│   ├── index.ts              # Plugin definition + default export
│   ├── actions/
│   │   ├── signTransaction.ts # Routes tx signing through Steward
│   │   ├── signMessage.ts     # Message signing via Steward
│   │   └── transfer.ts        # High-level "send tokens" action
│   ├── providers/
│   │   ├── walletStatus.ts    # Wallet address, chain, policy summary
│   │   └── balance.ts         # On-chain balance via Steward
│   ├── evaluators/
│   │   └── approvalRequired.ts # Pre-check if tx would need manual approval
│   ├── services/
│   │   └── StewardService.ts  # Singleton service wrapping StewardClient
│   └── types.ts               # Plugin-specific types
```

### `package.json`

```json
{
  "name": "@stwd/eliza-plugin",
  "version": "0.1.0",
  "description": "Steward wallet management plugin for ElizaOS agents",
  "type": "module",
  "main": "dist/index.js",
  "exports": {
    "./package.json": "./package.json",
    ".": {
      "import": {
        "types": "./dist/index.d.ts",
        "default": "./dist/index.js"
      }
    }
  },
  "dependencies": {
    "@stwd/sdk": "^0.1.1",
    "@elizaos/core": "2.0.0-alpha.77"
  },
  "peerDependencies": {
    "@elizaos/core": ">=2.0.0-alpha.50"
  },
  "devDependencies": {
    "tsup": "^8.0.0",
    "typescript": "^5.5.0"
  },
  "scripts": {
    "build": "tsup",
    "dev": "tsup --watch"
  }
}
```

---

## 2. Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `STEWARD_API_URL` | No | `http://localhost:7860` | Steward API base URL |
| `STEWARD_API_KEY` | No | — | API key for authentication |
| `STEWARD_AGENT_ID` | No | Uses runtime `agentId` | Override agent identity in Steward |
| `STEWARD_TENANT_ID` | No | — | Multi-tenant isolation key |
| `STEWARD_AUTO_REGISTER` | No | `true` | Auto-create wallet on first use |
| `STEWARD_FALLBACK_LOCAL` | No | `true` | Fall back to local signing if Steward unreachable |

### Character Config Registration

```json
{
  "name": "my-agent",
  "plugins": ["@stwd/eliza-plugin"],
  "settings": {
    "steward": {
      "apiUrl": "https://steward.example.com",
      "agentId": "agent-123",
      "autoRegister": true,
      "fallbackLocal": true
    }
  }
}
```

The plugin reads config from three sources (priority order):
1. Character `settings.steward.*`
2. Environment variables (`STEWARD_*`)
3. Auto-discovery: probe `localhost:7860/health` on init

### Auto-Discovery

During `init()`, if no explicit URL is configured, the plugin tries:
1. `http://localhost:7860/health` — local Steward instance
2. If reachable, uses it silently
3. If not, plugin disables itself (no error, just a warning log)

---

## 3. Plugin Interface

### 3.1 Actions

#### `STEWARD_SIGN_TRANSACTION`

Routes a transaction through Steward's policy engine and signing vault.

```typescript
const signTransactionAction: Action = {
  name: "STEWARD_SIGN_TRANSACTION",
  description: "Sign and broadcast a transaction through Steward's managed wallet with policy enforcement",
  similes: ["sign transaction", "send transaction", "execute transaction"],
  parameters: [
    {
      name: "to",
      description: "Destination address",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "value",
      description: "Amount in wei (EVM) or lamports (Solana)",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "data",
      description: "Calldata for contract interactions (hex-encoded)",
      required: false,
      schema: { type: "string" },
    },
    {
      name: "chainId",
      description: "Target chain ID (e.g. 8453 for Base, 1 for Ethereum)",
      required: false,
      schema: { type: "number" },
    },
  ],

  async validate(runtime, message) {
    const steward = runtime.getService("STEWARD");
    return steward !== null;
  },

  async handler(runtime, message, state, options) {
    const steward = runtime.getService<StewardService>("STEWARD");
    const { to, value, data, chainId } = options.parameters;

    const result = await steward.signTransaction({ to, value, data, chainId });

    if ("txHash" in result) {
      return {
        success: true,
        text: `Transaction signed and broadcast. Hash: ${result.txHash}`,
        data: { txHash: result.txHash },
      };
    }

    if (result.status === "pending_approval") {
      return {
        success: true,
        text: "Transaction requires manual approval. Waiting for owner to approve.",
        data: { status: "pending_approval", policies: result.results },
      };
    }

    return {
      success: false,
      error: "Transaction rejected by policy engine",
      data: { policies: result.results },
    };
  },
};
```

#### `STEWARD_SIGN_MESSAGE`

Signs an arbitrary message (EIP-191 / Solana equivalent).

```typescript
const signMessageAction: Action = {
  name: "STEWARD_SIGN_MESSAGE",
  description: "Sign a message using the Steward-managed wallet",
  parameters: [
    {
      name: "message",
      description: "The message to sign",
      required: true,
      schema: { type: "string" },
    },
  ],
  // ... validate + handler similar pattern
};
```

#### `STEWARD_TRANSFER`

High-level "send tokens" action that the LLM can invoke directly from natural language. Wraps `signTransaction` with human-readable amount parsing.

```typescript
const transferAction: Action = {
  name: "STEWARD_TRANSFER",
  description: "Send tokens to an address using the Steward-managed wallet",
  similes: ["send tokens", "transfer", "send ETH", "send SOL", "pay"],
  parameters: [
    {
      name: "to",
      description: "Recipient address or ENS name",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "amount",
      description: "Human-readable amount (e.g. '0.1 ETH', '50 USDC')",
      required: true,
      schema: { type: "string" },
    },
    {
      name: "chain",
      description: "Target chain name (base, ethereum, solana)",
      required: false,
      schema: { type: "string", enum: ["base", "ethereum", "solana"] },
    },
  ],
  // handler: parses amount, resolves ENS, converts to wei, calls signTransaction
};
```

### 3.2 Providers

#### `stewardWalletStatus`

Injected into agent context so the LLM knows its wallet state.

```typescript
const walletStatusProvider: Provider = {
  name: "stewardWalletStatus",
  description: "Current Steward wallet address, chain, and policy summary",

  async get(runtime, message, state) {
    const steward = runtime.getService<StewardService>("STEWARD");
    if (!steward?.isConnected()) {
      return { text: "", data: {} };
    }

    const agent = await steward.getAgent();
    const policies = await steward.getPolicies();

    const policyText = policies
      .filter(p => p.enabled)
      .map(p => `- ${p.type}: ${summarizePolicy(p)}`)
      .join("\n");

    return {
      text: [
        `Wallet: ${agent.walletAddress}`,
        `Agent ID: ${agent.id}`,
        `Active policies:`,
        policyText || "  (none)",
      ].join("\n"),
      values: {
        walletAddress: agent.walletAddress,
        agentId: agent.id,
      },
      data: {
        agent,
        policies,
      },
    };
  },
};
```

#### `stewardBalance`

```typescript
const balanceProvider: Provider = {
  name: "stewardBalance",
  description: "On-chain balance of the Steward-managed wallet",

  async get(runtime, message, state) {
    const steward = runtime.getService<StewardService>("STEWARD");
    if (!steward?.isConnected()) {
      return { text: "", data: {} };
    }

    const balance = await steward.getBalance();

    return {
      text: `Balance: ${balance.balances.nativeFormatted} ${balance.balances.symbol} (chain ${balance.balances.chainId})`,
      values: {
        balance: balance.balances.nativeFormatted,
        symbol: balance.balances.symbol,
        chainId: balance.balances.chainId,
      },
      data: { balance },
    };
  },
};
```

### 3.3 Evaluators

#### `approvalRequired`

Post-action evaluator that detects when a pending transaction needs user approval and shapes the agent's response accordingly.

```typescript
const approvalRequiredEvaluator: Evaluator = {
  name: "approvalRequired",
  description: "Checks if the last transaction is pending manual approval and adjusts response",
  alwaysRun: false,
  examples: [],

  async validate(runtime, message) {
    // Only run after transaction actions
    return message.content?.action?.startsWith("STEWARD_") ?? false;
  },

  async handler(runtime, message, state) {
    const lastResult = state?.lastActionResult;
    if (lastResult?.data?.status === "pending_approval") {
      // Could: send notification, create a reminder, store pending tx for follow-up
      const steward = runtime.getService<StewardService>("STEWARD");
      // Optionally poll or register a webhook for resolution
    }
  },
};
```

---

## 4. StewardService

A singleton service registered with the Eliza runtime that manages the `StewardClient` lifecycle.

```typescript
import { Service, type IAgentRuntime, logger } from "@elizaos/core";
import { StewardClient, StewardApiError } from "@stwd/sdk";
import type {
  SignTransactionInput,
  SignTransactionResult,
  CreateWalletResult,
} from "@stwd/sdk";

interface StewardServiceConfig {
  apiUrl: string;
  apiKey?: string;
  agentId: string;
  tenantId?: string;
  autoRegister: boolean;
  fallbackLocal: boolean;
}

export class StewardService extends Service {
  static serviceType = "STEWARD" as const;

  private client: StewardClient | null = null;
  private config: StewardServiceConfig | null = null;
  private agentIdentity: CreateWalletResult | null = null;
  private connected = false;

  async initialize(runtime: IAgentRuntime): Promise<void> {
    this.config = this.resolveConfig(runtime);

    if (!this.config) {
      logger.warn("[Steward] No configuration found, plugin disabled");
      return;
    }

    this.client = new StewardClient({
      baseUrl: this.config.apiUrl,
      apiKey: this.config.apiKey,
      tenantId: this.config.tenantId,
    });

    // Health check
    try {
      this.agentIdentity = await this.client.getAgent(this.config.agentId);
      this.connected = true;
      logger.info(`[Steward] Connected. Wallet: ${this.agentIdentity.walletAddress}`);
    } catch (err) {
      if (err instanceof StewardApiError && err.status === 404 && this.config.autoRegister) {
        // Agent doesn't exist yet — register it
        try {
          this.agentIdentity = await this.client.createWallet(
            this.config.agentId,
            runtime.character?.name ?? this.config.agentId,
          );
          this.connected = true;
          logger.info(`[Steward] Registered new wallet: ${this.agentIdentity.walletAddress}`);
        } catch (regErr) {
          logger.error("[Steward] Failed to auto-register agent:", regErr);
        }
      } else {
        logger.warn("[Steward] Could not connect:", err instanceof Error ? err.message : err);
        if (this.config.fallbackLocal) {
          logger.info("[Steward] Falling back to local signing");
        }
      }
    }
  }

  isConnected(): boolean {
    return this.connected && this.client !== null;
  }

  async signTransaction(tx: SignTransactionInput): Promise<SignTransactionResult> {
    this.assertConnected();
    return this.client!.signTransaction(this.config!.agentId, tx);
  }

  async signMessage(message: string) {
    this.assertConnected();
    return this.client!.signMessage(this.config!.agentId, message);
  }

  async getBalance(chainId?: number) {
    this.assertConnected();
    return this.client!.getBalance(this.config!.agentId, chainId);
  }

  async getAgent() {
    this.assertConnected();
    return this.agentIdentity!;
  }

  async getPolicies() {
    this.assertConnected();
    return this.client!.getPolicies(this.config!.agentId);
  }

  async getHistory() {
    this.assertConnected();
    return this.client!.getHistory(this.config!.agentId);
  }

  private assertConnected() {
    if (!this.connected || !this.client) {
      throw new Error("Steward service not connected");
    }
  }

  private resolveConfig(runtime: IAgentRuntime): StewardServiceConfig | null {
    const settings = (runtime.character?.settings as any)?.steward ?? {};
    const env = process.env;

    const apiUrl = settings.apiUrl ?? env.STEWARD_API_URL ?? this.autoDiscover();
    if (!apiUrl) return null;

    return {
      apiUrl,
      apiKey: settings.apiKey ?? env.STEWARD_API_KEY,
      agentId: settings.agentId ?? env.STEWARD_AGENT_ID ?? runtime.agentId,
      tenantId: settings.tenantId ?? env.STEWARD_TENANT_ID,
      autoRegister: settings.autoRegister ?? env.STEWARD_AUTO_REGISTER !== "false",
      fallbackLocal: settings.fallbackLocal ?? env.STEWARD_FALLBACK_LOCAL !== "false",
    };
  }

  private autoDiscover(): string | null {
    // Synchronous check isn't ideal; in practice we'd do an async probe
    // during init and cache the result. For config resolution, we just
    // return the default URL and let init() handle the health check.
    return "http://localhost:7860";
  }
}
```

---

## 5. Plugin Entry Point

```typescript
// src/index.ts
import { type Plugin, logger } from "@elizaos/core";
import { StewardService } from "./services/StewardService";
import { signTransactionAction } from "./actions/signTransaction";
import { signMessageAction } from "./actions/signMessage";
import { transferAction } from "./actions/transfer";
import { walletStatusProvider } from "./providers/walletStatus";
import { balanceProvider } from "./providers/balance";
import { approvalRequiredEvaluator } from "./evaluators/approvalRequired";

export const stewardPlugin: Plugin = {
  name: "@stwd/eliza-plugin",
  description: "Steward wallet management — policy-enforced signing, balances, and approval flows for ElizaOS agents",

  services: [StewardService],

  actions: [
    signTransactionAction,
    signMessageAction,
    transferAction,
  ],

  providers: [
    walletStatusProvider,
    balanceProvider,
  ],

  evaluators: [
    approvalRequiredEvaluator,
  ],

  async init(config, runtime) {
    const steward = runtime.getService<StewardService>("STEWARD");
    if (steward?.isConnected()) {
      const agent = await steward.getAgent();
      logger.info(`[Steward Plugin] Active — wallet ${agent.walletAddress}`);
    } else {
      logger.info("[Steward Plugin] Inactive — Steward not available, using local wallet");
    }
  },
};

export default stewardPlugin;

// Re-export for consumers
export { StewardService } from "./services/StewardService";
export type { StewardServiceConfig } from "./services/StewardService";
```

---

## 6. Transaction Flow (Detailed)

```
┌─────────────────┐
│  Agent Runtime   │
│  (LLM decides    │
│   to send tokens)│
└────────┬────────┘
         │ STEWARD_TRANSFER action invoked
         ▼
┌─────────────────┐
│  Transfer Action │
│  - Parse amount  │
│  - Resolve ENS   │
│  - Convert units │
└────────┬────────┘
         │ calls StewardService.signTransaction()
         ▼
┌─────────────────┐
│  StewardService  │
│  (wraps SDK)     │
└────────┬────────┘
         │ HTTP POST /vault/{agentId}/sign
         ▼
┌─────────────────┐
│  Steward API     │
│  ┌─────────────┐ │
│  │Policy Engine│ │  ← spending limits, approved addrs, rate limits, time windows
│  └──────┬──────┘ │
│         │        │
│  ┌──────▼──────┐ │
│  │   Vault     │ │  ← HSM / KMS-backed key storage
│  └──────┬──────┘ │
│         │        │
│  ┌──────▼──────┐ │
│  │  Broadcast  │ │  ← submit to chain RPC
│  └─────────────┘ │
└────────┬────────┘
         │
         ▼
  ┌──────────────────────────────────────┐
  │ Response (one of):                    │
  │ 200: { txHash: "0x..." }             │ → success, return receipt to agent
  │ 202: { status: "pending_approval" }  │ → agent tells user "waiting for approval"
  │ 403: { error: "policy violated" }    │ → agent explains why tx was rejected
  │ 5xx: network error                   │ → fallback to local if configured
  └──────────────────────────────────────┘
```

### Approval Flow (202 Pending)

When a transaction exceeds auto-approve thresholds:

1. Steward returns `202` with `status: "pending_approval"`
2. Plugin stores the pending tx reference
3. Agent tells the user: "This transaction needs your approval"
4. **Resolution paths:**
   - **Webhook** (preferred): Steward POSTs to a callback URL when owner approves/rejects
   - **Polling**: Agent periodically checks `/vault/{agentId}/history` for status change
   - **Dashboard**: Owner approves via Steward web UI

---

## 7. Backward Compatibility

### Fallback Strategy

```typescript
// In any action handler:
async handler(runtime, message, state, options) {
  const steward = runtime.getService<StewardService>("STEWARD");

  if (steward?.isConnected()) {
    // Use Steward-managed signing
    return await steward.signTransaction(tx);
  }

  // Fallback: check if there's a local wallet provider
  const localWallet = runtime.getService("WALLET");
  if (localWallet) {
    logger.warn("[Steward] Falling back to local signing — no policy enforcement");
    return await localWallet.signTransaction(tx);
  }

  return { success: false, error: "No wallet available (Steward unreachable, no local wallet)" };
}
```

### Opt-in Registration

The plugin does nothing if:
- Not listed in the character's `plugins` array
- No `STEWARD_*` env vars set AND no Steward on localhost
- Steward is unreachable and `fallbackLocal` is true (silently degrades)

Existing agents that don't add `@stwd/eliza-plugin` are completely unaffected.

---

## 8. Multi-Chain Support

### Current: EVM Only

The SDK's `SignTransactionInput` has `chainId` for EVM chain routing. Steward's vault signs EVM transactions natively.

```typescript
// EVM transaction
await steward.signTransaction({
  to: "0x...",
  value: "1000000000000000", // wei
  chainId: 8453, // Base
});
```

### Planned: Solana

Solana support requires a different signing flow (Solana transactions ≠ EVM transactions). Design:

```typescript
// Future: chain-aware transaction type
interface ChainTransaction {
  chain: "evm" | "solana";

  // EVM fields
  to?: string;
  value?: string;
  data?: string;
  chainId?: number;

  // Solana fields
  serializedTransaction?: string; // base64 encoded
  instructions?: SolanaInstruction[];
}
```

The plugin's `STEWARD_TRANSFER` action handles chain routing:

```typescript
// In transfer action handler
const chain = resolveChain(options.parameters.chain, options.parameters.to);

if (chain === "solana") {
  // Build Solana transaction, serialize, send to Steward's Solana vault
  return await steward.signSolanaTransaction(serialized);
} else {
  // EVM path
  return await steward.signTransaction({ to, value, data, chainId });
}
```

**Chain detection heuristic:**
- Address starts with `0x` → EVM
- Address is base58 (32-44 chars, no `0x`) → Solana
- Explicit `chain` parameter overrides

### SDK Changes Needed for Solana

```typescript
// @stwd/sdk additions (future)
signSolanaTransaction(agentId: string, tx: SolanaTransactionInput): Promise<SolanaSignResult>;

interface SolanaTransactionInput {
  serializedTransaction: string; // base64
  // OR
  instructions: Array<{
    programId: string;
    keys: Array<{ pubkey: string; isSigner: boolean; isWritable: boolean }>;
    data: string; // base64
  }>;
}
```

---

## 9. Build Configuration

### `tsup.config.ts`

```typescript
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  external: ["@elizaos/core"],
  target: "node22",
});
```

### `tsconfig.json`

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "dist",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src"],
  "exclude": ["node_modules", "dist"]
}
```

---

## 10. Integration Example

### Minimal Setup

```bash
# In your Eliza agent project
npm install @stwd/eliza-plugin

# Set env vars
export STEWARD_API_URL=http://localhost:7860
export STEWARD_API_KEY=your-key-here
```

```json
// character.json
{
  "name": "TradingAgent",
  "plugins": ["@stwd/eliza-plugin"],
  "settings": {
    "steward": {
      "autoRegister": true
    }
  }
}
```

That's it. The agent now:
- Has a Steward-managed wallet (auto-created on first run)
- Can respond to "send 0.01 ETH to 0x..." with policy-checked transactions
- Reports its wallet address and balance when asked
- Explains policy rejections in natural language

### With Milady

```json
// milaidy character.json
{
  "name": "milaidy",
  "plugins": [
    "@elizaos/plugin-sql",
    "@elizaos/plugin-knowledge",
    "@stwd/eliza-plugin"
  ],
  "settings": {
    "steward": {
      "apiUrl": "http://localhost:7860",
      "agentId": "milaidy-main",
      "autoRegister": true,
      "fallbackLocal": false
    }
  }
}
```

---

## 11. Open Questions / Future Work

1. **Webhook support**: Steward should POST to a callback when pending approvals resolve. The plugin would register a route (`/steward/webhook`) to receive these.

2. **ERC-8004 integration**: Agent identity tokens — the plugin could read the agent's on-chain identity NFT and surface it in the wallet status provider.

3. **Token balances**: Currently only native balance. Need ERC-20/SPL token balance queries (either in Steward API or plugin-side via RPC).

4. **Gas estimation**: Should the plugin estimate gas before submitting to Steward, or let Steward handle it?

5. **Multi-wallet**: One agent could have wallets on multiple chains. The service should support chain-specific wallet lookups.

6. **Transaction history in agent memory**: Store completed transactions as agent memories so the LLM can reference past activity.

7. **Solana vault**: Steward currently only has EVM vault. Solana signing requires a separate key derivation path and transaction serialization.

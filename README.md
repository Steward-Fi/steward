# Steward

Steward is the self-hostable authority plane for private enterprise agents. It gives agents scoped wallet and API capabilities without exposing secrets, routes sensitive actions through policy and human approval, and records execution evidence. Bring your own agent runtime, cloud, and custodian.

[![npm](https://img.shields.io/npm/v/@stwd/sdk)](https://www.npmjs.com/package/@stwd/sdk)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-steward.fi-blue)](https://docs.steward.fi)

## what exists today

Steward provides encrypted wallet and credential storage, authenticated multi-tenant APIs, policy evaluation and approval workflows, a credential-injecting proxy, operator freeze controls, and an HMAC-chained execution record. Wallet and API capabilities are the core. Trading venue packages are optional extensions.

| Area | Current implementation |
|---|---|
| **Custody** | Wallet keys are encrypted at rest under an operator-held root. An optional KMS envelope is available, with an adapter seam for third-party custody providers. |
| **Policy boundary** | Policy is evaluated in API route handlers before governed routes call signing operations. The vault primitive does not independently enforce policy. |
| **Approvals** | Sensitive actions can be held for human review, then approved or denied through API and UI workflows. |
| **Execution record** | Steward writes a machine-readable, HMAC-chained audit record. Offline, independently verifiable Ed25519 evidence bundles are roadmap work. |
| **Deployment** | Self-hosted Docker and embedded PGLite modes are available. Operators bring their own runtime, cloud, and custody configuration. |

## architecture

```text
agent runtime              Steward authority plane             target systems
┌─────────────┐      ┌────────────────────────────┐      ┌──────────────────┐
│ scoped token│─────>│ auth + route policy checks │─────>│ chains and APIs  │
│ no raw keys │      │ approvals                  │      │ custody provider │
│ no API keys │      │ encrypted wallet/secrets   │      └──────────────────┘
└─────────────┘      │ credential proxy           │
                     │ HMAC-chained audit record  │
                     └────────────────────────────┘
```

## quick start

```bash
npm install @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const steward = new StewardClient({
  // point this at your self-hosted Steward instance (see deploy/docker-compose.yml)
  baseUrl: "http://localhost:3200",
  apiKey: "stw_your_tenant_key",
  tenantId: "my-app",
});

// create an agent with EVM + Solana wallets
const agent = await steward.createWallet("trading-bot", "Trading Bot");
console.log(agent.walletAddresses); // { evm: "0x...", solana: "..." }

// request signing through a policy-evaluating API route
const result = await steward.signTransaction("trading-bot", {
  to: "0xRecipient",
  value: "10000000000000000", // 0.01 ETH
  chainId: 8453, // Base
});
```

see the full [quickstart guide](docs/quickstart.mdx) for auth setup and policies. see the [deployment guide](docs/deployment.md) for self-hosting.

---

## auth widget

drop-in React components for login and wallet management:

```bash
npm install @stwd/react @stwd/sdk
```

```tsx
import { StewardProvider, StewardLogin, StewardAuthGuard } from "@stwd/react";
import "@stwd/react/styles.css";

function App() {
  return (
    <StewardProvider
      client={stewardClient}
      auth={{ baseUrl: "http://localhost:3200" }}
    >
      <StewardAuthGuard fallback={<StewardLogin methods={["passkey", "email", "google"]} />}>
        <Dashboard />
      </StewardAuthGuard>
    </StewardProvider>
  );
}
```

components: `StewardLogin`, `StewardAuthGuard`, `StewardUserButton`, `StewardTenantPicker`, `WalletOverview`, `PolicyControls`, `ApprovalQueue`, `SpendDashboard`, `TransactionHistory`.

---

## packages

| package | version | description |
|---|---|---|
| [`@stwd/sdk`](https://www.npmjs.com/package/@stwd/sdk) | ![npm](https://img.shields.io/npm/v/@stwd/sdk) | TypeScript client for browser + Node. zero deps. |
| [`@stwd/react`](https://www.npmjs.com/package/@stwd/react) | ![npm](https://img.shields.io/npm/v/@stwd/react) | drop-in React components: login, wallet, policies, approvals. |
| [`@stwd/eliza-plugin`](https://www.npmjs.com/package/@stwd/eliza-plugin) | ![npm](https://img.shields.io/npm/v/@stwd/eliza-plugin) | ELIZA OS integration: sign, transfer, balance, approval evaluator. |
| `@stwd/api` | internal | Hono REST API. 30+ endpoints, multi-tenant, dual auth. |
| `@stwd/vault` | internal | wallet + secret encryption. AES-256-GCM, EVM + Solana. |
| `@stwd/policy-engine` | internal | composable policy evaluation. 6 rule types, 1000+ lines of tests. |
| `@stwd/proxy` | internal | API proxy with credential injection, alias system, audit trail. |
| `@stwd/auth` | internal | passkeys (WebAuthn), email magic links, SIWE, OAuth. |
| `@stwd/webhooks` | internal | HMAC-signed event delivery with retries. |
| `@stwd/db` | internal | Drizzle ORM schema, migrations, PGLite adapter. |
| `@stwd/shared` | internal | types, chain metadata, constants. |

---

## self-hosting

Steward runs anywhere. two options:

**docker (recommended for production):**

```bash
git clone https://github.com/Steward-Fi/steward.git && cd steward
cp .env.example .env
# set STEWARD_MASTER_PASSWORD, POSTGRES_PASSWORD, STEWARD_PLATFORM_KEYS,
# STEWARD_SESSION_SECRET, and STEWARD_JWT_SECRET in .env
docker compose up -d
curl http://127.0.0.1:3200/ready
```

starts the API (`:3200`), proxy (`:8080`), Postgres, and Redis. API migrations run automatically on startup unless `SKIP_MIGRATIONS` is set.

**embedded mode (no third-party dependencies):**

```bash
bun run start:local
```

uses PGLite (in-process Postgres via WASM). data persists to `~/.steward/data/`. good for local development, CLI agents, and desktop apps.

**required env vars:**

| variable | description |
|---|---|
| `STEWARD_MASTER_PASSWORD` | derives all vault encryption keys. **no recovery if lost.** |
| `DATABASE_URL` | Postgres connection string (not needed in embedded mode) |
| `STEWARD_SESSION_SECRET` | JWT signing secret (defaults to master password) |
| `REDIS_URL` | Redis for rate limiting + token store (optional) |
| `RESEND_API_KEY` | for email magic link auth (optional) |
| `PASSKEY_RP_ID` | WebAuthn relying party domain (optional) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth (optional) |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Discord OAuth (optional) |

full list in [`.env.example`](.env.example). see [deployment guide](docs/deployment.md) for production setup.

---

## features

- [x] **vault**: AES-256-GCM encrypted wallets, EVM (7 chains) + Solana
- [x] **policy engine**: 6 composable types (spending-limit, approved-addresses, rate-limit, time-window, auto-approve-threshold, allowed-chains)
- [x] **auth**: passkeys (WebAuthn), email magic links, SIWE, Google OAuth, Discord OAuth
- [x] **JWT sessions**: access + refresh token rotation, revoke single/all sessions
- [x] **cross-tenant identity**: one user, one wallet, multiple apps
- [x] **multi-tenant API**: full tenant isolation at middleware + DB level
- [x] **proxy gateway**: credential injection, alias system, spend tracking, audit trail
- [x] **React components**: login widget, wallet overview, policy controls, approval queue
- [x] **TypeScript SDK**: typed client, browser + Node, all wallet/policy/auth ops
- [x] **ELIZA OS plugin**: sign, transfer, balance, approval evaluator
- [x] **embedded mode**: PGLite, zero third-party dependencies, same API surface
- [x] **docker**: multi-stage Dockerfile, docker-compose with Postgres + Redis
- [x] **webhooks**: HMAC-signed events (tx.signed, tx.pending, policy.violation, etc.)
- [x] **per-tenant CORS**: configurable allowed origins per tenant

---

## what Steward offers

- **open source.** MIT licensed, full source available.
- **self-hostable.** docker, embedded PGLite, or hosted.
- **full auth surface.** passkey / email / SIWE / OAuth.
- **policy evaluation in governed API routes.** 6 composable rule types are evaluated before those routes call the vault. The vault primitive is not an independent policy boundary.
- **agent-native.** built from day one for autonomous operation: approval queues, audit log, kill-switch.
- **credential proxy.** inject keys for any third-party API. agents never see raw secrets.

---

## supported chains

Ethereum, Base, Polygon, Arbitrum, BSC, Gnosis, Base Sepolia, BSC Testnet, Solana, Bitcoin,
Monero (self-hosted deployments; official `monero-wallet-rpc` sidecar against remote public
nodes: keys never leave your host, policy evaluated by the relay route)

---

## integrations

- [ElizaOS](https://elizaos.ai) (via [`@stwd/eliza-plugin`](https://www.npmjs.com/package/@stwd/eliza-plugin))
- wagmi v2 and v3, with a first-class MetaMask Connect (EVM) connector
- Model Context Protocol (MCP) server for AI agents and IDEs

---

## contributing

see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR guidelines.

## links

- website: [steward.fi](https://steward.fi)
- docs: [docs.steward.fi](https://docs.steward.fi)
- npm: [@stwd/sdk](https://www.npmjs.com/package/@stwd/sdk), [@stwd/react](https://www.npmjs.com/package/@stwd/react), [@stwd/eliza-plugin](https://www.npmjs.com/package/@stwd/eliza-plugin)

## license

[MIT](LICENSE)

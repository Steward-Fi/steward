# Steward

auth + wallet infrastructure for autonomous agents. open source. self-hostable. policy enforced at the signing layer.

[![npm](https://img.shields.io/npm/v/@stwd/sdk)](https://www.npmjs.com/package/@stwd/sdk)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![API](https://img.shields.io/badge/API-live-brightgreen)](https://api.steward.fi)
[![Docs](https://img.shields.io/badge/docs-steward.fi-blue)](https://docs.steward.fi)

---

## the problem

AI agents need wallet keys, API keys, database credentials. today these live as plaintext environment variables, one prompt injection away from exfiltration. no spending controls, no audit trail, no kill switch.

existing embedded-wallet platforms were built for consumer apps, not agents. they're closed source, can't be self-hosted, charge per-transaction fees, and have no concept of policy enforcement or autonomous operation.

## the solution

Steward sits between agents and everything they access. four pillars:

1. **vault.** AES-256-GCM encrypted keys. EVM (7 chains) + Solana. keys never exist in plaintext outside a signing operation.
2. **policy engine.** 6 composable rule types evaluated before every action. spending limits, rate limits, address whitelists, time windows, auto-approve thresholds.
3. **auth.** passkeys, email magic links, SIWE, Google/Discord OAuth. JWT sessions with refresh token rotation.
4. **proxy gateway.** credential injection for any third-party API. agents never see raw keys. full audit trail.

## how it works in practice

an agent (or the app delegating to one) holds only a Steward URL and a scoped JWT. it never holds private keys. when it wants to act, its LLM sends a signing request; the policy engine evaluates the request against the agent's policy; the vault signs or refuses; an audit event is emitted either way.

the key never reaches the model, and compromised app code cannot exceed the policy. spend caps, allowlists, rate limits, and an atomic freeze switch are enforced in the vault itself, before any signature is produced.

---

## architecture

```
agent / app              Steward                        third-party
┌─────────────┐    ┌──────────────────────┐    ┌──────────────────┐
│ STEWARD_URL │───>│ auth (JWT/passkey)   │    │ chains (EVM/Sol) │
│ STEWARD_JWT │    │ policy engine        │───>│ OpenAI/Anthropic │
│             │    │ wallet vault         │    │ any API          │
│ no API keys │    │ secret vault         │    └──────────────────┘
│ no priv keys│    │ proxy gateway        │
└─────────────┘    │ audit log            │
                   └──────────────────────┘
```

---

## quick start

```bash
npm install @stwd/sdk
```

```typescript
import { StewardClient } from "@stwd/sdk";

const steward = new StewardClient({
  baseUrl: "https://api.steward.fi",
  apiKey: "stw_your_tenant_key",
  tenantId: "my-app",
});

// create an agent with EVM + Solana wallets
const agent = await steward.createWallet("trading-bot", "Trading Bot");
console.log(agent.walletAddresses); // { evm: "0x...", solana: "..." }

// sign a transaction (policy-enforced)
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
      auth={{ baseUrl: "https://api.steward.fi" }}
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
- **policy enforcement at the vault layer.** 6 composable rule types evaluated before any signature is produced. compromised app code cannot bypass.
- **agent-native.** built from day one for autonomous operation: approval queues, audit log, kill-switch.
- **credential proxy.** inject keys for any third-party API. agents never see raw secrets.

---

## supported chains

Ethereum, Base, Polygon, Arbitrum, BSC, Base Sepolia, BSC Testnet, Solana

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
- API: [api.steward.fi](https://api.steward.fi)
- npm: [@stwd/sdk](https://www.npmjs.com/package/@stwd/sdk), [@stwd/react](https://www.npmjs.com/package/@stwd/react), [@stwd/eliza-plugin](https://www.npmjs.com/package/@stwd/eliza-plugin)

## license

[MIT](LICENSE)

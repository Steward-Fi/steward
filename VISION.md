# Steward — Open-Source Privy Replacement for Agents

**An open-source, agent-first auth + wallet infrastructure.**
Passkey login. Embedded wallets. Policy enforcement. No vendor lock-in.

---

## What Steward Becomes

Privy solves two problems: *auth* (let anyone log in) and *wallets* (give everyone a wallet without crypto knowledge). It's great, but it's closed-source, expensive at scale, and has zero policy enforcement — every RPC call is a blind passthrough.

Steward replaces both, open source, with an agent-first design:

| Feature | Privy | Steward |
|---|---|---|
| Login methods | Email, wallet, OAuth | **Passkeys**, email, wallet, OAuth |
| Embedded wallets | ✅ (Privy KMS) | ✅ (self-custodied, AES-256-GCM) |
| Policy enforcement | ❌ | ✅ (5 policy types, composable) |
| Approval workflows | ❌ | ✅ (manual approval queue) |
| Multi-tenant | ❌ (single app) | ✅ (tenant isolation, per-tenant keys) |
| Agent-first design | ❌ (user-first) | ✅ (agents are first-class entities) |
| Transaction history | ❌ | ✅ (full audit trail per agent) |
| Webhooks | ❌ | ✅ (signed, retried, event-typed) |
| Open source | ❌ | ✅ (MIT) |
| Self-hostable | ❌ | ✅ (single binary + postgres) |
| Vendor lock-in | Privy controls your keys | You control everything |

The pitch: **"What if Privy was open-source, agent-native, and had spending limits?"**

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        @steward/auth                          │
│                                                               │
│  Passkeys (WebAuthn)  ·  SIWE  ·  OAuth  ·  Email/Magic Link │
│  Session management   ·  JWT tokens  ·  User ↔ wallet mapping │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                        @steward/vault                          │
│                                                               │
│  Key generation  ·  AES-256-GCM encryption  ·  Signing        │
│  Multi-chain (EVM + Solana)  ·  Ephemeral decryption          │
│  Pluggable backends: local encrypted | AWS KMS | Hashicorp    │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                    @steward/policy-engine                      │
│                                                               │
│  spending-limit  ·  approved-addresses  ·  rate-limit         │
│  time-window  ·  auto-approve-threshold  ·  custom evaluators │
│  Composable: all policies must pass for auto-approval         │
│  Manual approval queue for flagged transactions               │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                        @steward/api                            │
│                                                               │
│  Hono REST API  ·  Multi-tenant  ·  Platform + tenant auth    │
│  Agent CRUD  ·  Policy CRUD  ·  Vault signing  ·  Approvals   │
│  Transaction history  ·  Webhook dispatch  ·  SIWE sessions   │
└──────────────────────────┬───────────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────────┐
│                        @steward/sdk                            │
│                                                               │
│  TypeScript client  ·  createWallet  ·  signTransaction       │
│  getPolicies  ·  setPolicies  ·  getBalance  ·  signMessage   │
│  Batch operations  ·  Error handling  ·  Type-safe             │
└──────────────────────────────────────────────────────────────┘
```

---

## What Exists Today (Inventory)

### ✅ Built and Working
- **@steward/vault** — key generation, AES-256-GCM encryption/decryption, ephemeral signing, multi-chain EVM support (7 chains), balance queries
- **@steward/policy-engine** — 5 policy types fully implemented (spending-limit, approved-addresses, auto-approve-threshold, time-window, rate-limit), composable evaluation
- **@steward/api** — full Hono REST API: tenant CRUD, agent CRUD, policy CRUD, vault signing, approval queue (approve/reject/pending), transaction history, webhook dispatch, SIWE auth, rate limiting, health check
- **@steward/sdk** — TypeScript HTTP client: all CRUD + signing + batch operations + balance queries + message signing
- **@steward/db** — Drizzle ORM schema, postgres, migrations
- **@steward/auth** — API key generation (stw_*), hashing (SHA-256), timing-safe validation
- **@steward/webhooks** — HMAC-signed dispatch, retry with exponential backoff, event filtering
- **@steward/shared** — types, chain metadata, constants
- **Waifu bridge** — integration adapter with default policy templates
- **E2E integration example** — full lifecycle demo (provision → policy → sign → approve → reject → history → webhooks)
- **Deployed** — API running on milady VPS as systemd service, live at api.steward.fi via cloudflared
- **Web** — Next.js landing page deployed to Vercel at steward.fi

### ❌ Not Built Yet
- **Passkey auth** — WebAuthn/passkey registration + verification
- **Email auth** — magic link or OTP flow
- **OAuth providers** — Google, Discord, GitHub login
- **User wallets** — currently only "agent wallets" exist; need "user wallets" that auto-create on signup
- **Solana support** — schema + vault support EVM only; need Ed25519 keygen + signing
- **Platform-level auth** — a master API key for platforms (like Eliza Cloud) to manage all tenants
- **Auth.js integration** — NextAuth v5 adapter for Steward auth
- **React components** — login widget, wallet widget, policy management UI
- **Key storage backends** — currently only local encrypted postgres; need pluggable (AWS KMS, Hashicorp Vault)
- **Eliza Cloud bridge** — wallet methods in the agent container bridge protocol

---

## What Needs to Be Built

### Phase 1: Auth Layer (The Privy Replacement Core)

This is the biggest gap. Steward has wallet infra but no user-facing auth beyond SIWE and API keys.

#### 1a. Passkey Auth (`@steward/auth` expansion)

```
New files:
  packages/auth/src/passkey.ts        — WebAuthn registration + verification
  packages/auth/src/session.ts        — JWT session management (expand existing)
  packages/db/src/schema.ts           — add: users, authenticators, sessions tables
```

**Schema additions:**
```sql
-- Users (central identity, decoupled from tenants)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE,
  email_verified BOOLEAN DEFAULT false,
  name VARCHAR(255),
  image TEXT,
  wallet_address VARCHAR(128),           -- linked external wallet (optional)
  steward_wallet_id VARCHAR(64),         -- auto-created embedded wallet
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- WebAuthn credentials (passkeys)
CREATE TABLE authenticators (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,     -- base64url-encoded
  credential_public_key TEXT NOT NULL,    -- base64url-encoded
  counter INTEGER NOT NULL DEFAULT 0,
  credential_device_type VARCHAR(32),     -- 'singleDevice' or 'multiDevice'
  credential_backed_up BOOLEAN DEFAULT false,
  transports TEXT[],                       -- e.g. ['internal', 'hybrid']
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Sessions
CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_token TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- OAuth accounts (for Google, Discord, GitHub)
CREATE TABLE accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider VARCHAR(64) NOT NULL,          -- 'google', 'discord', 'github'
  provider_account_id VARCHAR(255) NOT NULL,
  access_token TEXT,
  refresh_token TEXT,
  expires_at INTEGER,
  UNIQUE(provider, provider_account_id)
);
```

**Passkey flow:**
```typescript
// packages/auth/src/passkey.ts
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

export class PasskeyAuth {
  private rpName: string;    // "Steward" or platform name
  private rpID: string;      // "steward.fi" or platform domain
  private origin: string;    // "https://steward.fi"

  // Registration: user enters email → browser prompts biometric → credential stored
  async startRegistration(userId: string, email: string): Promise<RegistrationOptions> { ... }
  async finishRegistration(userId: string, response: RegistrationResponse): Promise<void> { ... }

  // Authentication: user enters email → browser prompts biometric → session created
  async startAuthentication(email: string): Promise<AuthenticationOptions> { ... }
  async finishAuthentication(response: AuthenticationResponse): Promise<SessionToken> { ... }
}
```

**On successful first login, auto-create embedded wallet:**
```typescript
async function onUserCreated(user: User): Promise<void> {
  const vault = getVault();
  const agent = await vault.createAgent(
    `user-${user.id}`,  // tenant = user themselves
    `wallet-${user.id}`,
    `${user.email || user.name}'s Wallet`
  );
  await db.update(users)
    .set({ steward_wallet_id: agent.id })
    .where(eq(users.id, user.id));
}
```

#### 1b. Email Auth (Magic Link / OTP)

```
New files:
  packages/auth/src/email.ts           — magic link or OTP generation + verification
  packages/auth/src/email-provider.ts  — Resend/SendGrid/SMTP adapter
```

Two modes:
- **Magic link:** generate token → email link → click → verify → session
- **OTP:** generate 6-digit code → email → user enters code → verify → session

Magic link is simpler for v1. OTP is better UX (no inbox context switch).

#### 1c. OAuth Providers

```
New files:
  packages/auth/src/oauth/google.ts
  packages/auth/src/oauth/discord.ts
  packages/auth/src/oauth/github.ts
  packages/auth/src/oauth/base.ts      — shared OAuth2 flow
```

Standard OAuth2 code flow. Each provider needs:
- Client ID + secret (env vars)
- Authorization URL → redirect → callback → token exchange → user info → session

#### 1d. Auth.js Adapter (for Next.js platforms)

```
New package:
  packages/auth-nextjs/                — Auth.js v5 adapter
    src/index.ts                       — DrizzleAdapter + Steward session callbacks
    src/passkey-provider.ts            — Custom credentials provider wrapping PasskeyAuth
```

This lets any Next.js app use Steward as its auth backend with one import:
```typescript
import { StewardAuth } from "@steward/auth-nextjs";

export const { handlers, signIn, signOut, auth } = StewardAuth({
  stewardUrl: process.env.STEWARD_API_URL,
  providers: ["passkey", "google", "discord"],
  // auto-creates embedded wallet on first login
  autoCreateWallet: true,
});
```

### Phase 2: Wallet Enhancements

#### 2a. User Wallets (vs Agent Wallets)

Currently Steward only has "agent wallets" scoped to tenants. Need "user wallets" that:
- Auto-create on first login
- Belong to the user, not a tenant
- Can be used across tenants (user's personal wallet)
- Support embedded wallet UX (user never sees a private key)

**Schema change:**
```sql
ALTER TABLE agents ADD COLUMN owner_user_id UUID REFERENCES users(id);
ALTER TABLE agents ADD COLUMN wallet_type VARCHAR(32) DEFAULT 'agent';
-- wallet_type: 'agent' (platform-managed) | 'user' (user's embedded wallet)
```

#### 2b. Solana Support

```
Modified files:
  packages/vault/src/vault.ts          — add Ed25519 keygen via @solana/web3.js
  packages/vault/src/keystore.ts       — same encryption, different key format
  packages/shared/src/index.ts         — add Solana chain metadata
  packages/db/src/schema.ts            — chain_type field already exists
```

The vault already stores encrypted bytes. Solana just needs:
- `Keypair.generate()` instead of `generatePrivateKey()`
- `nacl.sign()` instead of viem signing
- Base58 address format instead of hex

#### 2c. Pluggable Key Storage

```
New files:
  packages/vault/src/backends/local.ts    — current AES-256-GCM (default)
  packages/vault/src/backends/aws-kms.ts  — AWS KMS integration
  packages/vault/src/backends/hashicorp.ts — Hashicorp Vault integration
  packages/vault/src/backend.ts            — interface definition
```

```typescript
interface KeyStorageBackend {
  store(agentId: string, privateKey: string): Promise<void>;
  retrieve(agentId: string): Promise<string>;
  delete(agentId: string): Promise<void>;
}
```

The existing KeyStore becomes `LocalEncryptedBackend`. AWS KMS and Hashicorp become optional backends for enterprises that need HSM-grade security.

### Phase 3: Platform Integration Layer

#### 3a. Platform Auth (Master Key)

Platforms like Eliza Cloud need a single API key to manage all their tenants:

```
Modified files:
  packages/api/src/index.ts            — add platform auth middleware
  packages/auth/src/platform-keys.ts   — platform key generation + validation
```

```typescript
// Platform-level auth header
// X-Steward-Platform-Key: stw_platform_abc123...
// Allows: create tenants, manage tenants, provision agent wallets across tenants

app.use("/platform/*", platformAuth);

app.post("/platform/tenants", async (c) => { ... });
app.post("/platform/tenants/:id/agents", async (c) => { ... });
app.get("/platform/tenants/:id/agents", async (c) => { ... });
```

#### 3b. Eliza Cloud Bridge (Agent Container → Wallet)

```
Modified files (in milaidy repo):
  packages/cloud-agent/src/bridge/protocol.ts  — add wallet method types
  packages/cloud-agent/src/bridge/handlers.ts  — add wallet handlers
  packages/cloud-agent/src/bridge/server.ts    — route wallet methods
```

New bridge methods:
```typescript
"wallet.getAddress"       // → returns agent's wallet address
"wallet.getBalance"       // → returns native balance
"wallet.sendTransaction"  // → policy check → sign → broadcast
"wallet.signMessage"      // → sign arbitrary data
"wallet.getPolicies"      // → view current policies
```

These get routed: container → bridge → cloud platform → Steward API → vault.

#### 3c. React Components (Drop-in UI)

```
New package:
  packages/react/
    src/StewardProvider.tsx     — context provider
    src/LoginButton.tsx         — passkey + OAuth login widget
    src/WalletWidget.tsx        — balance display + send UI
    src/PolicyManager.tsx       — policy configuration UI
    src/ApprovalQueue.tsx       — pending approvals UI
    src/TransactionHistory.tsx  — tx history view
```

The goal: a platform adds `<StewardProvider>` and gets auth + wallet UI out of the box, similar to Privy's `<PrivyProvider>`.

### Phase 4: Eliza Cloud Migration

With phases 1-3 built, migrating Eliza Cloud off Privy is surgical:

```
Modified files (in eliza-cloud repo):
  packages/lib/providers/PrivyProvider.tsx    → DELETE, replace with StewardProvider
  packages/lib/auth/privy-client.ts          → DELETE, replace with Steward auth
  packages/lib/services/server-wallets.ts    → swap Privy calls → Steward SDK calls
  packages/db/schemas/agent-server-wallets.ts → swap privy_wallet_id → steward_agent_id
  app/api/v1/user/wallets/provision/route.ts → use Steward provisioning
  app/api/v1/user/wallets/rpc/route.ts       → use Steward RPC routing
  next.config.ts                              → remove Privy CSP rules
  .env                                        → remove PRIVY_*, add STEWARD_*
  package.json                                → remove @privy-io/*, add @steward/*
```

---

## Implementation Priority

```
IMMEDIATE (this week)
├── 1. Platform auth (master key for Eliza Cloud)
├── 2. User table + auto-wallet-on-signup
└── 3. Passkey auth (WebAuthn registration + verification)

NEXT WEEK
├── 4. Email auth (magic link via Resend)
├── 5. OAuth providers (Google, Discord)
├── 6. Auth.js adapter (@steward/auth-nextjs)
└── 7. Eliza Cloud wallet swap (Privy → Steward)

FOLLOWING WEEK
├── 8. Bridge wallet methods (agent container → Steward)
├── 9. React components (login widget, wallet widget)
├── 10. Solana support
└── 11. Full Eliza Cloud migration (remove Privy entirely)

LATER
├── 12. Pluggable key backends (AWS KMS, Hashicorp)
├── 13. Dashboard polish + docs
├── 14. npm publish (@steward/sdk, @steward/auth-nextjs, @steward/react)
└── 15. steward.fi hosted service (SaaS offering)
```

---

## Repo Structure (Target)

```
steward-fi/
├── packages/
│   ├── api/              ✅ Hono REST API
│   ├── auth/             🔧 Expand: passkeys, email, OAuth, platform keys
│   ├── auth-nextjs/      🆕 Auth.js v5 adapter
│   ├── db/               ✅ Drizzle schema (expand: users, authenticators, sessions, accounts)
│   ├── policy-engine/    ✅ 5 policy types, composable
│   ├── react/            🆕 Drop-in React components
│   ├── sdk/              ✅ TypeScript HTTP client
│   ├── shared/           ✅ Types, constants
│   ├── vault/            🔧 Expand: Solana, pluggable backends
│   └── webhooks/         ✅ HMAC-signed dispatch
├── web/                  ✅ Landing page (steward.fi)
├── examples/
│   └── waifu-integration/ ✅ Full lifecycle demo
├── docker-compose.yml
├── Dockerfile
└── README.md
```

---

## The Pitch

**For agent platforms (Eliza Cloud, waifu.fun, etc.):**
"Drop-in auth + wallet infra. Passkey login, embedded wallets, spending limits. Open source. Self-host or use our hosted service. Replace Privy in a day."

**For the ecosystem:**
"The open-source standard for agent wallet infrastructure. Policy enforcement between agent intent and on-chain execution. No more unguarded private keys in containers."

**Why it wins:**
1. Open source — no vendor lock-in, audit the code yourself
2. Agent-first — policies, approval queues, audit trails built for autonomous agents
3. Passkeys — better auth than Privy (no passwords, phishing-resistant)
4. Self-hostable — one binary + postgres, run it anywhere
5. Cost — free to self-host, fraction of Privy's pricing for hosted

---

## First Tenant: Eliza Cloud (Milady)

Eliza Cloud is the proof case. It currently uses Privy for auth + wallets. Migrating it to Steward proves the entire stack works end-to-end:

- Users log in with passkeys (or Google/Discord fallback)
- Agent sandboxes get embedded wallets with default policies
- Agents can request transactions through the bridge protocol
- Policies enforce spending limits and address whitelists
- Platform admins can approve/reject flagged transactions
- Full audit trail for every wallet operation

If it works for Eliza Cloud's scale (multi-node Docker, hundreds of agents, real money), it works for anyone.

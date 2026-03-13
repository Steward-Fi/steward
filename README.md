# Steward

**Agent wallet infrastructure with user-controlled policy enforcement.**

Give your agents wallets. Keep the keys safe. Let users set the rules.

---

## What Is This

Agents are becoming autonomous economic actors — launching tokens, earning revenue, paying for compute. But giving an agent a raw private key is insane. Custodial platforms defeat the purpose. And every team rebuilds the same signing/policy infra from scratch.

Steward solves this: a signing service that sits between an agent and its wallet.

```
Agent wants to transact
  → POST /vault/:agentId/sign { tx }
  → Steward checks user-defined policies
  → If pass: sign, broadcast, return receipt
  → If fail: queue for user approval
  → Agent NEVER touches its own private key
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────┐
│  Agent       │────▶│  Steward API │────▶│  Vault  │
│  Container   │     │  (REST)      │     │  (Keys) │
└─────────────┘     └──────┬───────┘     └─────────┘
                           │
                    ┌──────▼───────┐
                    │   Policy     │
                    │   Engine     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  ERC-8004    │
                    │  Identity    │
                    └──────────────┘
```

### Packages

| Package | Description |
|---------|-------------|
| `packages/vault` | Encrypted keystore, key generation, signing |
| `packages/policy-engine` | Transaction evaluation against user-defined rules |
| `packages/api` | REST API for agent containers |
| `packages/dashboard` | Web UI for policy management + tx history |
| `packages/contracts` | ERC-8004 identity + on-chain policy registry |
| `packages/shared` | Shared types, utils, constants |
| `web` | Landing page (steward.fi) |

## User-Defined Policies

Users control what their agents can do with money:

- **Spending limits** — max per tx, per day, per week
- **Approved addresses** — whitelist of contracts/wallets
- **Auto-approve threshold** — small txs go through, big ones need human approval
- **Time windows** — restrict trading to certain hours
- **Rate limiting** — max N transactions per time period

Policies are composable (AND/OR logic) and enforced at the signing layer.

## ERC-8004 Identity

Every agent gets an on-chain identity (ERC-721 on Base). Transaction history builds reputation. Other platforms can verify an agent's financial track record without trusting the platform that hosts it.

## Stack

- **Runtime:** TypeScript (Bun)
- **API:** Hono
- **Database:** PostgreSQL
- **Signing:** viem
- **Frontend:** Next.js
- **Chain:** Base (ERC-8004 + USDC)
- **Monorepo:** Turborepo

## Development

```bash
bun install
bun run dev
```

## License

MIT

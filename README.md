# Steward Monorepo

Steward is agent wallet infrastructure with policy enforcement. It gives agents wallet access through a controlled signing layer, so users can define what an agent may sign, when approval is required, and how activity is surfaced across the API and dashboard.

## Packages

| Path | Description |
| --- | --- |
| `web` | Next.js app for the steward.fi landing page and `/dashboard/*` product routes |
| `packages/api` | Hono API that manages tenants, agents, policies, approvals, and signing flows |
| `packages/auth` | Shared auth helpers and tenant middleware for API-facing services |
| `packages/db` | Drizzle/Postgres client, schema, and migration entrypoints |
| `packages/policy-engine` | Policy evaluation engine for transaction approval decisions |
| `packages/sdk` | TypeScript client for talking to the Steward API from agents or apps |
| `packages/shared` | Shared domain types, constants, and API contracts |
| `packages/vault` | Secure wallet creation, key custody, and transaction signing |
| `packages/webhooks` | Webhook delivery and retry queue primitives for Steward events |

## Quick Start

1. Install dependencies:

```bash
bun install
```

2. Set the environment variables used in local development:

```bash
DATABASE_URL=postgres://...
STEWARD_MASTER_PASSWORD=change-me
STEWARD_DEFAULT_TENANT_KEY=local-api-key
RPC_URL=https://mainnet.base.org
NEXT_PUBLIC_STEWARD_API_URL=http://localhost:3200
NEXT_PUBLIC_STEWARD_API_KEY=local-api-key
NEXT_PUBLIC_STEWARD_TENANT_ID=default
```

3. Start the monorepo:

```bash
bun run dev
```

The root `dev` script runs the Turborepo pipeline. The web app serves the landing page and dashboard from `web`, and the API serves local backend routes on port `3200`.

## Architecture

```text
Agent / Client App
        |
        v
  @steward/sdk
        |
        v
packages/api (Hono)
   |        |        \
   |        |         \
   v        v          v
auth     policy-engine  webhooks
   \        | 
    \       v
     ----> vault
             |
             v
          db/shared
             |
             v
         PostgreSQL / chain RPC

web (Next.js)
  |- /
  \- /dashboard/*
     consumes API + SDK contracts
```

## Development Notes

- Package management: Bun workspaces
- Task orchestration: Turborepo
- Main frontend: Next.js in `web`
- Backend/runtime: Bun + TypeScript

## License

MIT

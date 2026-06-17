# Deployment Guide

This guide describes what the current code does. It does not assume a hosted control plane or private runbook.

## Prerequisites

- Bun 1.3+ for local and bare-metal runs. This repo currently pins `bun@1.3.9` in `package.json`.
- Docker Compose v2 for the included Compose deployment.
- PostgreSQL 16 for persistent server deployments, or the embedded PGLite backend for development/local mode.
- A stable `STEWARD_MASTER_PASSWORD` before storing any wallet or secret data.

## Quickstart: Docker Compose

The root `docker-compose.yml` starts four services:

- `steward-api` on `127.0.0.1:3200`
- `steward-proxy` on `127.0.0.1:8080`
- PostgreSQL 16 on the internal Compose network
- Redis 7 on the internal Compose network

```bash
cp .env.example .env
$EDITOR .env
```

Set at least these values in `.env`:

```bash
STEWARD_MASTER_PASSWORD=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -hex 24)
STEWARD_PLATFORM_KEYS=$(openssl rand -hex 32)

# Canonical JWT signing/verification secret. Used by API, proxy, auth, and
# agent-scoped tokens. Must be ≥32 chars in production. STEWARD_SESSION_SECRET
# remains a deprecated compatibility fallback for legacy deployments.
STEWARD_JWT_SECRET=$(openssl rand -hex 32)
```

Then start the stack:

```bash
docker compose up -d
docker compose logs -f steward-api
```

Health checks:

```bash
curl http://127.0.0.1:3200/health
curl http://127.0.0.1:3200/ready
curl http://127.0.0.1:8080/health
```

`/health` is a liveness check. `/ready` verifies migrations have completed, the database is reachable, and `STEWARD_MASTER_PASSWORD` is set.

Create a platform key by generating a random value and putting it in `STEWARD_PLATFORM_KEYS` before startup. Multiple platform keys can be configured as a comma-separated list.

Create the first tenant:

```bash
PLATFORM_KEY="$(grep '^STEWARD_PLATFORM_KEYS=' .env | cut -d= -f2 | cut -d, -f1)"

curl -sS -X POST http://127.0.0.1:3200/platform/tenants \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY" \
  -d '{"id":"default","name":"Default Tenant"}'
```

The response includes the tenant API key once. Store it; the raw key is not retrievable later.

## Embedded / local dev mode

For local development without Docker, run:

```bash
bun install
bun run start:local
```

`start:local` builds the packages needed by the embedded entry point, then runs `packages/api/src/embedded.ts`. Embedded mode:

- forces `STEWARD_DB_MODE=pglite`
- uses PGLite instead of external PostgreSQL
- persists data under `~/.steward/data` by default
- runs PGLite SQL migrations before importing the API server
- auto-generates `STEWARD_MASTER_PASSWORD` if it is missing

Persistence controls:

```bash
# Custom persistent directory
STEWARD_PGLITE_PATH=/var/lib/steward bun run start:local

# In-memory only; data is lost on restart
STEWARD_PGLITE_MEMORY=true bun run start:local
```

Warning: if local mode auto-generates `STEWARD_MASTER_PASSWORD`, vault data encrypted in that process is tied to that generated value. Set a fixed `STEWARD_MASTER_PASSWORD` if you need encrypted wallet/secret data to survive restarts predictably.

## Bare-metal / systemd deployment

A bare-metal deployment runs the same API and proxy processes without Docker:

1. Install Bun 1.3+ and PostgreSQL 16.
2. Create a dedicated database/user and set `DATABASE_URL`.
3. Set required secrets in a systemd `EnvironmentFile` or a secrets manager exposed to the service.
4. Run the API command from the repo root, for example `bun run packages/api/src/index.ts`.
5. Run the proxy as a separate service, for example `bun run packages/proxy/src/index.ts`.
6. Put Caddy, nginx, or another TLS reverse proxy in front of the API and proxy if they are exposed outside localhost.

Do not rotate `STEWARD_MASTER_PASSWORD` after encrypted keys exist unless you have a migration procedure that decrypts and re-encrypts every stored value.

## Railway deployment

Railway deployment is a Docker-managed deploy of the application image plus managed Postgres and Redis services.

Use the project image convention when pulling a published image:

```text
ghcr.io/0xsolace/steward:<tag>
```

Configure the Railway service with the normal production environment plus Railway-provided connection URLs:

- `DATABASE_URL` from Railway Postgres
- `REDIS_URL` from Railway Redis
- `STEWARD_MASTER_PASSWORD`
- `STEWARD_PLATFORM_KEYS`
- `STEWARD_JWT_SECRET` (canonical; `STEWARD_SESSION_SECRET` accepted as deprecated fallback)
- public URL related settings such as `APP_URL`, `PASSKEY_RP_ID`, and `PASSKEY_ORIGIN`

Run the proxy as a separate Railway service/process using the same image and command `bun run packages/proxy/src/index.ts`, with `STEWARD_PROXY_PORT` set to the port Railway expects for that service.

A hosted instance at `api.steward.fi` is run by the project for trusted testers. Self-hosted deployments should not depend on it for operator workflows.

### Automated Railway deploys via GitHub Actions (optional)

The repo ships reference deploy workflows (`deploy-staging.yml`, `deploy-railway.yml`)
but **bakes no deployment target into source** — Steward is sovereign and
self-hostable, so every instance points the workflows at its **own** Railway via
repo configuration. To use them on your own fork/instance, set these GitHub repo
**variables** (Settings → Secrets and variables → Actions → Variables) and the
`RAILWAY_TOKEN` **secret**:

| name | kind | meaning |
| --- | --- | --- |
| `RAILWAY_TOKEN` | secret | Railway API token for your project |
| `STAGING_RAILWAY_SERVICE_ID` / `_ENV_ID` / `_HEALTH_URL` | vars | your staging service/env/health URL |
| `PRODUCTION_RAILWAY_SERVICE_ID` / `_ENV_ID` / `_HEALTH_URL` | vars | your production service/env/health URL |

Branch model the workflows assume: `develop` auto-deploys to **staging** (after a
green Docker build); `main` is promoted to **production** manually via the gated
`Deploy Railway (Production)` workflow (bind a protected `Production` GitHub
environment with required reviewers). If the variables are unset, the deploy
script fails closed rather than shipping to a default target.

Downstream consumers (e.g. an eliza-cloud deployment) run their **own** instance
this way with their own Railway + variables; they do not deploy from or depend on
any other operator's instance.

## Environment variable reference

| Variable | Purpose | Default | Validation / production rule |
| --- | --- | --- | --- |
| `PORT` | API listen port | `3200` | Must parse as a positive integer. |
| `STEWARD_BIND_HOST` | API bind address | `127.0.0.1` | Use `0.0.0.0` only behind a firewall/reverse proxy. Compose sets this to `0.0.0.0` inside the container. |
| `DATABASE_URL` | PostgreSQL connection string | none; PGLite selected when absent/forced in embedded paths | Required by the normal API entry point because `context.ts` calls `requireEnv("DATABASE_URL")`; embedded mode supplies `pglite://embedded` internally. |
| `STEWARD_DB_MODE` | Force database backend | auto | Set to `pglite` to force PGLite. |
| `STEWARD_PGLITE_PATH` | PGLite persistence directory | `~/.steward/data` | Used only by PGLite. |
| `STEWARD_PGLITE_MEMORY` | Use in-memory PGLite | `false` | Set exactly `true`; data is discarded on restart. |
| `STEWARD_MASTER_PASSWORD` | Root secret for vault encryption and JWT fallback | none | Required by normal API startup; production throws without it. Use a long random value and keep it stable. |
| `STEWARD_KDF_SALT` | Deployment salt for scrypt master-key derivation | legacy built-in salt | Hex string; at least 32 hex chars recommended. Production warns when absent. |
| `STEWARD_JWT_SECRET` | Canonical JWT signing/verification secret used by API, proxy, auth routes, user sessions, agent-scoped tokens | falls back to `STEWARD_SESSION_SECRET` (deprecated) then `STEWARD_MASTER_PASSWORD` in embedded/dev mode | Required in production; must be ≥32 characters. Set separately from master password. |
| `STEWARD_SESSION_SECRET` | Deprecated. Backward-compatibility fallback for `STEWARD_JWT_SECRET` | none | Deployments should rename to `STEWARD_JWT_SECRET`. Will be removed in a future release. |
| `AGENT_TOKEN_EXPIRY` | Expiry for agent-scoped JWTs | API context: `30d`; `.env.example`/Compose set `24h` | Must be accepted by `jose` `setExpirationTime`, e.g. `24h`, `7d`. |
| `STEWARD_PLATFORM_KEYS` | Comma-separated platform operator keys for `/platform/*` | none | Required to use platform routes. Each request sends one key in `X-Steward-Platform-Key`. |
| `STEWARD_DEFAULT_TENANT_KEY` | API key hash/plain value field for the default tenant bootstrap path | empty string | Only useful for single/default tenant setups. Platform-created tenants return generated API keys. |
| `RPC_URL` | Default EVM RPC URL | `https://sepolia.base.org` in API/vault code; Compose sets Base mainnet | Must be reachable for balance/broadcast operations. |
| `CHAIN_ID` | Default EVM chain id | `84532` in auth/platform context, `8453` in some vault routes; Compose sets `8453` | Must parse as an integer. Prefer setting explicitly. |
| `REDIS_URL` | Redis for rate limiting, token/challenge stores, proxy spend tracking/cache | none | Optional, but recommended for production. Without it some stores are in-memory or Postgres-backed depending on startup state. |
| `RESEND_API_KEY` | Email magic-link delivery | none | If absent, email auth logs/dev-returns tokens instead of sending mail. |
| `EMAIL_FROM` | Magic-link sender | `login@steward.fi` | Must be accepted by Resend when email delivery is enabled. |
| `APP_URL` | Public base URL for auth links/callbacks | `https://steward.fi` | Set to your app/API-facing URL for magic links. |
| `EMAIL_AUTH_REDIRECT_BASE_URL` | Redirect base used by one email-auth callback path | `https://www.elizacloud.ai` | Set if using that callback flow. |
| `PASSKEY_RP_NAME` | WebAuthn relying-party display name | `Steward` | Browser-visible string. |
| `PASSKEY_RP_ID` | WebAuthn relying-party domain | `steward.fi` | Must match the registration/authentication domain. |
| `PASSKEY_ORIGIN` | Expected WebAuthn origin | `https://steward.fi` | Must match browser origin. |
| `PASSKEY_ALLOWED_ORIGINS` | Additional comma-separated passkey origins | falls back to `PASSKEY_ORIGIN` | Must contain exact origins. |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth | none | Required only for Google OAuth. |
| `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET` | Discord OAuth | none | Required only for Discord OAuth. |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub OAuth | none | Present in `.env.example`; only useful where corresponding routes are enabled. |
| `TWITTER_CLIENT_ID` / `TWITTER_CLIENT_SECRET` | Twitter/X OAuth | none | Required only for Twitter/X OAuth. |
| `SIWE_ALLOWED_DOMAINS` | Optional SIWE domain allowlist | none | Comma-separated domains; when set, SIWE messages must match. |
| `STEWARD_PROXY_PORT` | Proxy listen port | `8080` | Must parse as an integer. Compose exposes `127.0.0.1:8080` by default. |
| `NEXT_PUBLIC_STEWARD_API_URL` | Browser-facing API URL for the Next.js web app | `http://localhost:3200` | Used by `web/`, not the API process. |
| `NEXT_PUBLIC_WC_PROJECT_ID` | WalletConnect project id for the web app | none | Used by `web/`. |
| `STEWARD_PROXY_URL` | Proxy URL used by web/server-side app code | `http://localhost:8080` in local Compose | Should match the exposed proxy URL. |
| `STEWARD_AGENT_TOKEN` | Agent token for web/server-side routes | none | Required only by app paths that call Steward as an agent. |
| `SKIP_MIGRATIONS` | Disable API startup migrations | false | Set `true` or `1` only when another process applies migrations. |

## Migration behavior

Migrations run automatically on startup unless `SKIP_MIGRATIONS=true` or `SKIP_MIGRATIONS=1`.

- Normal PostgreSQL mode calls the Drizzle migrator from `packages/db/src/migrate.ts` against `packages/db/drizzle` before the API serves traffic.
- PGLite mode does not run the Postgres migrator in `index.ts`. Instead, `packages/db/src/pglite.ts` replays `.sql` files from `packages/db/drizzle` in lexicographic order and tracks applied files in `__steward_migrations`.
- If a PostgreSQL migration fails at startup, the API exits instead of serving with a partially migrated schema.

Only set `SKIP_MIGRATIONS` when you have a separate migration job and can guarantee it completed before the API starts.

## Upgrades

For Compose deployments:

```bash
docker compose pull
docker compose up -d
curl http://127.0.0.1:3200/ready
```

If you build locally instead of pulling an image:

```bash
git pull
docker compose build
docker compose up -d
```

Database migrations auto-apply during API startup. Back up Postgres before upgrades, especially before schema changes that affect vault, auth, or tenant tables.

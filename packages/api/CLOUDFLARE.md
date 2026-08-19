# Steward API on Cloudflare Workers

Steward now ships three runtime adapters that share the same Hono app
(`packages/api/src/app.ts`):

| Adapter        | Entry point                          | Use case                                                          |
| -------------- | ------------------------------------ | ----------------------------------------------------------------- |
| Bun (existing) | `packages/api/src/index.ts`          | Production server with TCP Postgres + ioredis. Long-lived process.|
| PGLite         | `packages/api/src/embedded.ts`       | Electrobun / desktop. In-process WASM Postgres, no external deps.  |
| Workers (new)  | `packages/api/src/worker.ts`         | Cloudflare Workers. Request-owned Neon WebSocket Postgres + REST Redis (Upstash). |

The adapters are additive — switching to Workers does NOT change the Bun
or PGLite paths.

## Architecture

- **DB driver** is selected by the `DATABASE_DRIVER` env var. Production uses
  `neon-websocket` so every authenticated request can own one tenant-scoped
  transaction; `neon-http` is limited to local/test compatibility:
  - `postgres-js` (default): TCP pool, used by Bun/Node.
  - `neon-websocket`: request-owned Neon pool, used by production Workers.
  - `neon-http`: local/test compatibility only; production Worker boot rejects it.
  - PGLite (set via `setPGLiteOverride()` in `embedded.ts`).
- **Redis** is selected by `REDIS_DRIVER`:
  - `ioredis` (default): persistent TCP connection, used by Bun/Node.
  - `upstash`: REST adapter (`packages/redis/src/upstash-adapter.ts`)
    around `@upstash/redis`. Same ioredis-shaped surface, fetch-based.
- **JWT verification** stays local using `jose` (HMAC HS256) — works the
  same on Workers.
- **SIWE / SIWS nonces** go through the pluggable `StoreBackend` abstraction
  (`packages/auth/src/store-backends.ts`). On Workers this resolves to
  Upstash; on Bun it resolves to ioredis or Postgres `auth_kv_store`.
- **Migrations** never run inside the Worker. The Bun entry runs them at
  boot unless `SKIP_MIGRATIONS=1`. Workers expect migrations to be applied
  out-of-band via `bun run migrate:neon` (see
  `packages/db/CLOUDFLARE.md`).
- **No setInterval** in the worker entry. All TTL-based cleanup
  (auth challenges, SIWE nonces, rate-limit windows) is enforced by the
  backing store (Upstash / Postgres native expiry).

### Per-request usage on Workers

The Worker entry creates one Neon WebSocket handle per request and binds it to
the async request context. Authenticated middleware then pins downstream
`getDb()` calls to one tenant transaction on that handle. The entry owns and
awaits cleanup; route code must not create or retain its own socket pool.

```ts
import { createNeonTransactionDbForRequest, withRequestDatabase } from "@stwd/db";

const handle = createNeonTransactionDbForRequest(env);
try {
  return await withRequestDatabase(handle.db, () => app.fetch(request, env));
} finally {
  await handle.close();
}
```

Steward's `worker.ts` already owns this lifecycle; the snippet documents the
required shape for alternate Worker composition roots.

## One-time setup

1. Cloudflare account + `wrangler login`.
2. Provision a Neon project and copy the TCP-capable connection string for
   migrations (e.g. `postgres://...neon.tech/db?sslmode=require`).
3. Provision an Upstash Redis database and copy `KV_REST_API_URL` +
   `KV_REST_API_TOKEN`.
4. (Optional) Reserve any custom domains in Cloudflare so you can attach
   them later.

## Secrets

Set these via `wrangler secret put <NAME>` from the `packages/api`
directory. Do NOT put them in `wrangler.toml`.

Wrangler secrets are scoped per environment. Configure the unqualified,
staging, and production Workers separately; setting one does not populate the
others:

```bash
bunx wrangler secret put STEWARD_JWT_SECRET
bunx wrangler secret put STEWARD_JWT_SECRET --env staging
bunx wrangler secret put STEWARD_JWT_SECRET --env production
```

Repeat those three commands for every sensitive binding below. Put non-secret
bindings such as `APP_URL` and `STEWARD_IDENTITY_JWT_ISSUER` in the matching
Wrangler `[vars]` table for each environment. The committed default, staging,
and production variable sets all declare
`NODE_ENV=production`, so a missing or shorter-than-32-character JWT secret is
rejected before any database handle is selected.

| Binding                         | Why                                                                    |
| ------------------------------- | ---------------------------------------------------------------------- |
| `DATABASE_URL`                  | Neon connection string. Workers use request-owned WebSockets; migrations use the same PostgreSQL endpoint out of band. |
| `KV_REST_API_URL`               | Upstash REST endpoint.                                                 |
| `KV_REST_API_TOKEN`             | Upstash REST token.                                                    |
| `STEWARD_JWT_SECRET`            | Canonical HS256 JWT signing and verification secret. Minimum 32 characters in production. |
| `STEWARD_MASTER_PASSWORD`       | Vault keystore master password. Used by `KeyStore` (AES-256-GCM).      |
| `STEWARD_KDF_SALT`              | Per-deployment hex salt for the KeyStore KDF. Required in production.  |
| `STEWARD_AUDIT_HMAC_KEY`        | Separate high-entropy root for the tamper-evident audit chain. Required in production. |
| `STEWARD_IDENTITY_JWT_PRIVATE_KEY` | Optional PKCS#8 RS256/ES256 identity-token key. Set separately in each environment that serves identity tokens. |
| `RESEND_API_KEY`                | Magic-link email delivery.                                             |
| `EMAIL_FROM`                    | Optional: from address for magic links.                                |
| `APP_URL`                       | Canonical HTTPS public base for identity discovery/tokens and magic links. Required unless `STEWARD_IDENTITY_JWT_ISSUER` is set. |
| `STEWARD_IDENTITY_JWT_ISSUER`   | Optional dedicated canonical HTTPS identity base. Required when `APP_URL` is absent. |
| `EMAIL_AUTH_REDIRECT_BASE_URL`  | Optional: where to redirect after email auth (defaults elizacloud.ai). |
| `GOOGLE_CLIENT_ID`/`_SECRET`    | Google OAuth.                                                          |
| `DISCORD_CLIENT_ID`/`_SECRET`   | Discord OAuth.                                                         |
| `GITHUB_CLIENT_ID`/`_SECRET`    | GitHub OAuth.                                                          |
| `TWITTER_CLIENT_ID`/`_SECRET`   | Twitter/X OAuth (PKCE).                                                |
| `PASSKEY_RP_ID`                 | WebAuthn relying-party ID (your apex domain).                          |
| `PASSKEY_ORIGIN`                | WebAuthn origin (https://...).                                         |
| `PASSKEY_RP_NAME`               | Display name for the WebAuthn UI.                                      |
| `PASSKEY_ALLOWED_ORIGINS`       | Optional comma-separated additional origins for multi-tenant passkeys. |

When asymmetric identity tokens are enabled, put the private key in the
environment-scoped secret above and configure the matching non-secret
`STEWARD_IDENTITY_JWT_ALG`, `STEWARD_IDENTITY_JWT_KID`,
`STEWARD_IDENTITY_JWT_ISSUER`, and `STEWARD_IDENTITY_JWT_AUDIENCE` variables in
each Wrangler environment. Do not reuse one environment's issuer or private
key in another environment.

`SKIP_MIGRATIONS=1`, `DATABASE_DRIVER=neon-websocket`, and `REDIS_DRIVER=upstash`
are already in `wrangler.toml` `[vars]` so they ship with every deploy.

Non-secret client-IP trust config (auth rate limiting) can go in `[vars]`:
`STEWARD_TRUST_CLOUDFLARE=true` (Workers always sit behind Cloudflare, so
`cf-connecting-ip` is authoritative here), or `STEWARD_TRUSTED_PROXY_HOPS=<n>`
when a different appending proxy chain fronts the worker. Optional
`STEWARD_AUTH_RATE_LIMIT_OUTAGE_VALVE_MAX` bounds auth admissions per minute
per isolate while a configured Upstash is unreachable (default 300, `0` =
strict fail-closed). See `packages/api/src/routes/auth.ts`
(`trustedClientIp`).

On the Railway deploy (no Cloudflare in front), `STEWARD_TRUSTED_PROXY_HOPS=2`
is REQUIRED, not optional (Railway's edge adds two `x-forwarded-for` entries and
the right-most one rotates between nodes, so the client is the 2nd from the
right — verified against prod). Until it is set, auth rate limits fall back to
coarse per-host buckets, which are weaker on a directly-exposed
(non-Host-locked) service. See `docs/deploy/railway-lean-full.md`.

## Migrations

```bash
cd packages/db
DATABASE_URL="postgres://...neon.tech/db?sslmode=require" bun run migrate:neon
```

Run this BEFORE `wrangler deploy` so the schema is up to date when traffic
arrives. See `packages/db/CLOUDFLARE.md` for the deeper rationale and CI
example.

## Deploy

```bash
cd packages/api

# Local smoke test (boots a workerd instance against your local secrets):
cp .dev.vars.example .dev.vars
# Replace the database and Upstash placeholders in .dev.vars first.
bunx wrangler dev

# Real deploy to staging or prod:
bunx wrangler deploy --env staging
bunx wrangler deploy --env production
```

`wrangler deploy --dry-run --outdir=dist` (or `bun run wrangler:dry-run`)
builds the worker bundle without uploading. The lockfile's Wrangler 4.105.0
currently reports **6.88 MiB raw / 1.85 MiB gzipped** — comfortably under the
10 MiB compressed Workers limit.

## Testing locally

`wrangler dev` boots a local workerd instance with full nodejs_compat. The
committed deployment vars intentionally enforce production validation, so
local development must copy `.dev.vars.example` to the ignored `.dev.vars`.
That file explicitly selects `NODE_ENV=development` and opts into development
secret fallbacks; never use it for a shared preview or deployment. Replace its
database and Upstash placeholders before starting workerd. To exercise the
production posture locally instead, remove the development override and set
complete high-entropy roots, including `STEWARD_JWT_SECRET`,
`STEWARD_MASTER_PASSWORD`, `STEWARD_KDF_SALT`, and
`STEWARD_AUDIT_HMAC_KEY`.

Example production-like `.dev.vars` shape:

```
DATABASE_URL=postgres://USER:PASS@ep-XYZ.us-east-2.aws.neon.tech/db?sslmode=require
KV_REST_API_URL=https://YOUR-DB.upstash.io
KV_REST_API_TOKEN=YOUR_TOKEN
STEWARD_JWT_SECRET=...
STEWARD_MASTER_PASSWORD=...
STEWARD_KDF_SALT=...
STEWARD_AUDIT_HMAC_KEY=...
RESEND_API_KEY=...
```

## Known limitations

- **No long-lived background work.** Workers don't allow `setInterval`,
  background fetches outside `ctx.waitUntil()`, or persistent connections.
  The Bun entry's IP rate-limit GC and SIWE nonce GC have been replaced by
  TTL-driven cleanup in the storage backends. Anything new that needs a
  cron should use Cloudflare Cron Triggers (add a `scheduled()` handler in
  `worker.ts`).
- **Per-request DB client.** Each request owns a max=1 WebSocket pool so tenant
  context and route SQL stay on one transaction connection. For very high QPS,
  evaluate Hyperdrive with the same transaction and cleanup invariants.
- **No `node:fs` at runtime.** PGLite, the Drizzle file-based migrator,
  and any code that reads from the SQL migrations folder cannot run on a
  Worker. The pluggable factories make sure these paths are dead-code in
  the worker bundle.
- **Web Crypto vs node:crypto.** All current usages
  (`createCipheriv`, `randomBytes`, `scryptSync`, `createPublicKey`,
  `verify`) are supported under `nodejs_compat` (released GA September
  2024). Inline comments at each import site document the verification
  status and a tweetnacl/`crypto.subtle` fallback in case any path fails
  in practice.

## When to fall back

- **Heavy CPU work** (e.g. raising `scryptSync` N to 65536+) may exceed
  the default 10 ms CPU budget. Bump the budget via Cloudflare paid plans
  or move the work off the request path.
- **WebSockets / streaming** — Workers support both, but Steward's API is
  request/response only today.

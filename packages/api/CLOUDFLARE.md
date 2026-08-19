# Steward API on Cloudflare Workers

Steward now ships three runtime adapters that share the same Hono app
(`packages/api/src/app.ts`):

| Adapter        | Entry point                          | Use case                                                          |
| -------------- | ------------------------------------ | ----------------------------------------------------------------- |
| Bun (existing) | `packages/api/src/index.ts`          | Production server with TCP Postgres + ioredis. Long-lived process.|
| PGLite         | `packages/api/src/embedded.ts`       | Electrobun / desktop. In-process WASM Postgres, no external deps.  |
| Workers (new)  | `packages/api/src/worker.ts`         | Cloudflare Workers. HTTP Postgres (Neon) + REST Redis (Upstash). |

The adapters are additive — switching to Workers does NOT change the Bun
or PGLite paths.

## Architecture

- **DB driver** is selected by the `DATABASE_DRIVER` env var:
  - `postgres-js` (default): TCP pool, used by Bun/Node.
  - `neon-http`: Neon's HTTP/fetch driver, used by Workers.
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

The neon-http driver is HTTP-only, so a fresh client per request is
acceptable. For the singleton case `getDb()` continues to work, but for
hot paths consider:

```ts
import { createDbForRequest } from "@stwd/db";

app.use("*", async (c, next) => {
  c.set("db", createDbForRequest(c.env));
  await next();
});
```

Worker requests use the request-owned database context; the neon-http client is
cheap to construct and never escapes the event lifetime.

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
directory. The default, staging, and production Workers have separate secret
stores, so provision each deployed target explicitly (`wrangler secret put
<NAME>`, `wrangler secret put <NAME> --env staging`, and `wrangler secret put
<NAME> --env production`). Do NOT put secret values in `wrangler.toml`.

| Secret                          | Why                                                                    |
| ------------------------------- | ---------------------------------------------------------------------- |
| `DATABASE_URL`                  | Neon connection string. Workers use HTTP; migrations need TCP.         |
| `KV_REST_API_URL`               | Upstash REST endpoint.                                                 |
| `KV_REST_API_TOKEN`             | Upstash REST token.                                                    |
| `STEWARD_JWT_SECRET`            | Canonical HS256 JWT signing and verification secret. Minimum 32 characters in production. |
| `STEWARD_MASTER_PASSWORD`       | Vault keystore master password. Used by `KeyStore` (AES-256-GCM).      |
| `STEWARD_KDF_SALT`              | Per-deployment hex salt for the KeyStore KDF. Required in production.  |
| `STEWARD_REQUEST_SIGNING_SECRETS` | API HMAC roots for production machine requests. Browser clients never receive these values. |
| `RESEND_API_KEY`                | Magic-link email delivery.                                             |
| `EMAIL_FROM`                    | Optional: from address for magic links.                                |
| `APP_URL`                       | Optional: base URL for magic-link callbacks.                           |
| `EMAIL_AUTH_REDIRECT_BASE_URL`  | Optional: where to redirect after email auth (defaults elizacloud.ai). |
| `GOOGLE_CLIENT_ID`/`_SECRET`    | Google OAuth.                                                          |
| `DISCORD_CLIENT_ID`/`_SECRET`   | Discord OAuth.                                                         |
| `GITHUB_CLIENT_ID`/`_SECRET`    | GitHub OAuth.                                                          |
| `TWITTER_CLIENT_ID`/`_SECRET`   | Twitter/X OAuth (PKCE).                                                |
| `PASSKEY_RP_ID`                 | WebAuthn relying-party ID (your apex domain).                          |
| `PASSKEY_ORIGIN`                | WebAuthn origin (https://...).                                         |
| `PASSKEY_RP_NAME`               | Display name for the WebAuthn UI.                                      |
| `PASSKEY_ALLOWED_ORIGINS`       | Optional comma-separated additional origins for multi-tenant passkeys. |

The Workers target currently supports only the local encrypted vault backend.
`STEWARD_KMS_PROVIDER` and `STEWARD_EXTERNAL_CUSTODY_PROVIDER` are rejected at
boot because their provider credential chains are process-global; accepting
request-local binding options while executing under different global authority
would cross a tenant/deployment trust boundary. Use the Bun/Node deployment for
AWS KMS, PKCS#11, or external custody until request-owned provider clients are
available on Workers.

`NODE_ENV=production`, `SKIP_MIGRATIONS=1`, `DATABASE_DRIVER=neon-http`, and `REDIS_DRIVER=upstash`
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
bunx wrangler dev

# Real deploy to staging or prod:
bunx wrangler deploy --env staging
bunx wrangler deploy --env production
```

`wrangler deploy --dry-run --outdir=dist` (or `bun run wrangler:dry-run`)
builds the worker bundle without uploading. Current bundle size:
**3.3 MiB raw / 949 KiB gzipped** — comfortably under the 10 MiB compressed
Workers limit.

## Testing locally

`wrangler dev` boots a local workerd instance with full nodejs_compat. It
will read `.dev.vars` for secrets — do NOT commit it. Example shape:

```
NODE_ENV=development
DATABASE_URL=postgres://USER:PASS@ep-XYZ.us-east-2.aws.neon.tech/db?sslmode=require
KV_REST_API_URL=https://YOUR-DB.upstash.io
KV_REST_API_TOKEN=YOUR_TOKEN
STEWARD_JWT_SECRET=...
STEWARD_MASTER_PASSWORD=...
STEWARD_KDF_SALT=... # at least 32 hex characters
STEWARD_REQUEST_SIGNING_SECRETS=... # optional in local development
RESEND_API_KEY=...
```

## Known limitations

- **No long-lived background work.** Workers don't allow `setInterval`,
  background fetches outside `ctx.waitUntil()`, or persistent connections.
  The Bun entry's IP rate-limit GC and SIWE nonce GC have been replaced by
  TTL-driven cleanup in the storage backends. Anything new that needs a
  cron should use Cloudflare Cron Triggers (add a `scheduled()` handler in
  `worker.ts`).
- **Per-request DB client.** `neon-http` is fetch-based, so we don't
  benefit from connection pooling. For very high QPS, look at
  Hyperdrive (Cloudflare's Postgres pooler) or sharding the workload.
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

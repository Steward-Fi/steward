# Railway deploy: lean vs full (plugin toggle runbook)

how to ship the **same Steward image** as either a **lean service** (core only) or
a **full/trading service** (core + the trading plugin), driven entirely by one
environment variable. nothing in the image changes between the two; only the env
differs.

this runbook covers: the two modes, the complete required-env checklist, the
deploy steps, the post-deploy smoke, and the rollback hatch.

---

## 1. the toggle

the composition root reads the environment at boot and decides which opt-in
plugins to register. source of truth: `packages/api/src/plugin-config.ts`
(`resolveEnabledPlugins`), consumed by `packages/api/src/compose.ts`
(`composeApp` for routes, `runComposedPluginMigrations` for migrations).

| mode | env | what boots |
|------|-----|------------|
| **lean** | `STEWARD_PLUGINS` unset / empty | core only. trading routes NOT mounted, trading module never evaluated, trading migrations NOT run |
| **full** | `STEWARD_PLUGINS=trading` | core + trading. trading routes mounted, trading migrations run on boot |

legacy compatibility: `STEWARD_ENABLE_TRADING=true` ALSO enables trading (it
unions `trading` into the set). prefer `STEWARD_PLUGINS=trading` for new config;
keep the legacy var only if an older deploy already sets it. setting both is
harmless (union).

fail-closed: an UNKNOWN name in `STEWARD_PLUGINS` (e.g. a typo `tradng`) THROWS
at boot — the container refuses to start rather than silently shipping the wrong
feature profile (`UnknownPluginError`, `plugin-config.ts`). known set is
currently `{ trading }` (`KNOWN_PLUGIN_NAMES`).

### which service gets which

two Railway services, same image, different env:

- **lean service** → `STEWARD_PLUGINS` **unset** (do not set it at all). this is
  the trading-free core: auth, vault, agents, wallets, webhooks, policies, audit,
  adapters, etc.
- **full / trading service** → `STEWARD_PLUGINS=trading`. everything the lean
  service has, plus the `/trade/*` and `/v1/trade/*` routes and the trade-session
  / venue stack.

> the toggle flips ROUTES and MIGRATIONS together (parity). see §5.

---

## 2. required-env checklist

read the env directly from the codebase — these are the vars an actual healthy
boot consults, not just `.env.example`. the runtime entry is
`packages/api/src/index.ts` (`CMD ["bun", "packages/api/src/index.ts"]` in the
`Dockerfile`).

legend: **[boot-fatal in prod]** = boot throws / `process.exit(1)` if missing
when `NODE_ENV=production`. **[ready-gate]** = boot succeeds but `/ready` returns
503 until set. **[functional]** = no boot failure, but the named feature is
broken/disabled without it.

### mode-independent (BOTH services)

these are set identically on the lean and full services (different VALUES per
service where noted, e.g. each service its own DB).

| var | severity | why | source |
|-----|----------|-----|--------|
| `NODE_ENV=production` | required | flips every dev-secret fallback OFF; without it secrets silently fall back to predictable dev values | `Dockerfile` (already `ENV NODE_ENV=production`); read across `packages/auth/src/jwt.ts`, `packages/api/src/services/audit.ts`, `packages/vault/src/keystore.ts` |
| `PORT=3200` | required | listen port; `/health` probe targets it | `Dockerfile` (`ENV PORT=3200`), `packages/api/src/index.ts` |
| `STEWARD_BIND_HOST=0.0.0.0` | required on Railway | default is `127.0.0.1` (loopback only) — Railway's proxy can't reach the container unless it binds `0.0.0.0` | `packages/api/src/index.ts` (`STEWARD_BIND_HOST`) |
| `DATABASE_URL` | **[boot-fatal in prod]** | Postgres connection. boot runs `runMigrations()` blocking before serving; a bad/missing URL fails migration → `process.exit(1)` | `packages/api/src/index.ts`, `packages/db` (`shouldUsePGLite`) |
| `STEWARD_JWT_SECRET` | **[boot-fatal in prod]** | canonical JWT signing secret. `validateJwtSecretEnv()` runs at module load in `index.ts`; in prod it THROWS if unset or `< 32` chars | `packages/auth/src/jwt.ts` (`getJwtSecret`), called from `packages/api/src/index.ts` |
| `STEWARD_MASTER_PASSWORD` | **[boot-fatal / ready-gate]** | derives per-agent vault encryption keys. `/ready` reports `vault: not ok` if unset; vault key derivation throws when used | `packages/api/src/index.ts` (`/ready`), `packages/vault/src/keystore.ts` |
| `STEWARD_KDF_SALT` | **[boot-fatal in prod]** | per-deploy KDF salt for vault key derivation. `keystore.ts` THROWS in production if unset (and requires ≥ 32 hex chars) | `packages/vault/src/keystore.ts` |
| `STEWARD_AUDIT_HMAC_KEY` | **[boot-fatal in prod]** | HMAC key for the tamper-evident audit chain. in production the audit service THROWS if unset (or below the min entropy) | `packages/api/src/services/audit.ts` |
| `APP_URL` | [functional] | base URL for magic-link callbacks; wrong value breaks email login links | `packages/api/src` (`APP_URL`) |
| `RPC_URL` | [functional] | default EVM RPC for balance/tx; core wallet ops degrade without a real one | `.env.example`, `packages/api/src` (`RPC_URL`) |
| `CHAIN_ID` | [functional] | default chain id (8453 Base mainnet / 84532 Base Sepolia) | `packages/api/src` (`CHAIN_ID`) |
| `STEWARD_PLATFORM_KEYS` | [functional] | operator keys for cross-tenant `/platform/*` admin routes; unset = no platform admin access | `packages/api/src` (`STEWARD_PLATFORM_KEYS`) |

recommended-but-optional (mode-independent), set if the feature is used:

| var | why | source |
|-----|-----|--------|
| `REDIS_URL` | rate-limit enforcement, proxy spend tracking, tenant policy cache. unset → in-memory rate limit + spend tracking disabled | `packages/api/src/middleware/redis.ts`, `packages/redis` |
| `STEWARD_DEFAULT_TENANT_KEY` | default tenant for single-tenant self-host (no `X-Steward-Tenant` header) | `.env.example` |
| `RESEND_API_KEY` / `EMAIL_FROM` | magic-link email send; unset → tokens logged to console (not viable in prod) | `packages/auth`, `.env.example` |
| `GOOGLE_/DISCORD_/GITHUB_/TWITTER_CLIENT_ID+SECRET` | the matching OAuth login button only works if its pair is set | `packages/api/src/routes/auth` |
| `PASSKEY_RP_ID` / `PASSKEY_ORIGIN` / `PASSKEY_RP_NAME` | WebAuthn passkeys; must match the served domain | `.env.example` |
| `SIWE_ALLOWED_DOMAINS` | SIWE/SIWS message-domain allowlist | `packages/api/src` (`SIWE_ALLOWED_DOMAINS`) |
| `STEWARD_OAUTH_ALLOWED_REDIRECTS` | OAuth redirect allowlist | `packages/api/src` |

leave UNSET in any shared/prod env (dangerous if set): `STEWARD_ALLOW_DEV_SECRETS`,
`STEWARD_ENABLE_PROD_TEST_ACCOUNT_TOKEN`, `SKIP_MIGRATIONS`, and the
`STEWARD_ALLOW_*_EXPORT` / `STEWARD_ALLOW_UNSAFE_*` family — these are dev/break-glass
escape hatches (`.env.example`, `packages/api/src`, `packages/vault/src`).

### trading-only (FULL service only)

set these ONLY on the full/trading service. they are read by the trading plugin
and its venue stack. unset on the lean service (it never mounts trading).

| var | severity | why | source |
|-----|----------|-----|--------|
| `STEWARD_PLUGINS=trading` | required (full) | enables the trading plugin (routes + migrations) | `packages/api/src/plugin-config.ts` |
| `HL_BUILDER_ADDRESS` | [functional] | Hyperliquid builder-code address (fee receiver) for HL order routing | `packages/venue-hyperliquid/src` |
| `HL_BUILDER_FEE_TENTHS_BP` | [functional] | HL builder fee (tenths of a basis point) | `packages/venue-hyperliquid/src` |
| `HYPERLIQUID_FETCH_TIMEOUT_MS` | optional | HL venue HTTP timeout | `packages/venue-hyperliquid/src` |
| `POLYMARKET_BUILDER_ENABLED` | [functional] | enable Polymarket builder-fee routing | `packages/venue-polymarket/src` |
| `POLYMARKET_BUILDER_FEE_BPS` | [functional] | Polymarket builder fee (bps) | `packages/venue-polymarket/src` |
| `POLYMARKET_BUILDER_RECEIVER` | [functional] | Polymarket builder-fee receiver | `packages/venue-polymarket/src` |
| `POLYMARKET_SIGNING_SERVER_URL` | [functional] | third-party Polymarket order-signing service URL | `packages/venue-polymarket/src` |
| `POLYMARKET_SIGNING_SERVER_TOKEN` | [functional] | auth token for the Polymarket signing service | `packages/venue-polymarket/src` |
| `POLYMARKET_FETCH_TIMEOUT_MS` | optional | Polymarket venue HTTP timeout | `packages/venue-polymarket/src` |

note: the trading plugin also reads `DATABASE_URL`, `STEWARD_MASTER_PASSWORD`,
`STEWARD_AUDIT_HMAC_KEY`, `STEWARD_PLATFORM_KEYS` — but those are already in the
mode-independent set above, so no extra action for the full service beyond
flipping `STEWARD_PLUGINS=trading` and adding the venue vars it actually uses.

> testnet/CI-only HL/PM vars (`HL_TESTNET_SMOKE`, `HL_TESTNET_USER`,
> `STEWARD_PM_TEST_CREDS`) are NOT production env — do not set them on a prod
> trading service.

### capabilities-only (FULL service running the capabilities plugin)

the capabilities plugin (agent-facing credential-invoke layer) is an opt-in
plugin toggled the SAME way as trading, through `STEWARD_PLUGINS`. it may run
alongside trading (`STEWARD_PLUGINS=trading,capabilities`) or alone
(`STEWARD_PLUGINS=capabilities`). its operator CRUD + agent invoke routes 404 in
lean; its `capability_invocations` migration runs on boot only in full (parity).

set these ONLY on a service that enables `capabilities`. the agent invoke route
delegates the allowed call THROUGH the proxy via `@stwd/proxy-client` (it NEVER
decrypts a secret in-process); these vars are how it reaches the proxy. fail-
closed: if any is missing, the invoke route returns **503** and forwards nothing.

| var | severity | why | source |
|-----|----------|-----|--------|
| `STEWARD_PLUGINS=capabilities` (or `trading,capabilities`) | required (full) | enables the capabilities plugin (routes + migrations) | `packages/api/src/plugin-config.ts` |
| `STEWARD_PROXY_URL` | required (full) | base URL of the Steward proxy service the invoke route delegates to (e.g. `https://proxy.internal`). ABSENT => invoke returns 503 | `packages/plugin-capabilities/src/invoke.ts` |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRET` | required (full) | HMAC secret the invoke route signs its proxy requests with. MUST be one of the secrets the proxy verifies (`STEWARD_PROXY_REQUEST_SIGNING_SECRET(S)` on the proxy). ABSENT => invoke returns 503 | `packages/plugin-capabilities/src/invoke.ts` |

notes:
- the invoke route mints a SHORT-LIVED `api:proxy`-scoped agent token per call
  using the shared `STEWARD_JWT_SECRET` (already in the mode-independent set) —
  the SAME secret the proxy verifies tokens with. no extra token var is needed.
- `STEWARD_PROXY_REQUEST_SIGNING_SECRETS` (comma-separated, plural) is also
  accepted; the invoke route uses the FIRST entry. run the proxy with request
  signing enabled (`STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE=true`) in prod.
- the capabilities plugin also reads `DATABASE_URL`, `STEWARD_MASTER_PASSWORD`,
  `STEWARD_AUDIT_HMAC_KEY` — already in the mode-independent set (no extra action
  beyond `STEWARD_PLUGINS`, `STEWARD_PROXY_URL`, and the signing secret).
- the proxy itself needs a credential route materialized for the agent (the
  capability GRANT does this) + the target host in its allowlist / a named alias.

---

## 3. build the image

the image is built + pushed by CI; you do NOT build locally for a deploy.

- workflow: `.github/workflows/docker.yml` (`Docker`). on push to `develop` or
  `main` (and on `v*` tags) it builds `Dockerfile` and pushes
  `ghcr.io/steward-fi/steward:<tag>` (PRs build but do not push).
- tags follow the branch/tag: `develop`, `main`, or semver `v0.5.0`.

so: merge to `develop` → image `ghcr.io/steward-fi/steward:develop` is published.
that tag is what the deploy workflows ship.

---

## 4. deploy steps

both services pull the **same** `ghcr.io/steward-fi/steward:<tag>` image. the
deploy mechanism is `scripts/railway-deploy.sh`, which only (a) repoints the
service to the image and (b) triggers a redeploy. it does **NOT** set env vars —
env is configured per service in Railway directly (CI `vars`/`secrets` or the
Railway dashboard). that's why the same image becomes lean or full purely by the
env on each service.

deploy targets are NOT baked into the repo: each service is addressed by
`RAILWAY_SERVICE_ID` + `RAILWAY_ENV_ID` (set as CI repo variables). staging is
auto on `develop` (`.github/workflows/deploy-staging.yml`); production is a gated
manual dispatch (`.github/workflows/deploy-railway.yml`).

### A. one-time per service (env setup)

on the **lean service** in Railway, set the mode-independent vars from §2.
ensure `STEWARD_PLUGINS` is **NOT present** (delete it if it exists).

on the **full/trading service**, set the mode-independent vars **plus**
`STEWARD_PLUGINS=trading` and the trading-only venue vars from §2.

generate the secrets fresh per environment:

```sh
openssl rand -hex 32   # STEWARD_JWT_SECRET (>=32 chars)
openssl rand -hex 32   # STEWARD_AUDIT_HMAC_KEY
openssl rand -hex 32   # STEWARD_KDF_SALT (>=32 hex chars)
openssl rand -hex 32   # STEWARD_MASTER_PASSWORD (long random)
```

> `STEWARD_KDF_SALT` and `STEWARD_MASTER_PASSWORD` are encryption-domain values:
> rotating them requires re-encrypting existing vault keys. set once, keep
> stable per environment.

### B. ship the image

staging (auto): merge to `develop`. `Docker` builds+pushes
`:develop`, then `Deploy Staging` deploys it to the staging service(s).

production (gated): merge `develop → main` (reviewed), then dispatch
`Deploy Railway (Production)` from the Actions tab with the image tag (`main` or
a `v*` tag). the `Production` GitHub environment can require a reviewer (second
gate). run with `dry_run=true` first to confirm the target resolves.

if you have BOTH a lean and a full production service, you run the production
deploy once per service (each has its own `RAILWAY_SERVICE_ID`/`RAILWAY_ENV_ID`
repo vars). the image tag is identical; only the per-service env differs.

### C. smoke + verify

after each service finishes deploying, run the smoke script (§ smoke below) and
confirm `/ready` is 200:

```sh
# lean service
scripts/deploy/smoke-steward.sh https://<lean-service-host> lean

# full/trading service
scripts/deploy/smoke-steward.sh https://<full-service-host> full

# deep readiness (both)
curl -fsS https://<host>/ready | jq .
```

`/ready` returns `{ status: "ready", checks: { migrations, database, vault,
importSessionStore } }` with HTTP 200 only when all checks pass. a 503 here means
a required env var is missing (most commonly `STEWARD_MASTER_PASSWORD` or a bad
`DATABASE_URL`) — fix env and redeploy.

### D. rollback (the hatch)

see §6.

---

## 5. parity: routes and migrations flip together

the toggle is enforced through ONE resolver (`resolveEnabledPlugins`) consumed by
BOTH the route-composition path (`composeApp`) and the migration path
(`runComposedPluginMigrations`) in `packages/api/src/compose.ts`. they can never
drift — trading routes and trading migrations are always both-on or both-off.

practical consequences when you flip a service:

- **lean → full** (`STEWARD_PLUGINS` unset → `trading`): on the next boot the
  trading plugin's migrations run (into per-plugin namespaced tables
  `drizzle.__drizzle_migrations_plugin_<id>`, isolated from the core's
  `drizzle.__drizzle_migrations` journal), AFTER the core migrator, then trading
  routes mount. expect a slightly longer first boot while migrations apply.
- **full → lean** (`trading` → unset): trading routes stop mounting immediately.
  the trading TABLES are LEFT IN PLACE — this is harmless: they live in an
  isolated namespaced journal, nothing references them in lean mode, and they are
  not dropped. flipping back to full later re-mounts the routes without re-running
  already-applied migrations. (lean mode does NOT delete trading data; it just
  stops serving the routes.)

so a full→lean→full flip is non-destructive and reversible at the env level.

---

## 6. rollback hatch

three independent levers, fastest first:

1. **mode flip (no redeploy of a new image).** if the trading plugin itself is
   the problem, set `STEWARD_PLUGINS` empty (delete it) on the affected service
   and redeploy the SAME image. it boots lean — trading routes gone, trading
   data untouched (see §5). this isolates a trading-plugin regression without
   touching the core.

2. **image rollback.** redeploy the previous good image tag via the same deploy
   workflow / `scripts/railway-deploy.sh <previous-tag>`. since both services run
   the same image, roll back each service to the same prior tag. env is unchanged,
   so it comes back in the same mode it was in.

3. **Railway native rollback.** Railway keeps prior deployments per service —
   redeploy the last-known-good deployment from the Railway dashboard if the
   GHCR tag is unavailable.

after any rollback: re-run the smoke script and `curl /ready` on the affected
service before declaring it healthy.

migration note: a `lean → full` flip that fails DURING trading migrations
fail-closes (`process.exit(1)` in `index.ts`) — the container won't serve
traffic half-migrated. rolling that service back to lean (lever 1) restores
service immediately; the partially-applied trading migration ledger is namespaced
and isolated, so it does not corrupt the core schema.

---

## 7. quick reference: per-service env diff

| var | lean service | full/trading service |
|-----|--------------|----------------------|
| `STEWARD_PLUGINS` | unset | `trading` |
| `HL_BUILDER_ADDRESS` | unset | set |
| `HL_BUILDER_FEE_TENTHS_BP` | unset | set |
| `POLYMARKET_BUILDER_ENABLED` | unset | set (if PM used) |
| `POLYMARKET_BUILDER_FEE_BPS` | unset | set (if PM used) |
| `POLYMARKET_BUILDER_RECEIVER` | unset | set (if PM used) |
| `POLYMARKET_SIGNING_SERVER_URL` | unset | set (if PM used) |
| `POLYMARKET_SIGNING_SERVER_TOKEN` | unset | set (if PM used) |
| everything else in §2 mode-independent | set | set (same vars, own values) |

that single column of differences is the entire lean-vs-full contract. the image
is byte-identical.

---

## 8. the proxy service (separate process, same image)

the **proxy gateway** (`packages/proxy/src/index.ts`) is a SEPARATE process from
the API. it sits between agent containers and third-party APIs: agents send it a
request with a scoped JWT (and, in prod, an HMAC request signature), it matches a
credential route, decrypts the tenant's secret, injects it as a header, forwards
upstream, and scrubs the credential from the response. it runs the SAME
`ghcr.io/steward-fi/steward:<tag>` image as the API — only the start command and
env differ.

> agents talk to the proxy via the `@stwd/proxy-client` client (`proxyUrl` +
> `token` + `signingSecret`); it computes the signature/idempotency headers the
> proxy expects. see `packages/proxy-client/README.md`.

### 8.1 start command override

the API image's default `CMD` runs the API. for the proxy service, override the
start command:

```
bun packages/proxy/src/index.ts
```

on Railway: set the service's **Custom Start Command** to the line above. nothing
else in the image changes.

### 8.2 required-env checklist (proxy service)

read directly from proxy source: `packages/proxy/src/index.ts`,
`packages/proxy/src/config.ts`, `packages/proxy/src/middleware/auth.ts`,
`packages/proxy/src/middleware/redis-enforcement.ts`, and
`packages/vault/src/keystore.ts` (the decrypt path).

| var | severity | why | source |
|-----|----------|-----|--------|
| `NODE_ENV=production` | required | turns OFF dev-secret fallbacks AND turns ON the mandatory request-signature check + Redis fail-closed. this is the single flag that hardens the proxy | `packages/proxy/src/middleware/auth.ts` (`proxyRequestSignatureRequired`), `redis-enforcement.ts` |
| `STEWARD_BIND_HOST=0.0.0.0` | required on Railway | Bun binds `0.0.0.0` by default, but set it explicitly so Railway's proxy can reach the container | Bun.serve default; mirror the API service |
| `STEWARD_PROXY_PORT` | required | listen port for the proxy (default `8080`). point Railway's health check + target port here | `packages/proxy/src/config.ts` (`PROXY_PORT`), `index.ts` |
| `DATABASE_URL` | **[boot-fatal]** | same Postgres as the API. `index.ts` exits(1) if unset. reads `secret_routes` + `secrets`, writes `proxy_audit_log`. use the SAME database as the API service | `packages/proxy/src/index.ts` (`getDatabaseUrl`) |
| `STEWARD_JWT_SECRET` | **[boot-fatal in prod]** | `validateJwtSecretEnv()` runs at boot; verifies the agent bearer tokens. MUST equal the API's value (same tokens) | `packages/proxy/src/index.ts`, `@stwd/auth` |
| `STEWARD_MASTER_PASSWORD` | **[boot-fatal / functional]** | derives the vault key that decrypts injected secrets. MUST equal the API's value or decryption fails | `packages/proxy/src/handlers/proxy.ts` (`getSecretVault`), `packages/vault/src/keystore.ts` |
| `STEWARD_KDF_SALT` | **[boot-fatal in prod]** | per-deploy KDF salt for vault key derivation; `keystore.ts` THROWS in production if unset (≥32 hex chars). MUST equal the API's value | `packages/vault/src/keystore.ts` |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRET` (or `_SECRETS` for rotation, plural = comma-separated) | required in prod | HMAC secret the proxy verifies the agent's `X-Steward-Signature` against. without it, prod requests get 500 (`Proxy request signing is not configured`). the agent's `@stwd/proxy-client` must be given the SAME secret | `packages/proxy/src/middleware/auth.ts` (`configuredProxySigningSecrets`) |
| `REDIS_URL` | required in prod (fail-closed) | rate limit + spend tracking + idempotency replay store. in prod the proxy FAILS CLOSED when Redis is configured-but-unreachable. LLM-host spend tracking only runs when Redis is available | `packages/proxy/src/middleware/redis-enforcement.ts` |

recommended-but-optional (proxy service):

| var | why | source |
|-----|-----|--------|
| `STEWARD_PROXY_ALLOWED_HOSTS` | comma-separated extra hosts for `/proxy/<host>/...` direct proxying, beyond the built-in aliases. `api.openai.com` + `api.anthropic.com` (and the birdeye/coingecko/helius aliases) are ALREADY allowed by default; set this only to add hosts | `packages/proxy/src/config.ts` (`DEFAULT_ALIASES`), `handlers/alias.ts` |
| `STEWARD_SECRET_ROUTE_ALLOWED_HOSTS` | extra hosts a `secret_route` may target, beyond the vault default allowlist (openai/anthropic/birdeye/coingecko/helius already default-allowed) | `packages/vault/src/secret-vault.ts` |
| `REDIS_REQUIRED=true` | force Redis to be mandatory even outside prod | `redis-enforcement.ts` |
| `STEWARD_PROXY_UPSTREAM_TIMEOUT_MS` / `STEWARD_PROXY_RESPONSE_BYTES` / `STEWARD_PROXY_STREAM_DURATION_MS` | upstream timeout + response-size + stream-duration caps | `packages/proxy/src/handlers/proxy.ts` |
| `STEWARD_PROXY_MAX_IN_FLIGHT_PER_AGENT` / `_PER_TENANT` | in-flight concurrency caps (overflow → 429) | `packages/proxy/src/handlers/proxy.ts` |

**leave UNSET in prod (break-glass / weakens security):**
`STEWARD_PROXY_ALLOW_UNSIGNED_REQUESTS` (prod ignores it and still requires
signatures, but do not set it), `STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE=false`
(prod forces it on regardless), `STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL`,
`STEWARD_ALLOW_BROAD_SECRET_ROUTES`, `STEWARD_PGLITE_MEMORY`.

### 8.3 master-password co-location tradeoff (honest note)

the proxy holds `STEWARD_MASTER_PASSWORD` + `STEWARD_KDF_SALT` because it
decrypts injected secrets itself. that means the proxy and the API currently
share the same encryption trust domain: a full compromise of either process can
decrypt tenant secrets. this is acceptable for now (both run the same image, same
operator, same VPC) but it is NOT isolation — a future hardening step is to move
decryption behind a dedicated KMS/enclave so neither the API nor the proxy holds
the raw master password. document this in the threat model when the split lands.

the proxy's own defense-in-depth (independent of that tradeoff): mandatory JWT
`api:proxy` scope, HMAC proof-of-possession request signatures (prod), an
idempotency-key requirement on mutating methods, a host allowlist on both the
route and the resolver, SSRF guards on outbound DNS, and response scrubbing that
returns 502 if the upstream ever reflects the injected credential.

### 8.4 health + smoke

the proxy exposes an unauthenticated `GET /health` returning
`{ ok, service: "steward-proxy", version, aliases }`. point Railway's health
check at `/health` on `STEWARD_PROXY_PORT`.

after deploy:

```sh
# health 200 + unauthenticated request -> 401 (auth guard live)
scripts/deploy/smoke-proxy.sh https://<proxy-host> <api-proxy-scoped-jwt>

# optional: also exercise a signed request path (needs the signing secret)
STEWARD_PROXY_REQUEST_SIGNING_SECRET=<secret> \
  scripts/deploy/smoke-proxy.sh --signed https://<proxy-host> <jwt> <tenantId> <agentId>
```

### 8.5 rollback (proxy service)

the proxy is **stateless** (all state is in Postgres/Redis). rollback = redeploy
the previous good image tag via the same `scripts/railway-deploy.sh <tag>` /
Railway native rollback, exactly like the API service (§6, levers 2 and 3). the
mode-flip lever (§6 lever 1) does not apply — the proxy has no plugin toggle. env
is unchanged across a rollback, so it comes back in the same posture. after
rollback: re-run `smoke-proxy.sh` and confirm `/health` is 200.

> keep `STEWARD_MASTER_PASSWORD` / `STEWARD_KDF_SALT` / `STEWARD_JWT_SECRET`
> IDENTICAL between the API and proxy services and STABLE across rollbacks —
> rotating them requires re-encrypting vault keys (master/salt) or reissuing
> tokens (jwt).

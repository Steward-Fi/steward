# Steward on Railway — Deployment Guide

> Deploy Steward as Eliza Cloud's self-hosted auth + wallet service on Railway.

---

## Prerequisites

- [Railway account](https://railway.app) + CLI installed (`npm i -g @railway/cli`)
- A Neon Postgres connection string **or** use Railway's managed Postgres add-on
- Secrets ready to generate (vault, KDF, JWT, email-code, audit-chain, platform, and proxy-signing roots)
- (Optional) [Resend](https://resend.com) API key for magic-link emails
- (Optional) Google / Discord OAuth credentials

---

## 1. Initialize the Project

```bash
cd /path/to/steward-fi

# Login to Railway
railway login

# Create a new Railway project
railway init
# → Select "Empty Project" when prompted
# → Name it something like "steward" or "eliza-auth"
```

### Connect GitHub for auto-deploy (recommended)

```bash
# Link to your GitHub repo
railway link
```

Or do it in the Railway dashboard: **Project → Settings → Connect Repo → select steward-fi**.

Set the deploy branch (e.g. `develop` or `main`) under **Settings → Deploy → Branch**.

---

## 2. Add Services

### Option A: Railway Managed Postgres + Redis (easiest)

In the Railway dashboard:

1. Click **+ New** → **Database** → **PostgreSQL**
2. Click **+ New** → **Database** → **Redis**

Railway auto-provisions provider-admin `DATABASE_URL` and `REDIS_URL` values.
Use the database URL only in the protected bootstrap job; do not reference that
admin credential from the API. After bootstrap, configure the API with the
restricted `steward_app` URL. Redis may remain a normal service reference.

### Option B: External Neon Postgres + Railway Redis

If using Neon:

1. Create a `steward` database in your Neon project (or use the default `neondb`)
2. Grab the operator connection string using authenticated TLS, preferably
   `sslmode=verify-full`; production rejects unverified `sslmode=require` unless
   its separate risk acknowledgement is explicitly enabled.
3. Add Railway Redis as above for rate limiting

---

## 3. Set Environment Variables

In the Railway dashboard, go to your **steward-api** service → **Variables** tab.

Add all of these:

```bash
# ─── Server ───────────────────────────────────────────────────────────────────
PORT=3200
NODE_ENV=production
STEWARD_BIND_HOST=0.0.0.0

# ─── Database ─────────────────────────────────────────────────────────────────
# Use the restricted application login created by the bootstrap job:
DATABASE_URL=<restricted steward_app connection URL>
# If using third-party Neon:
# DATABASE_URL=postgresql://steward_app:pass@ep-xxx.neon.tech/steward?sslmode=verify-full
STEWARD_APP_DATABASE_ROLE=steward_app
STEWARD_PLATFORM_DATABASE_URL=<restricted steward_platform connection URL>
STEWARD_PLATFORM_DATABASE_ROLE=steward_platform

# ─── Security (generate these — do NOT reuse across environments) ─────────────
# Generate each with: openssl rand -hex 32
STEWARD_MASTER_PASSWORD=<openssl rand -hex 32>
STEWARD_KDF_SALT=<openssl rand -hex 32>
STEWARD_JWT_SECRET=<openssl rand -hex 32>
STEWARD_EMAIL_CODE_SECRET=<openssl rand -hex 32>
STEWARD_AUDIT_HMAC_KEY=<openssl rand -hex 32>
STEWARD_EXECUTION_AUTH_SECRET=<v1: plus openssl rand -hex 32>
STEWARD_PLATFORM_KEYS=<stw_platform_ plus 24 random bytes as hex>
# This bootstrap operator key needs both the generic platform write gate and
# the route-specific scopes used below. Narrow this list for ongoing operation.
STEWARD_PLATFORM_KEY_SCOPES={"<same raw platform key>":["platform:write","platform:tenant:create","platform:tenant:read","platform:agent:create","platform:agent-token:create","platform:agent:delete"]}

# This example uses Steward's built-in local custody. In production that mode
# decrypts signing keys in application memory and requires an explicit posture
# acknowledgement. Prefer STEWARD_KMS_PROVIDER=aws|pkcs11 where available.
STEWARD_ACK_LOCAL_CUSTODY=true

# ─── Redis ────────────────────────────────────────────────────────────────────
# If using Railway Redis:
REDIS_URL=${{Redis.REDIS_URL}}
# If third-party: REDIS_URL=redis://:password@host:6379

# ─── EVM / Blockchain ────────────────────────────────────────────────────────
RPC_URL=https://mainnet.base.org
CHAIN_ID=8453

# ─── Auth — Email (Magic Links) ──────────────────────────────────────────────
# Omit RESEND_API_KEY only if email login should remain unavailable. Production
# deliberately fails email delivery closed; there is no console-delivery mode.
RESEND_API_KEY=<from resend.com>
EMAIL_FROM=login@yourdomain.com
APP_URL=https://your-steward.up.railway.app

# ─── Auth — Passkeys (WebAuthn) ──────────────────────────────────────────────
PASSKEY_RP_NAME=ElizaCloud
PASSKEY_RP_ID=your-steward.up.railway.app
PASSKEY_ORIGIN=https://your-app.com

# ─── Auth — OAuth (optional) ─────────────────────────────────────────────────
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=
# DISCORD_CLIENT_ID=
# DISCORD_CLIENT_SECRET=
# TWITTER_CLIENT_ID=
# TWITTER_CLIENT_SECRET=

# ─── Migrations ──────────────────────────────────────────────────────────────
# The restricted API login must never own or migrate schema objects.
SKIP_MIGRATIONS=true
```

Keep `STEWARD_MIGRATION_DATABASE_URL` and `STEWARD_OPERATOR_DATABASE_URL`
outside the API service in a separately protected release job. The operator
must be a provider-superuser-equivalent capable of managing `BYPASSRLS` roles
and function ownership; ordinary `CREATEROLE` is insufficient.

Review the [custody-posture guide](security/custody-posture.md) before accepting
local custody in production.

### Generate secrets locally

```bash
# Run these and paste the output into Railway's variable editor
echo "STEWARD_MASTER_PASSWORD=$(openssl rand -hex 32)"
echo "STEWARD_KDF_SALT=$(openssl rand -hex 32)"
echo "STEWARD_JWT_SECRET=$(openssl rand -hex 32)"
echo "STEWARD_EMAIL_CODE_SECRET=$(openssl rand -hex 32)"
echo "STEWARD_AUDIT_HMAC_KEY=$(openssl rand -hex 32)"
echo "STEWARD_EXECUTION_AUTH_SECRET=v1:$(openssl rand -hex 32)"
PLATFORM_KEY="stw_platform_$(openssl rand -hex 24)"
echo "STEWARD_PLATFORM_KEYS=$PLATFORM_KEY"
echo "STEWARD_PLATFORM_KEY_SCOPES={\"$PLATFORM_KEY\":[\"platform:write\",\"platform:tenant:create\",\"platform:tenant:read\",\"platform:agent:create\",\"platform:agent-token:create\",\"platform:agent:delete\"]}"
```

**Save `STEWARD_PLATFORM_KEYS` somewhere safe** — you'll need it to create tenants.

---

## 4. Configure Build & Deploy

Railway auto-detects the `Dockerfile`. Verify these settings in **Service → Settings**:

| Setting | Value |
|---------|-------|
| **Builder** | Dockerfile |
| **Dockerfile Path** | `./Dockerfile` |
| **Watch Paths** | `/` (default, or scope to `packages/` + root configs) |

### Health Check

Under **Service → Settings → Deploy → Health Check**:

- **Path:** `/health`
- **Port:** `3200`
- **Timeout:** `45s` (Steward runs migrations on first boot, may take a moment)

### Start Command

Leave blank — the Dockerfile's `CMD` handles it:
```
CMD ["bun", "packages/api/src/index.ts"]
```

---

## 5. Deploy

### Via GitHub (auto-deploy)

Push to your configured branch:

```bash
git push origin develop
```

Railway picks it up automatically. Watch the build in the dashboard.

### Via CLI (manual)

```bash
railway up
```

### Database release gate

Before every production rollout, run the complete release migrator with the
same `STEWARD_PLUGINS` selection as the API:

```bash
DATABASE_URL="$STEWARD_MIGRATION_DATABASE_URL" bun run --cwd packages/api migrate
psql "$STEWARD_OPERATOR_DATABASE_URL" \
  -v steward_app_role=steward_app \
  -v steward_migration_role=steward_migrator \
  -v steward_bootstrap_role=steward_bootstrap_owner \
  -v steward_platform_role=steward_platform \
  -f scripts/postgres/rls-bootstrap.sql
psql "$STEWARD_MIGRATION_DATABASE_URL" \
  -v steward_migration_role=steward_migrator \
  -f scripts/postgres/rls-activate.sql
```

The API command applies both core and enabled-plugin journals; the DB-only
migrator is not a complete release. On a brand-new empty database, run the
initial complete migration with the provider operator as `DATABASE_URL`, then
bootstrap/provision the three login credentials and activate. Subsequent
releases use the dedicated migrator. Only after this gate passes may the API
start with `SKIP_MIGRATIONS=true` and be checked at `/health` and `/ready`.

Watch logs:
```bash
railway logs
```

---

## 6. Custom Domain Setup

### Default Railway URL

After deploy, Railway gives you a URL like:
```
https://steward-production-xxxx.up.railway.app
```

### Add custom domain (e.g. `steward.elizacloud.ai`)

1. In Railway dashboard: **Service → Settings → Networking → Custom Domain**
2. Add: `steward.elizacloud.ai`
3. Railway shows the CNAME target (something like `xxxx.up.railway.app`)

### Update DNS

Add a CNAME record at your DNS provider:

```
steward.elizacloud.ai  CNAME  xxxx.up.railway.app
```

### Update environment variables to match

```bash
# Update these after the custom domain is live:
APP_URL=https://steward.elizacloud.ai
PASSKEY_RP_ID=steward.elizacloud.ai
PASSKEY_ORIGIN=https://steward.elizacloud.ai
```

Railway handles SSL automatically.

---

## 7. Post-Deploy Verification

```bash
# Set your base URL
export BASE="https://steward.elizacloud.ai"  # or your Railway URL

# Health check
curl -sf "$BASE/health"
# → {"status":"ok","version":"<current API version>","uptime":...}

# Deep readiness check (verifies DB + migrations + vault)
curl -sf "$BASE/ready"
# → {"status":"ready","version":"<current API version>","uptime":...,"checks":{"migrations":{"ok":true},"database":{"ok":true},...}}
# Set STEWARD_READY_PROBE_TOKEN and send X-Steward-Probe-Token only from an
# operator probe when the full diagnostic details are required.

# List available auth providers
curl -sf "$BASE/auth/providers"
# → {"ok":true,"passkey":true,"email":true,"siwe":true,...}
```

### Create the initial tenant

```bash
export PLATFORM_KEY="<your STEWARD_PLATFORM_KEYS value>"

# Create the eliza-cloud tenant
curl -sf -X POST "$BASE/platform/tenants" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY" \
  -d '{"id": "eliza-cloud", "name": "Eliza Cloud"}'
# → {"ok":true,"data":{"id":"eliza-cloud","name":"Eliza Cloud","apiKey":"stwd_..."}}
```

**Save the returned `apiKey`** — this is the tenant API key for Eliza Cloud's backend to authenticate with Steward.

### Smoke test: create a test agent

```bash
# Create an agent through the non-interactive scoped platform boundary.
curl -sf -X POST "$BASE/platform/tenants/eliza-cloud/agents" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY" \
  -d '{"id": "test-agent", "name": "Railway Smoke Test"}'

# Get an agent JWT through the scoped platform provisioning route. The sibling
# tenant route requires an owner/admin session with recent MFA and intentionally
# rejects a bare tenant API key by default.
TOKEN=$(curl -sf -X POST "$BASE/platform/tenants/eliza-cloud/agents/test-agent/token" \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY" \
  -d '{"scopes":["agent"]}' | jq -r '.data.token')

# Check balance
curl -sf "$BASE/agents/test-agent/balance" \
  -H "Authorization: Bearer $TOKEN"

# Clean up
curl -sf -X DELETE "$BASE/platform/tenants/eliza-cloud/agents/test-agent" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY"
```

---

## 8. Connect to Eliza Cloud (Vercel)

In your Eliza Cloud Vercel project, set these environment variables:

```bash
# Steward API URL (server-side)
STEWARD_API_URL=https://steward.elizacloud.ai

# Steward API URL (client-side, for browser auth flows)
NEXT_PUBLIC_STEWARD_API_URL=https://steward.elizacloud.ai

# Tenant API key (server-side only, from tenant creation step above)
STEWARD_API_KEY=<tenant apiKey from step 7>
```

The JWT signing secret belongs only to Steward's server-side API and proxy
services. Do not add `STEWARD_JWT_SECRET` or its deprecated
`STEWARD_SESSION_SECRET` fallback to Vercel or any browser-facing environment.
Keep `STEWARD_API_KEY` in Vercel's server-only environment as well; never use a
`NEXT_PUBLIC_` prefix or otherwise include it in the browser bundle.

Redeploy the Vercel app after setting these.

### Verify the integration

1. Visit your Eliza Cloud frontend
2. Try logging in (email magic link, wallet, or passkey)
3. Auth requests should hit `steward.elizacloud.ai` and return tokens
4. Check Railway logs for incoming requests: `railway logs`

---

## 9. CI/CD

### Auto-deploy on push (recommended)

Railway auto-deploys when you push to the connected branch:

```bash
# Deploys automatically
git push origin develop
```

Configure the branch in **Service → Settings → Source → Deploy Branch**.

### Manual deploy via CLI

```bash
# Deploy current directory
railway up

# Deploy with a specific environment
railway up --environment production
```

### Rollback

In the Railway dashboard: **Deployments → click a previous successful deploy → Rollback**.

---

## 10. Deploying the Proxy (Optional)

If you need the credential-injection proxy (for managing API keys on behalf of agents), deploy it as a second Railway service in the same project:

1. **+ New** → **Service** → connect same GitHub repo
2. Name it `steward-proxy`
3. Set the **Start Command** override:
   ```
   bun packages/proxy/src/index.ts
   ```
4. Set environment variables (same DB + Redis, different port):
   ```bash
   STEWARD_PROXY_PORT=8080
   PORT=8080
   NODE_ENV=production
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   STEWARD_MASTER_PASSWORD=<same as API service>
   STEWARD_KDF_SALT=<same as API service>
   STEWARD_JWT_SECRET=<same as API service>
   STEWARD_AUDIT_HMAC_KEY=<same as API service>
   STEWARD_EXECUTION_AUTH_SECRET=<same as API service>
   STEWARD_PROXY_REQUEST_SIGNING_SECRETS=<dedicated shared HMAC root>
   REDIS_URL=${{Redis.REDIS_URL}}
   ```
5. Health check: **Path:** `/health`, **Port:** `8080`
6. Custom domain: `proxy.elizacloud.ai` (optional)

Production proxy callers must sign every request with the same dedicated HMAC
root. A bearer token alone is insufficient. Use `@stwd/proxy-client` or the
[signed broker integration](guides/session-broker-integration.mdx) rather than
hand-building the canonical signature. Set the signing root on each server-side
caller as well as the proxy; never expose it to a browser. If API readiness
should include the proxy clock check, also set
`STEWARD_PROXY_URL=https://proxy.elizacloud.ai` on the API service.
The API service also needs the same dedicated root as
`STEWARD_PROXY_REQUEST_SIGNING_SECRET` when it is a proxy caller.

---

## Troubleshooting

### Build fails

```bash
# Check build logs in dashboard or:
railway logs --build
```

Common issues:
- **bun.lock out of sync** — run `bun install` locally and commit `bun.lock`
- **Missing workspace package.json** — all packages in `packages/` must exist

### App crashes on startup

```bash
railway logs
```

Common issues:
- **Missing `STEWARD_MASTER_PASSWORD`** — required, app won't start without it
- **Bad `DATABASE_URL`** — verify the connection string, check SSL (`?sslmode=require` for Neon)
- **Migration failure** — check logs for SQL errors, may need to create the database manually

### Health check fails

- Ensure `PORT=3200` is set (Railway uses this to route traffic)
- Ensure `STEWARD_BIND_HOST=0.0.0.0` (not `127.0.0.1`)
- The `/ready` endpoint does a deep check (DB + exact core and enabled-plugin migration ledgers + vault). Deployment acceptance requires both public `/health` and `/ready` receipts.

### "Tenant not found" errors

```bash
# List all tenants
curl -sf "$BASE/platform/tenants" \
  -H "X-Steward-Platform-Key: $PLATFORM_KEY"
```

### Connection refused from Vercel

- Verify `STEWARD_API_URL` doesn't have a trailing slash
- Verify the Railway service is public (Settings → Networking → Public Networking enabled)
- Check Railway's firewall / WAF isn't blocking Vercel's IPs

---

## Environment Variable Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `3200` | API listen port |
| `STEWARD_BIND_HOST` | No | `127.0.0.1` | Bind host. **Set `0.0.0.0` on Railway** |
| `NODE_ENV` | No | — | Set `production` |
| `DATABASE_URL` | **Yes** | — | Restricted, non-owner `steward_app` connection only. |
| `STEWARD_APP_DATABASE_ROLE` | **Yes in production** | — | Exact role expected on `DATABASE_URL`. |
| `STEWARD_PLATFORM_DATABASE_URL` | **Yes for destructive platform operations** | — | Separate restricted platform-authority connection. |
| `STEWARD_PLATFORM_DATABASE_ROLE` | **Yes with platform DB URL** | `steward_platform` | Exact platform login. |
| `STEWARD_MIGRATION_DATABASE_URL` | **Release job only** | — | Dedicated migrator; never expose to the API. |
| `STEWARD_MIGRATION_CONNECT_TIMEOUT_SECONDS` | Release job only | `15` | Positive connection deadline in seconds. |
| `STEWARD_MIGRATION_LOCK_TIMEOUT_MS` | Release job only | `60000` | Positive advisory-lock deadline, no greater than the overall deadline. |
| `STEWARD_MIGRATION_STATEMENT_TIMEOUT_MS` | Release job only | `300000` | Positive SQL statement deadline, no greater than the overall deadline. |
| `STEWARD_MIGRATION_OVERALL_TIMEOUT_MS` | Release job only | `600000` | Positive deadline for each complete core or plugin migration attempt. |
| `STEWARD_STARTUP_PHASE_TIMEOUT_MS` | No | `30000` | Positive default deadline for each pre-listen compose/RLS/Redis/auth-store/scheduler/custody phase. |
| `STEWARD_STARTUP_<PHASE>_TIMEOUT_MS` | No | phase default | Optional exact override; phases are `COMPOSE`, `RLS`, `REDIS`, `AUTH_STORES`, `SCHEDULERS`, and `CUSTODY`. |
| `STEWARD_OPERATOR_DATABASE_URL` | **Bootstrap job only** | — | Provider-superuser-equivalent; never expose to the API. |
| `STEWARD_MASTER_PASSWORD` | **Yes** | — | Vault encryption secret. Keep separate from JWT signing material. |
| `STEWARD_KDF_SALT` | **Yes in production** | — | Stable deployment KDF salt, at least 16 random bytes. Back it up with the encrypted vault data. |
| `STEWARD_JWT_SECRET` | **Yes** | — | Canonical server-side signing and verification secret for user, session, and agent JWTs. Must be at least 32 characters in production. |
| `STEWARD_SESSION_SECRET` | No | — | Deprecated compatibility fallback. Rename existing deployments to `STEWARD_JWT_SECRET`. |
| `STEWARD_PLATFORM_KEYS` | **Yes** | — | Platform admin key(s), comma-separated |
| `STEWARD_PLATFORM_KEY_SCOPES` | **Yes for platform routes** | — | JSON map from a raw platform key (or its SHA-256 hex digest) to explicit scopes. Unmapped keys authenticate but have no authorization. |
| `STEWARD_EMAIL_CODE_SECRET` | **Yes for email auth** | — | Separate secret binding email codes and polling receipts; at least 32 characters in production. |
| `STEWARD_AUDIT_HMAC_KEY` | **Yes in production** | — | Separate HMAC root for the tenant audit chain. |
| `STEWARD_EXECUTION_AUTH_SECRET` | **Yes for governed provider execution** | — | Versioned (`v1:<secret>`) authorization root shared by the API and proxy; keep it distinct from JWT and request-signing roots. |
| `STEWARD_ACK_LOCAL_CUSTODY` | **Yes only for production local custody** | — | Set `true` only after accepting plaintext signing-key bytes in API memory; omit when using a supported KMS mode. |
| `STEWARD_DEFAULT_TENANT_KEY` | No | — | Default tenant key for single-tenant mode |
| `STEWARD_DEFAULT_TENANT_ID` | No | `default` | Tenant used by auth routes when a request supplies no tenant hint; the tenant must already exist. |
| `RPC_URL` | No | `https://sepolia.base.org` | EVM RPC endpoint |
| `CHAIN_ID` | No | `84532` | Default chain ID |
| `STEWARD_NATIVE_PRICE_FALLBACK_USD` | No | `10000` | Positive finite native-token USD valuation used to record spend when the price oracle is unavailable. |
| `REDIS_URL` | **Yes for the production proxy** | — | Redis for rate limiting + spend tracking; the proxy fails closed without it unless its explicit soft-fail override is enabled. |
| `RESEND_API_KEY` | No | — | Resend key for magic-link delivery. Without a provider, production email login fails closed. |
| `EMAIL_FROM` | No | `login@steward.fi` | Magic link sender address |
| `APP_URL` | No | `https://steward.fi` | Base URL for magic link callbacks |
| `PASSKEY_RP_NAME` | No | `Steward` | WebAuthn relying party display name |
| `PASSKEY_RP_ID` | No | `steward.fi` | WebAuthn relying party ID (your domain) |
| `PASSKEY_ORIGIN` | No | `https://steward.fi` | Allowed origin for passkey operations |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret |
| `DISCORD_CLIENT_ID` | No | — | Discord OAuth client ID |
| `DISCORD_CLIENT_SECRET` | No | — | Discord OAuth client secret |
| `TWITTER_CLIENT_ID` | No | — | Twitter/X OAuth client ID |
| `TWITTER_CLIENT_SECRET` | No | — | Twitter/X OAuth client secret |
| `AGENT_TOKEN_EXPIRY` | No | `24h` | Agent JWT token lifetime |
| `SKIP_MIGRATIONS` | **Yes in production** | `false` | Set `true`; the complete release gate must finish first. |
| `STEWARD_PROXY_PORT` | No | `8080` | Proxy service listen port |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRET` / `_SECRETS` | **Yes for production proxy traffic** | — | Dedicated HMAC root used by proxy clients to sign requests and by the proxy to verify them. |
| `STEWARD_PROXY_URL` | No | — | API-side proxy URL used by `/ready` for the optional proxy clock check. |

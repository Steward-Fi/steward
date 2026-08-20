# Steward Deployment Guide

> Last updated: 2026-03-27

## Overview

Steward runs as two **systemd services** on each Milady node, built from source using Bun. It connects to a shared Neon PostgreSQL database and Redis for production proxy rate limiting and spend tracking.

- `steward.service` — REST API on port 3200
- `steward-proxy.service` — API proxy gateway on port 8080

**Production nodes:** see your operator-local inventory (SEC-130 — node addresses are deliberately not committed to this repo; see Node Inventory below).

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  Milady Core Node                                     │
│                                                       │
│  systemd: steward.service                             │
│    └─ bun run packages/api/src/index.ts               │
│    └─ Listens: 0.0.0.0:3200                          │
│    └─ Env: /opt/steward/.env                          │
│                                                       │
│  systemd: steward-proxy.service                       │
│    └─ bun run packages/proxy/src/index.ts             │
│    └─ Listens: 0.0.0.0:8080                          │
│                                                       │
│  Docker: agent containers                             │
│    └─ Reach steward at: http://172.18.0.1:3200        │
│    └─ Reach proxy at:   http://172.18.0.1:8080        │
│       (Docker bridge gateway IP)                      │
│                                                       │
│  External: <your-domain> → TLS terminator (nginx/deploy/nginx.conf)        │
│            → 127.0.0.1:3200 (never plain HTTP to a node IP)                 │
└──────────────────────────────────────────────────────┘
```

---

## Deploy to a New Node

### Prerequisites
- SSH root access to the node
- Bun installed (`curl -fsSL https://bun.sh/install | bash`)
- Node has internet access for npm packages

### Step 1: Sync source code

```bash
# From your workstation (where you have the steward repo)
NODE_IP="<node-ip>"
# Path to your local clone of THIS repo — keep real checkout paths out of
# committed docs.
STEWARD_SRC="/path/to/your/local/steward-checkout"
rsync -az --delete \
  --exclude='.git' --exclude='node_modules' --exclude='.next' \
  --exclude='web' --exclude='.turbo' \
  -e "ssh -o StrictHostKeyChecking=accept-new" \
  "${STEWARD_SRC}/" root@${NODE_IP}:/opt/steward/
```

### Step 2: Install dependencies

```bash
ssh root@${NODE_IP} "cd /opt/steward && bun install"
```

### Step 3: Configure environment

```bash
ssh root@${NODE_IP} "cat > /opt/steward/.env << 'EOF'
PORT=3200
NODE_ENV=production
API_VERSION=0.2.0
STEWARD_BIND_HOST=0.0.0.0

# Database (shared Neon Postgres — restricted app role; never the owner)
DATABASE_URL=postgresql://steward_app:<password>@<neon-host>/neondb?sslmode=verify-full&options=-c search_path=steward,public
SKIP_MIGRATIONS=1

# Before first start or schema upgrade, execute the admin → bootstrap →
# migration-role → activation procedure in docs/security/database-rls-rollout.mdx.
# Do not store either operator URL in this runtime env file.

# Vault encryption
STEWARD_MASTER_PASSWORD=<256-bit-hex-secret>

# Auth
STEWARD_JWT_SECRET=<separate-jwt-secret>
STEWARD_PLATFORM_KEYS=<platform-admin-key>
# Optional; defaults to "default" when tenant-less auth requests omit a hint.
STEWARD_DEFAULT_TENANT_ID=default

# RPC
RPC_URL=https://mainnet.base.org
CHAIN_ID=8453
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
# Conservative spend valuation during native-token oracle outages.
STEWARD_NATIVE_PRICE_FALLBACK_USD=10000

# Redis (required by the production proxy unless its explicit soft-fail
# override is enabled)
REDIS_URL=redis://localhost:6379

# Proxy port (if running proxy on same machine)
# PROXY_PORT=8080
EOF
chmod 600 /opt/steward/.env"
```

**Critical env vars:**
| Variable | Purpose | Required |
|----------|---------|----------|
| `DATABASE_URL` | Neon Postgres connection string with `search_path=steward,public` | Yes |
| `STEWARD_MASTER_PASSWORD` | AES-256 vault encryption key (256-bit hex) | Yes |
| `STEWARD_JWT_SECRET` | JWT signing secret (separate from master password!) | Yes |
| `STEWARD_PLATFORM_KEYS` | Platform admin API key for tenant management | Yes |
| `STEWARD_DEFAULT_TENANT_ID` | Tenant used by auth routes when a request supplies no tenant hint | No (`default`) |
| `STEWARD_BIND_HOST` | Must be `0.0.0.0` for Docker containers to reach it | Yes |
| `REDIS_URL` | Redis connection string for rate limiting + spend tracking | Yes (production) |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRETS` | Shared secret(s) the proxy uses to verify every request signature | Yes (production) |
| `RPC_URL` | EVM RPC endpoint (default: Base mainnet) | No |
| `STEWARD_NATIVE_PRICE_FALLBACK_USD` | Native-token USD valuation during price-oracle outages | No (`10000`) |

### Step 4: Create systemd services

Install the **shipped, hardened units** (`deploy/steward.service`,
`deploy/steward-proxy.service`) — they run as a dedicated unprivileged
`steward` user with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`,
and backoff restart limits. Do NOT hand-roll units that run the services as
root with unconditional restart loops (SEC-022).

```bash
# 1. Create the dedicated user and install Bun for it (units use
#    /home/steward/.bun/bin/bun)
ssh root@${NODE_IP} "
  useradd --system --create-home --shell /usr/sbin/nologin steward 2>/dev/null || true
  sudo -u steward bash -c 'curl -fsSL https://bun.sh/install | bash'
"

# 2. Move the env file to the path the units expect and lock it down
ssh root@${NODE_IP} "
  mkdir -p /etc/steward
  cp /opt/steward/.env /etc/steward/env
  chmod 600 /etc/steward/env
  chown -R steward:steward /opt/steward
"

# 3. Install + start the shipped units
ssh root@${NODE_IP} "
  cp /opt/steward/deploy/steward.service /etc/systemd/system/steward.service
  cp /opt/steward/deploy/steward-proxy.service /etc/systemd/system/steward-proxy.service
  systemctl daemon-reload
  systemctl enable steward steward-proxy
  systemctl start steward steward-proxy
"
```

<details>
<summary>Legacy single-service setup (still works)</summary>

If you don't need the proxy, install only `deploy/steward.service` (same
hardening, API only) and skip `steward-proxy.service`:

```bash
ssh root@${NODE_IP} "
  cp /opt/steward/deploy/steward.service /etc/systemd/system/steward.service
  systemctl daemon-reload && systemctl enable steward && systemctl start steward"
```
</details>

### Step 5: Verify

```bash
# API health check
ssh root@${NODE_IP} "curl -sf http://localhost:3200/health"
# Expected: {"status":"ok","version":"0.2.0","uptime":...}

# Proxy health check
ssh root@${NODE_IP} "curl -sf http://localhost:8080/health"
# Expected: {"status":"ok","proxy":true}

# Check reachable from Docker bridge
ssh root@${NODE_IP} "curl -sf http://172.18.0.1:3200/health"
ssh root@${NODE_IP} "curl -sf http://172.18.0.1:8080/health"
```

### Step 6: Create milady-cloud tenant (if first time)

The platform key must never appear on a command line (local ps/history,
remote process list). Read it on the node from the mode-0600 env file and
call the API over localhost via the SSH channel; the credential header reaches
curl through a mode-0600 temporary header file, never as an argv-expansible
`-H "X-Steward-Platform-Key: ${PK}"` (SEC-020/SEC-022):

```bash
ssh root@${NODE_IP} "PK=\$(grep '^STEWARD_PLATFORM_KEYS=' /etc/steward/env | cut -d= -f2- | cut -d, -f1); \
  case \"\${PK}\" in ''|*[!A-Za-z0-9._~-]*) exit 1;; esac; [ \"\${#PK}\" -le 512 ] || exit 1; \
  AUTH_FILE=\$(mktemp); chmod 600 \"\${AUTH_FILE}\"; trap 'rm -f \"\${AUTH_FILE}\"' EXIT; \
  printf 'X-Steward-Platform-Key: %s\\n' \"\${PK}\" > \"\${AUTH_FILE}\"; \
  curl -sf -X POST http://localhost:3200/platform/tenants \
  -H 'Content-Type: application/json' \
  -H \"@\${AUTH_FILE}\" \
  -d '{\"id\": \"milady-cloud\", \"name\": \"Milady Cloud\"}'"
```

For any other platform-key operation, use an SSH tunnel from your workstation
(never plain HTTP to a node IP over the internet):

```bash
ssh -L 3200:localhost:3200 root@${NODE_IP}
# then, locally:
case "$PLATFORM_KEY" in ''|*[!A-Za-z0-9._~-]*) echo "Invalid platform key" >&2; exit 1;; esac
AUTH_FILE=$(mktemp); chmod 600 "$AUTH_FILE"
printf 'X-Steward-Platform-Key: %s\n' "$PLATFORM_KEY" > "$AUTH_FILE"
curl -sf http://localhost:3200/platform/tenants -H "@$AUTH_FILE"
rm -f "$AUTH_FILE"
```

---

## Update Steward on Existing Nodes

### Quick update (source sync + restart)

```bash
NODE_IP="<node-ip>"  # from your operator-local inventory (never committed — see Node Inventory)
STEWARD_SRC="/path/to/your/local/steward-checkout"  # your local clone of THIS repo

# 1. Sync updated source
rsync -az --delete \
  --exclude='.git' --exclude='node_modules' --exclude='.next' \
  --exclude='web' --exclude='.turbo' \
  -e "ssh -o StrictHostKeyChecking=accept-new" \
  "${STEWARD_SRC}/" root@${NODE_IP}:/opt/steward/

# 2. Install any new dependencies
ssh root@${NODE_IP} "cd /opt/steward && bun install"

# 3. Restart
ssh root@${NODE_IP} "systemctl restart steward"

# 4. Verify
ssh root@${NODE_IP} "curl -sf http://localhost:3200/health"
```

### Update all nodes at once

```bash
# Node IPs come from your operator-local inventory — the same one
# scripts/deploy-all.sh reads (STEWARD_NODES or scripts/deploy-nodes.local.conf).
NODES="<node-ip-1> <node-ip-2> <node-ip-3>"
STEWARD_SRC="/path/to/your/local/steward-checkout"  # your local clone of THIS repo

for NODE in $NODES; do
  echo "=== Updating ${NODE} ==="
  rsync -az --delete \
    --exclude='.git' --exclude='node_modules' --exclude='.next' \
    --exclude='web' --exclude='.turbo' \
    -e "ssh -o StrictHostKeyChecking=accept-new" \
    "${STEWARD_SRC}/" root@${NODE}:/opt/steward/
  ssh -o StrictHostKeyChecking=accept-new root@${NODE} "cd /opt/steward && bun install && systemctl restart steward"
  sleep 2
  ssh -o StrictHostKeyChecking=accept-new root@${NODE} "curl -sf http://localhost:3200/health"
  echo ""
done
```

---

## How Agent Provisioning Works

When a new agent container is created by the Milady Cloud provisioner:

### 1. Agent Registration
The provisioner calls the Steward API to create an agent:
```
POST /agents
X-Steward-Tenant: milady-cloud
X-Steward-Key: <tenant-api-key>
Body: { "id": "<agent-uuid>", "name": "Agent Name" }
```
This creates:
- An agent record in the database
- An EVM wallet (encrypted with master password)
- A Solana wallet (encrypted with master password)

### 2. Token Issuance
The provisioner gets a JWT for the agent:
```
POST /agents/<agent-id>/token
X-Steward-Tenant: milady-cloud
X-Steward-Key: <tenant-api-key>
```
Returns a 30-day JWT with `scope: "agent"`.

### 3. Container Environment
The container receives these env vars for Steward integration:
```
STEWARD_API_URL=http://172.18.0.1:3200   # Docker bridge gateway
STEWARD_AGENT_TOKEN=<jwt>                  # Agent-scoped JWT
STEWARD_AGENT_ID=<agent-id>               # Agent identifier
```

### 4. Agent → Steward Communication
Inside the container, the agent uses the `@stwd/sdk` or direct HTTP:
- **Check balance:** `GET /agents/<id>/balance` (Authorization: Bearer <jwt>)
- **Sign transaction:** `POST /vault/<id>/sign` (Authorization: Bearer <jwt>)
- **Get wallet address:** from agent creation response or `GET /agents/<id>`

### 5. Policy Enforcement
All signing requests are evaluated against the agent's policies before execution. The policy engine checks:
- Spending limits (per-tx, daily, weekly)
- Approved addresses (whitelist/blacklist)
- Rate limits
- Time windows
- Chain restrictions

---

## Verification Checklist

After deploying or updating, verify:

- [ ] `curl http://localhost:3200/health` returns `{"status":"ok",...}`
- [ ] `curl http://172.18.0.1:3200/health` works (Docker bridge access)
- [ ] `systemctl status steward` shows `active (running)`
- [ ] Creating a test agent works
- [ ] Signing a test transaction works
- [ ] Policy enforcement works (denied address returns 403)
- [ ] Agent JWT authentication works

### Full E2E smoke test

Run this ON the node or through an SSH tunnel (`ssh -L 3200:localhost:3200
root@<node-ip>`). Never point it at `http://<node-ip>:3200` over the
internet — the platform key and tenant keys would cross the network in
cleartext (SEC-022).

```bash
read -rsp "Platform key: " PK; printf '\n'
case "$PK" in ''|*[!A-Za-z0-9._~-]*) echo "Invalid platform key" >&2; exit 1;; esac
BASE="http://localhost:3200"
PLATFORM_HEADERS=$(mktemp); TENANT_HEADERS=$(mktemp); TOKEN_HEADERS=$(mktemp)
chmod 600 "$PLATFORM_HEADERS" "$TENANT_HEADERS" "$TOKEN_HEADERS"
trap 'rm -f "$PLATFORM_HEADERS" "$TENANT_HEADERS" "$TOKEN_HEADERS"' EXIT
printf 'X-Steward-Platform-Key: %s\n' "$PK" > "$PLATFORM_HEADERS"

# Create test tenant
RESP=$(curl -sf -X POST $BASE/platform/tenants \
  -H "Content-Type: application/json" \
  -H "@$PLATFORM_HEADERS" \
  -d '{"id":"smoke-test","name":"Smoke Test"}')
API_KEY=$(echo $RESP | jq -r '.data.apiKey')
printf 'X-Steward-Tenant: smoke-test\nX-Steward-Key: %s\n' "$API_KEY" > "$TENANT_HEADERS"

# Create agent
curl -sf -X POST $BASE/agents \
  -H "Content-Type: application/json" \
  -H "@$TENANT_HEADERS" \
  -d '{"id":"test-1","name":"Test Agent"}'

# Set policies
curl -sf -X PUT $BASE/agents/test-1/policies \
  -H "Content-Type: application/json" \
  -H "@$TENANT_HEADERS" \
  -d '[{"type":"spending-limit","enabled":true,"config":{"maxPerTx":"1000000000000000000","maxPerDay":"5000000000000000000"}}]'

# Get JWT
TOKEN=$(curl -sf -X POST $BASE/agents/test-1/token \
  -H "@$TENANT_HEADERS" | jq -r '.data.token')
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$TOKEN_HEADERS"

# Check balance
curl -sf $BASE/agents/test-1/balance \
  -H "@$TOKEN_HEADERS"

# Sign (no broadcast)
curl -sf -X POST $BASE/vault/test-1/sign \
  -H "Content-Type: application/json" \
  -H "@$TOKEN_HEADERS" \
  -d '{"to":"0x0000000000000000000000000000000000000001","value":"0","data":"0x","broadcast":false}'

# Clean up
curl -sf -X DELETE $BASE/agents/test-1 \
  -H "@$TENANT_HEADERS"
```

---

## Troubleshooting

### Steward won't start
```bash
journalctl -u steward --no-pager -n 50
journalctl -u steward-proxy --no-pager -n 50
# Legacy single-service:
journalctl -u steward --no-pager -n 50
```
Common causes:
- Missing `STEWARD_MASTER_PASSWORD` in `.env`
- Database connection failure (check `DATABASE_URL`)
- Port 3200 already in use (`ss -tlnp | grep 3200`)
- Port 8080 already in use (`ss -tlnp | grep 8080`)

### Containers can't reach Steward
- Verify bind host: `STEWARD_BIND_HOST=0.0.0.0` in `.env`
- Check Docker bridge IP: `docker network inspect bridge | grep Gateway`
- Test from container: `docker exec <container> curl http://172.18.0.1:3200/health`

### Policy engine crashes on signing
- Known issue: spending-limit policies without `maxPerWeek` caused `BigInt(undefined)` error
- **Fixed in commit 156e747** — ensure you're running latest source
- Check logs: `journalctl -u steward --since "5 minutes ago"`

### "Tenant not found" errors
- Verify the tenant through the owner-only platform header file created in the
  smoke-test procedure above:
  `curl -sf http://localhost:3200/platform/tenants -H "@$PLATFORM_HEADERS"`
- Create missing tenant via platform API

### High memory usage
- Steward typically uses ~140MB
- If growing unbounded, check for connection pool leaks
- Restart: `systemctl restart steward`

---

## Docker Image (Alternative Deployment)

The repo includes a `Dockerfile` for containerized deployment. However, the current production setup uses **systemd + bare metal Bun** because:
- Faster iteration (rsync + restart vs rebuild image)
- Shared Neon DB means no local Postgres needed
- Simpler debugging (journalctl vs docker logs)

To use Docker instead:
```bash
cd /opt/steward
docker compose -f docker-compose.yml up -d
```
Note: The root `docker-compose.yml` includes a local Postgres. For Neon, use the `deploy/docker-compose.yml` variant or override `DATABASE_URL`.

---

## Node Inventory

Node addresses are **operator-local configuration and are intentionally not
committed to this public repo** (SEC-130): a committed inventory of
custodial-wallet hosts is a confirmed target list and a network-reconnaissance
shortcut. Keep your inventory in one of:

- `STEWARD_NODES="milady=<ip> core-1=<ip> ..."` (consumed by `scripts/deploy-all.sh`)
- `scripts/deploy-nodes.local.conf` (gitignored; one `name=<ip>` per line)

Track node health/notes in your own ops system, not in this document.

> **Threat note — agent→API traffic on the Docker bridge:** the systemd
> topology below has agents reaching the API as plain HTTP to
> `http://172.18.0.1:3200` on the docker bridge. Bearer tokens are visible to
> any process able to tap host traffic (other containers, host compromise).
> Prefer the `deploy/docker-compose.yml` isolated-network path (agents reach
> the API by container name on `milady-isolated`; host ports are
> loopback-only) and front all external access with TLS.

---

## Credential Routes — Proxy Injection Setup

The proxy (`:8080`) requires at least one **credential route** per target API host before it can inject credentials. Without routes, all proxy requests return `403 No credential route configured`.

### How it works

1. Agent sends request to proxy: `Authorization: Bearer <agent-jwt>`
2. Proxy resolves path alias (e.g. `/openai/...` → `api.openai.com`)
3. Proxy looks up matching credential route for `(tenantId, host, path, method)`
4. Proxy decrypts the referenced secret from the vault
5. Credential is injected into the outbound request (header / query / body)
6. Request is forwarded to real API; agent JWT is stripped

### Named Aliases (built-in)

| Alias | Target Host |
|-------|------------|
| `/openai/...` | `api.openai.com` |
| `/anthropic/...` | `api.anthropic.com` |
| `/birdeye/...` | `public-api.birdeye.so` |
| `/coingecko/...` | `api.coingecko.com` |
| `/helius/...` | `api.helius.xyz` |

Direct proxy also works: `/proxy/<hostname>/<path>`

### Creating a secret

```bash
curl -s -X POST \
  -H "X-Steward-Tenant: <tenant-id>" \
  -H "X-Steward-Key: <tenant-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"name":"openai-prod","value":"sk-real-key-here","description":"OpenAI production key"}' \
  localhost:3200/secrets
# → {"ok":true,"data":{"id":"<secret-uuid>", ...}}
```

### Creating a credential route

```bash
# OpenAI — inject as Authorization: Bearer {value}
curl -s -X POST \
  -H "X-Steward-Tenant: <tenant-id>" \
  -H "X-Steward-Key: <tenant-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "secretId": "<secret-uuid>",
    "hostPattern": "api.openai.com",
    "pathPattern": "/*",
    "injectAs": "header",
    "injectKey": "Authorization",
    "injectFormat": "Bearer {value}",
    "priority": 10
  }' \
  localhost:3200/secrets/routes

# Anthropic — inject as x-api-key: {value}
curl -s -X POST \
  -H "X-Steward-Tenant: <tenant-id>" \
  -H "X-Steward-Key: <tenant-api-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "secretId": "<secret-uuid>",
    "hostPattern": "api.anthropic.com",
    "pathPattern": "/*",
    "injectAs": "header",
    "injectKey": "x-api-key",
    "injectFormat": "{value}",
    "priority": 10
  }' \
  localhost:3200/secrets/routes
```

### Route fields

| Field | Required | Description |
|-------|----------|-------------|
| `secretId` | ✅ | UUID of the secret to inject |
| `hostPattern` | ✅ | Exact hostname or wildcard (e.g. `*.example.com`) |
| `pathPattern` | — | Path prefix with wildcard, default `/*` |
| `method` | — | HTTP method filter, default `*` (all) |
| `injectAs` | ✅ | `header`, `query`, or `body` |
| `injectKey` | ✅ | Header name or query param key |
| `injectFormat` | — | Template with `{value}` placeholder, default `{value}` |
| `priority` | — | Higher wins when multiple routes match, default `0` |
| `enabled` | — | `true`/`false`, default `true` |

### Testing the proxy flow

```bash
# 1. Get an agent JWT
TOKEN=$(curl -s -X POST \
  -H "X-Steward-Tenant: <tenant-id>" \
  -H "X-Steward-Key: <tenant-api-key>" \
  -H "Content-Type: application/json" \
  -d '{"agentId":"<agent-uuid>","scopes":["api:proxy"],"expiresIn":"1h"}' \
  localhost:3200/agents/<agent-uuid>/token | jq -r '.data.token')

# 2. Make a proxied request (credential injected automatically)
curl -H "Authorization: Bearer $TOKEN" localhost:8080/openai/v1/models

# Expected with real key: 200 + model list
# Expected with dummy key: 401 invalid_api_key (proxy flow still worked!)
```

### Known issue fixed: GET /secrets/routes returns 500

**Root cause:** In Hono, `GET /:id` was registered before `GET /routes`, causing the literal path segment "routes" to be parsed as a secret UUID — which fails PostgreSQL UUID validation and throws a 500.

**Fix:** Reordered route registration in `packages/api/src/routes/secrets.ts` so all `/routes/*` handlers are declared before `/:id` handlers. **Committed in `29e8a13`.**

---

## Redis Setup (required in production)

Redis enables persistent rate limiting and spend tracking that survives API restarts. The Docker Compose deploy ships a `redis` service and sets `REDIS_URL` on `steward-proxy`; **in production the proxy fails closed without Redis** (see below). Redis is only optional in non-production or when `STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL=true` is set, in which case rate-limit/spend counters are in-memory only and reset on restart.

### Install Redis on a node

```bash
apt-get install -y redis-server
systemctl enable redis-server
systemctl start redis-server
redis-cli ping  # → PONG
```

### Configure in .env

```bash
# Add to /opt/steward/.env:
REDIS_URL=redis://localhost:6379

# Or with password:
REDIS_URL=redis://:yourpassword@localhost:6379
```

### Verify Redis integration

```bash
# After restarting Steward, check logs for:
# [redis] Connected to redis://localhost:6379
journalctl -u steward --since "1 minute ago" | grep redis
```

Redis is used for:
- **Rate limiting** — `rate-limit` policy counters (tx/hour, tx/day) persist across restarts
- **Spend tracking** — daily/weekly spend totals survive restarts
- **Webhook delivery queue** — retries are queued in Redis

In **production** (`NODE_ENV=production`) the proxy treats Redis as **required** and fails **closed** without it: `checkProxyRateLimit`/`checkProxySpendLimit` reject requests (429/402/503) unless you explicitly set `STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL=true`. The compose deploy therefore ships a `redis` service and sets `REDIS_URL`. Only in non-production (or with the soft-fail override) do rate-limit/spend counters fall back to in-memory and reset on restart.

### Eviction policy (SEC-021 follow-up)

The shipped production compose stacks (`docker-compose.yml` and
`deploy/docker-compose.yml`) set `--maxmemory-policy noeviction`. Under memory
pressure, Redis therefore fails writes instead of silently evicting spend and
rate counters; Steward's enforcement path treats those failures as closed.
Alert on `used_memory` well below `maxmemory` so availability problems are
handled before the fail-closed boundary is reached. The enterprise-reference
stack and any externally managed or custom Redis must be configured and
verified separately: use `noeviction` for enforcement counters (or document a
deliberate financial-control risk acceptance), isolate them from cache
workloads, and never assume an eviction policy such as `allkeys-lru` is safe.

---

## Webhook Configuration

After deploying, configure webhooks for your tenants to receive real-time event notifications:

```bash
BASE="http://localhost:3200"
read -rsp "Tenant API key: " API_KEY; printf '\n'
TENANT_HEADERS=$(mktemp); WEBHOOK_RESPONSE=$(mktemp)
chmod 600 "$TENANT_HEADERS" "$WEBHOOK_RESPONSE"
trap 'rm -f "$TENANT_HEADERS"' EXIT
printf 'X-Steward-Key: %s\n' "$API_KEY" > "$TENANT_HEADERS"

# Register a webhook endpoint
curl -sf -X POST $BASE/webhooks \
  -H "@$TENANT_HEADERS" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhooks/steward",
    "events": ["tx.pending", "tx.signed", "policy.violation"],
    "description": "Production webhook",
    "maxRetries": 5,
    "retryBackoffMs": 60000
  }' > "$WEBHOOK_RESPONSE"
echo "Webhook config and one-time secret saved to $WEBHOOK_RESPONSE (mode 0600)"
```

**Securely move or consume `WEBHOOK_RESPONSE`, then delete it.** The `secret`
field is only returned on creation and is used to verify
`X-Steward-Signature` on incoming events; do not print it into terminal or CI
logs.

> **At-rest encryption and legacy plaintext rows (SEC-088):** webhook secrets
> are encrypted at rest (AES-256-GCM; key from
> `STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY`/`STEWARD_MASTER_PASSWORD`). Configs
> written before encryption shipped may still hold **plaintext** secrets.
> There is deliberately **no eager mass re-encryption at boot** — a boot-time
> rewrite would need the encryption key during migrations and would race
> concurrently booting replicas. Instead each config row is upgraded lazily,
> via a compare-and-swap on the stored value, the next time that webhook
> fires or is re-saved (see `packages/api/src/services/webhook-dispatch.ts`),
> and new delivery rows only ever snapshot the encrypted form. Until a legacy
> config fires or is re-saved, its plaintext secret stays recoverable by
> anyone with DB read access (backup leak, read replica). **After upgrading,
> rotate or re-save pre-existing webhooks to force immediate re-encryption.**

### Verify webhook delivery

```bash
# List recent deliveries
WEBHOOK_ID="wh_..."
curl -sf "$BASE/webhooks/$WEBHOOK_ID/deliveries" \
  -H "@$TENANT_HEADERS"
```

---

## E2E Integration Test

The repo includes a full E2E test script that validates the complete flow:

```bash
# Run against a specific node via SSH tunnel (node ports are loopback-only —
# never point STEWARD_URL at http://<node-ip>:3200 over the internet):
#   ssh -L 3200:localhost:3200 root@<node-ip>
STEWARD_URL=http://localhost:3200 bun run scripts/e2e-integration-test.ts

# With proxy (default: STEWARD_URL with :3200 → :8080)
STEWARD_URL=http://localhost:3200 PROXY_URL=http://localhost:8080 \
  bun run scripts/e2e-integration-test.ts
```

The E2E test covers:
1. Tenant + agent provisioning
2. Wallet operations (balance, sign, policy enforcement)
3. Proxy operations (credential injection, audit logging)
4. Secret management (CRUD, rotation, credential routes)
5. Redis enforcement (rate limits, spend tracking)
6. Cascading cleanup

Expected output on a healthy node:
```
✅ PASS: Create tenant
✅ PASS: Create agent
✅ PASS: Set policies
✅ PASS: Get agent JWT
✅ PASS: Check balance
✅ PASS: Sign transaction (whitelisted address)
✅ PASS: Policy rejection (non-whitelisted address)
✅ PASS: Create secret
✅ PASS: Create credential route
✅ PASS: Proxy injection (OpenAI alias)
✅ PASS: Cleanup
─────────────────────────────────────────
Passed: 11/11  Failed: 0  Skipped: 0
```

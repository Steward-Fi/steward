# Steward Deployment Guide

> Last updated: 2026-03-27

## Overview

Steward runs as two **systemd services** on each Milady node, built from source using Bun. It connects to a shared Neon PostgreSQL database and an optional Redis instance for rate limiting and spend tracking.

- `steward.service` — REST API on port 3200
- `steward-proxy.service` — API proxy gateway on port 8080

**Current production nodes:** milady-core-1 through milady-core-6 (all Hetzner dedicated servers).

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
# From your workstation (where you have the steward-fi repo)
NODE_IP="<node-ip>"
rsync -az --delete \
  --exclude='.git' --exclude='node_modules' --exclude='.next' \
  --exclude='web' --exclude='.turbo' \
  -e "ssh -o StrictHostKeyChecking=accept-new" \
  /home/shad0w/projects/steward-fi/ root@${NODE_IP}:/opt/steward/
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

# Database (shared Neon Postgres — steward schema)
DATABASE_URL=postgresql://neondb_owner:<password>@<neon-host>/neondb?sslmode=require&options=-c search_path=steward,public

# Vault encryption
STEWARD_MASTER_PASSWORD=<256-bit-hex-secret>

# Auth
STEWARD_JWT_SECRET=<separate-jwt-secret>
STEWARD_PLATFORM_KEYS=<platform-admin-key>

# RPC
RPC_URL=https://mainnet.base.org
CHAIN_ID=8453
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com

# Redis (optional — enables rate limiting + spend tracking)
# REDIS_URL=redis://localhost:6379

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
| `STEWARD_BIND_HOST` | Must be `0.0.0.0` for Docker containers to reach it | Yes |
| `REDIS_URL` | Redis connection string for rate limiting + spend tracking | Yes (production) |
| `STEWARD_PROXY_REQUEST_SIGNING_SECRETS` | Shared secret(s) the proxy uses to verify every request signature | Yes (production) |
| `RPC_URL` | EVM RPC endpoint (default: Base mainnet) | No |

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
call the API over localhost via the SSH channel (SEC-022):

```bash
ssh root@${NODE_IP} "PK=\$(grep '^STEWARD_PLATFORM_KEYS=' /etc/steward/env | cut -d= -f2- | cut -d, -f1); \
  curl -sf -X POST http://localhost:3200/platform/tenants \
  -H 'Content-Type: application/json' \
  -H \"X-Steward-Platform-Key: \${PK}\" \
  -d '{\"id\": \"milady-cloud\", \"name\": \"Milady Cloud\"}'"
```

For any other platform-key operation, use an SSH tunnel from your workstation
(never plain HTTP to a node IP over the internet):

```bash
ssh -L 3200:localhost:3200 root@${NODE_IP}
# then, locally:
curl -sf http://localhost:3200/platform/tenants -H "X-Steward-Platform-Key: $PLATFORM_KEY"
```

---

## Update Steward on Existing Nodes

### Quick update (source sync + restart)

```bash
NODE_IP="88.99.66.168"  # milady-core-1

# 1. Sync updated source
rsync -az --delete \
  --exclude='.git' --exclude='node_modules' --exclude='.next' \
  --exclude='web' --exclude='.turbo' \
  -e "ssh -o StrictHostKeyChecking=accept-new" \
  /home/shad0w/projects/steward-fi/ root@${NODE_IP}:/opt/steward/

# 2. Install any new dependencies
ssh root@${NODE_IP} "cd /opt/steward && bun install"

# 3. Restart
ssh root@${NODE_IP} "systemctl restart steward"

# 4. Verify
ssh root@${NODE_IP} "curl -sf http://localhost:3200/health"
```

### Update all nodes at once

```bash
NODES="88.99.66.168 178.63.251.122 138.201.80.125 85.10.193.52 136.243.47.243 195.201.57.227"

for NODE in $NODES; do
  echo "=== Updating ${NODE} ==="
  rsync -az --delete \
    --exclude='.git' --exclude='node_modules' --exclude='.next' \
    --exclude='web' --exclude='.turbo' \
    -e "ssh -o StrictHostKeyChecking=accept-new" \
    /home/shad0w/projects/steward-fi/ root@${NODE}:/opt/steward/
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
PK="<platform-key>"
BASE="http://localhost:3200"

# Create test tenant
RESP=$(curl -sf -X POST $BASE/platform/tenants \
  -H "Content-Type: application/json" \
  -H "X-Steward-Platform-Key: $PK" \
  -d '{"id":"smoke-test","name":"Smoke Test"}')
API_KEY=$(echo $RESP | jq -r '.data.apiKey')

# Create agent
curl -sf -X POST $BASE/agents \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: smoke-test" \
  -H "X-Steward-Key: $API_KEY" \
  -d '{"id":"test-1","name":"Test Agent"}'

# Set policies
curl -sf -X PUT $BASE/agents/test-1/policies \
  -H "Content-Type: application/json" \
  -H "X-Steward-Tenant: smoke-test" \
  -H "X-Steward-Key: $API_KEY" \
  -d '[{"type":"spending-limit","enabled":true,"config":{"maxPerTx":"1000000000000000000","maxPerDay":"5000000000000000000"}}]'

# Get JWT
TOKEN=$(curl -sf -X POST $BASE/agents/test-1/token \
  -H "X-Steward-Tenant: smoke-test" \
  -H "X-Steward-Key: $API_KEY" | jq -r '.data.token')

# Check balance
curl -sf $BASE/agents/test-1/balance \
  -H "Authorization: Bearer $TOKEN"

# Sign (no broadcast)
curl -sf -X POST $BASE/vault/test-1/sign \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"to":"0x0000000000000000000000000000000000000001","value":"0","data":"0x","broadcast":false}'

# Clean up
curl -sf -X DELETE $BASE/agents/test-1 \
  -H "X-Steward-Tenant: smoke-test" \
  -H "X-Steward-Key: $API_KEY"
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
- Verify tenant exists: `curl -sf http://localhost:3200/platform/tenants -H 'X-Steward-Platform-Key: <key>'`
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

| Node | IP | API (:3200) | Proxy (:8080) | Notes |
|------|-----|------------|--------------|-------|
| milady-core-1 | 88.99.66.168 | ✅ Running | ✅ Running | Primary; front with your own domain/TLS |
| milady-core-2 | 178.63.251.122 | ✅ Running | ✅ Running | |
| milady-core-3 | 138.201.80.125 | ✅ Running | ✅ Running | |
| milady-core-4 | 85.10.193.52 | ✅ Running | ✅ Running | |
| milady-core-5 | 136.243.47.243 | ✅ Running | ✅ Running | |
| milady-core-6 | 195.201.57.227 | ✅ Running | ✅ Running | |

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

---

## Webhook Configuration

After deploying, configure webhooks for your tenants to receive real-time event notifications:

```bash
PK="<your-platform-key>"
API_KEY="<tenant-api-key>"
BASE="http://localhost:3200"

# Register a webhook endpoint
curl -sf -X POST $BASE/webhooks \
  -H "X-Steward-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/webhooks/steward",
    "events": ["tx.pending", "tx.signed", "policy.violation"],
    "description": "Production webhook",
    "maxRetries": 5,
    "retryBackoffMs": 60000
  }'
# → Returns webhook config including "secret" (save this!)
```

**Save the `secret` field** — it's only returned on creation. Use it to verify `X-Steward-Signature` on incoming events.

### Verify webhook delivery

```bash
# List recent deliveries
WEBHOOK_ID="wh_..."
curl -sf "$BASE/webhooks/$WEBHOOK_ID/deliveries" \
  -H "X-Steward-Key: $API_KEY"
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

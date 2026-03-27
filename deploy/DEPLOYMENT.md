# Steward Deployment Guide

> Last updated: 2026-03-27

## Overview

Steward runs as a **systemd service** on each Milady node, built from source using Bun. It connects to a shared Neon PostgreSQL database and listens on port 3200.

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
│  Docker: agent containers                             │
│    └─ Reach steward at: http://172.18.0.1:3200        │
│       (Docker bridge gateway IP)                      │
│                                                       │
│  External: api.steward.fi → milady-core-1:3200        │
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
  -e "ssh -o StrictHostKeyChecking=no" \
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
| `RPC_URL` | EVM RPC endpoint (default: Base mainnet) | No |

### Step 4: Create systemd service

```bash
ssh root@${NODE_IP} "cat > /etc/systemd/system/steward.service << 'EOF'
[Unit]
Description=Steward Wallet Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/steward
ExecStart=/root/.bun/bin/bun run packages/api/src/index.ts
Restart=always
RestartSec=10
EnvironmentFile=/opt/steward/.env

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable steward
systemctl start steward"
```

### Step 5: Verify

```bash
# Health check
ssh root@${NODE_IP} "curl -sf http://localhost:3200/health"
# Expected: {"status":"ok","version":"0.2.0","uptime":...}

# Check it's reachable from Docker bridge
ssh root@${NODE_IP} "curl -sf http://172.18.0.1:3200/health"
```

### Step 6: Create milady-cloud tenant (if first time)

```bash
PLATFORM_KEY="<your-platform-key>"
ssh root@${NODE_IP} "curl -sf -X POST http://localhost:3200/platform/tenants \
  -H 'Content-Type: application/json' \
  -H 'X-Steward-Platform-Key: ${PLATFORM_KEY}' \
  -d '{\"id\": \"milady-cloud\", \"name\": \"Milady Cloud\"}'"
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
  -e "ssh -o StrictHostKeyChecking=no" \
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
    -e "ssh -o StrictHostKeyChecking=no" \
    /home/shad0w/projects/steward-fi/ root@${NODE}:/opt/steward/
  ssh -o StrictHostKeyChecking=no root@${NODE} "cd /opt/steward && bun install && systemctl restart steward"
  sleep 2
  ssh -o StrictHostKeyChecking=no root@${NODE} "curl -sf http://localhost:3200/health"
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
```
Common causes:
- Missing `STEWARD_MASTER_PASSWORD` in `.env`
- Database connection failure (check `DATABASE_URL`)
- Port 3200 already in use (`ss -tlnp | grep 3200`)

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

| Node | IP | Steward | Status |
|------|-----|---------|--------|
| milady-core-1 | 88.99.66.168 | ✅ Running | Primary, hosts api.steward.fi |
| milady-core-2 | 178.63.251.122 | ✅ Running | |
| milady-core-3 | 138.201.80.125 | ✅ Running | |
| milady-core-4 | 85.10.193.52 | ✅ Running | |
| milady-core-5 | 136.243.47.243 | ✅ Running | |
| milady-core-6 | 195.201.57.227 | ✅ Running | |

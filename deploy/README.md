# Steward — Node Deployment Guide

Deploy Steward as the key management and policy-enforcement layer for Milady agent nodes.

## Architecture

```
┌─────────────────────── Milady Node ───────────────────────┐
│                    milady-isolated network                 │
│                                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐      │
│  │  Agent A     │  │  Agent B     │  │  Agent C     │     │
│  │  (milady-*)  │  │  (milady-*)  │  │  (milady-*)  │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         └────────────────┬┘─────────────────┘              │
│                          │                                 │
│                   ┌──────▼───────┐                         │
│                   │   Steward    │  :3200                  │
│                   │  (vault +    │                         │
│                   │   policies)  │                         │
│                   └──────┬───────┘                         │
│                          │                                 │
│                   ┌──────▼───────┐                         │
│                   │  PostgreSQL  │  (or external Neon)     │
│                   │  steward-db  │                         │
│                   └──────────────┘                         │
└───────────────────────────────────────────────────────────┘
```

Agents never hold private keys directly. They request signatures from Steward, which enforces spending limits, allowlists, and approval flows.

## Quick Start

### Prerequisites

- Docker & Docker Compose on the target node
- SSH access to the node
- The `milady-isolated` Docker network (created by the Milady orchestrator)

### 1. Deploy Steward

```bash
# Set the master password (encrypts all vault keys at rest)
export STEWARD_MASTER_PASSWORD="$(openssl rand -base64 32)"

# Deploy to a node
./deploy/provision-steward-node.sh 88.99.66.168

# Save the output — it contains the platform key and agent config
```

### 2. Migrate Existing Agents

```bash
# Dry run first — see what would happen
./deploy/migrate-agent-keys.sh 88.99.66.168 <platform-key> --dry-run

# Execute migration
./deploy/migrate-agent-keys.sh 88.99.66.168 <platform-key>
```

### 3. Configure Agents

Add these env vars to each agent container:

```bash
STEWARD_API_URL=http://steward:3200    # Container-to-container via Docker network
STEWARD_AGENT_ID=<agent-uuid>
STEWARD_AGENT_TOKEN=<from-migration-output>
```

## Configuration Reference

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `STEWARD_MASTER_PASSWORD` | ✅ | — | Encryption password for vault keys |
| `DATABASE_URL` | — | Local PG | PostgreSQL connection string |
| `PORT` | — | `3200` | API listen port |
| `RPC_URL` | — | `https://mainnet.base.org` | EVM RPC endpoint |
| `CHAIN_ID` | — | `8453` | EVM chain ID (Base mainnet) |
| `SOLANA_RPC_URL` | — | `https://api.mainnet-beta.solana.com` | Solana RPC |
| `STEWARD_PLATFORM_KEY` | — | Auto-generated | Platform API key for admin operations |

### Using an External Database (Neon)

To use Neon or another hosted Postgres instead of the local container:

1. Set `DATABASE_URL` in `deploy/.env`:
   ```
   DATABASE_URL=postgresql://user:pass@ep-xxx.neon.tech/steward?sslmode=require
   ```
2. In `docker-compose.yml`, comment out the `steward-db` service and the `depends_on` block.

### Volumes

| Volume | Purpose |
|---|---|
| `steward-data` | Application data directory |
| `steward-pgdata` | PostgreSQL data (only if using local PG) |

## API Endpoints

### Health Check
```
GET /health → { "ok": true, "status": "healthy" }
```

### Platform API (admin)
Authenticated via `X-Steward-Platform-Key` header.

| Method | Path | Description |
|---|---|---|
| `POST` | `/platform/tenants` | Create tenant |
| `GET` | `/platform/tenants` | List tenants |
| `GET` | `/platform/tenants/:id` | Get tenant details |
| `DELETE` | `/platform/tenants/:id` | Delete tenant |
| `PUT` | `/platform/tenants/:id/policies` | Set agent policies |
| `POST` | `/platform/tenants/:id/agents` | Create agent |
| `POST` | `/platform/tenants/:id/agents/batch` | Batch create agents |
| `GET` | `/platform/tenants/:id/agents` | List agents |
| `GET` | `/platform/stats` | Platform statistics |

### Agent API
Authenticated via `Authorization: Bearer <agent-token>` or API key.

Agents use the SDK (`@stwd/sdk`) to interact with Steward — see the [SDK docs](../packages/sdk/README.md).

## Operations

### View Logs
```bash
ssh root@<node-ip> "docker compose -f /opt/steward/deploy/docker-compose.yml logs -f steward"
```

### Restart Steward
```bash
ssh root@<node-ip> "docker compose -f /opt/steward/deploy/docker-compose.yml restart steward"
```

### Database Migrations
Migrations run automatically on startup via `@stwd/db`'s migrate module.

### Backup
```bash
# Backup PostgreSQL data
ssh root@<node-ip> "docker exec steward-db pg_dump -U steward steward > /data/backups/steward-$(date +%Y%m%d).sql"
```

## Troubleshooting

### Steward won't start
1. Check logs: `docker compose logs steward`
2. Verify `STEWARD_MASTER_PASSWORD` is set in `.env`
3. Verify `DATABASE_URL` is reachable (try `docker exec steward-db pg_isready`)
4. Check port 3200 isn't already in use: `ss -tlnp | grep 3200`

### Agents can't reach Steward
1. Verify both containers are on `milady-isolated`: `docker network inspect milady-isolated`
2. Test from agent container: `docker exec <agent> curl http://steward:3200/health`
3. Check Steward is healthy: `curl http://localhost:3200/health`

### Database connection errors
1. If using local PG: `docker compose logs steward-db`
2. If using Neon: verify the connection string and that the IP isn't blocked
3. Check DNS resolution: `docker exec steward nslookup steward-db`

### Migration script failures
1. Run with `--dry-run` first to verify agent discovery
2. Check that the platform key matches what Steward is running with
3. Verify the `milady-cloud` tenant exists: `curl -H 'X-Steward-Platform-Key: <key>' http://localhost:3200/platform/tenants`

## Security Notes

- **Master password**: Store securely. If lost, vault keys cannot be recovered. Consider using a secrets manager.
- **Platform key**: Provides full admin access. Rotate periodically.
- **Network isolation**: Steward runs on `milady-isolated` and should NOT be exposed to the public internet without authentication.
- **Port 3200**: Bound to `0.0.0.0` by default for initial setup. In production, consider binding to `127.0.0.1` or using a reverse proxy.

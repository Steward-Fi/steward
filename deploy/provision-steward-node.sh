#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# provision-steward-node.sh — Deploy Steward on a Milady node
#
# Idempotent: safe to re-run. Will rebuild image and restart service.
#
# Usage:
#   ./deploy/provision-steward-node.sh <node-ip> [ssh-key]
#
# Environment variables (required):
#   STEWARD_MASTER_PASSWORD  — Vault master encryption password
#
# Optional env vars:
#   DATABASE_URL             — External DB (default: local Postgres via compose)
#   RPC_URL                  — EVM RPC endpoint (default: Base mainnet)
#   CHAIN_ID                 — EVM chain ID (default: 8453)
#   SOLANA_RPC_URL           — Solana RPC endpoint
#   STEWARD_REPO             — Git repo URL (default: current directory rsync)
#   SSH_KEY                  — Path to SSH key (default: ~/.ssh/id_ed25519)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Args ─────────────────────────────────────────────────────────────────────
NODE_IP="${1:?Usage: $0 <node-ip> [ssh-key]}"
SSH_KEY="${2:-${SSH_KEY:-$HOME/.ssh/id_ed25519}}"

# ── Validation ───────────────────────────────────────────────────────────────
if [[ -z "${STEWARD_MASTER_PASSWORD:-}" ]]; then
  echo "❌ STEWARD_MASTER_PASSWORD is required"
  exit 1
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i ${SSH_KEY}"
SSH_CMD="ssh ${SSH_OPTS} root@${NODE_IP}"
SCP_CMD="scp ${SSH_OPTS}"
REMOTE_DIR="/opt/steward"

echo "══════════════════════════════════════════════════════════════"
echo "  Steward Node Provisioning"
echo "  Node: ${NODE_IP}"
echo "══════════════════════════════════════════════════════════════"

# ── Step 1: Ensure milady-isolated network exists ────────────────────────────
echo ""
echo "▸ Step 1: Checking Docker network..."
${SSH_CMD} "docker network inspect milady-isolated >/dev/null 2>&1 || docker network create milady-isolated"
echo "  ✓ milady-isolated network ready"

# ── Step 2: Sync source code to node ────────────────────────────────────────
echo ""
echo "▸ Step 2: Syncing Steward source to ${NODE_IP}:${REMOTE_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# rsync source (excluding heavy dirs)
rsync -az --delete \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='.next' \
  --exclude='web' \
  --exclude='.turbo' \
  --exclude='deploy/.env' \
  -e "ssh ${SSH_OPTS}" \
  "${REPO_ROOT}/" "root@${NODE_IP}:${REMOTE_DIR}/"
echo "  ✓ Source synced"

# ── Step 3: Write .env file on node ─────────────────────────────────────────
echo ""
echo "▸ Step 3: Writing environment config..."

# Read the existing remote .env (if any) so re-runs are idempotent and do NOT
# rotate generated secrets (rotating STEWARD_KDF_SALT/STEWARD_JWT_SECRET would
# brick an existing vault / invalidate sessions).
EXISTING_ENV="$(${SSH_CMD} "cat ${REMOTE_DIR}/deploy/.env 2>/dev/null || true")"

# env_get <KEY>: echo the value of KEY from the existing remote .env, else empty.
env_get() {
  printf '%s\n' "${EXISTING_ENV}" | sed -n "s/^$1=//p" | head -n1
}

# Reuse already-generated secrets if present, otherwise generate fresh ones.
STEWARD_JWT_SECRET="${STEWARD_JWT_SECRET:-$(env_get STEWARD_JWT_SECRET)}"
[[ -n "${STEWARD_JWT_SECRET}" ]] || STEWARD_JWT_SECRET="$(openssl rand -hex 32)"
STEWARD_KDF_SALT="${STEWARD_KDF_SALT:-$(env_get STEWARD_KDF_SALT)}"
[[ -n "${STEWARD_KDF_SALT}" ]] || STEWARD_KDF_SALT="$(openssl rand -hex 32)"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-$(env_get POSTGRES_PASSWORD)}"
[[ -n "${POSTGRES_PASSWORD}" ]] || POSTGRES_PASSWORD="$(openssl rand -hex 32)"
STEWARD_PROXY_REQUEST_SIGNING_SECRETS="${STEWARD_PROXY_REQUEST_SIGNING_SECRETS:-$(env_get STEWARD_PROXY_REQUEST_SIGNING_SECRETS)}"
[[ -n "${STEWARD_PROXY_REQUEST_SIGNING_SECRETS}" ]] || STEWARD_PROXY_REQUEST_SIGNING_SECRETS="$(openssl rand -hex 32)"
PLATFORM_KEY="${STEWARD_PLATFORM_KEY:-$(env_get STEWARD_PLATFORM_KEY)}"
[[ -n "${PLATFORM_KEY}" ]] || PLATFORM_KEY="$(openssl rand -hex 32)"

# Render the .env LOCALLY into a mode-0600 temp file, then stream it to the node
# over ssh stdin. Secrets never appear on any command line (local or remote).
LOCAL_ENV_FILE="$(umask 077 && mktemp)"
trap 'rm -f "${LOCAL_ENV_FILE}"' EXIT
cat > "${LOCAL_ENV_FILE}" << ENVEOF
STEWARD_MASTER_PASSWORD=${STEWARD_MASTER_PASSWORD}
STEWARD_JWT_SECRET=${STEWARD_JWT_SECRET}
STEWARD_KDF_SALT=${STEWARD_KDF_SALT}
STEWARD_PLATFORM_KEY=${PLATFORM_KEY}
STEWARD_PROXY_REQUEST_SIGNING_SECRETS=${STEWARD_PROXY_REQUEST_SIGNING_SECRETS}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DATABASE_URL=${DATABASE_URL:-}
REDIS_URL=${REDIS_URL:-redis://redis:6379}
RPC_URL=${RPC_URL:-https://mainnet.base.org}
CHAIN_ID=${CHAIN_ID:-8453}
SOLANA_RPC_URL=${SOLANA_RPC_URL:-https://api.mainnet-beta.solana.com}
ENVEOF

${SSH_CMD} "umask 077; cat > ${REMOTE_DIR}/deploy/.env" < "${LOCAL_ENV_FILE}"
echo "  ✓ Environment configured"

# ── Step 4: Build and start services ────────────────────────────────────────
echo ""
echo "▸ Step 4: Building Steward Docker image..."
${SSH_CMD} "cd ${REMOTE_DIR} && docker compose -f deploy/docker-compose.yml build --no-cache steward"
echo "  ✓ Image built"

echo ""
echo "▸ Step 5: Starting services..."
${SSH_CMD} "cd ${REMOTE_DIR} && docker compose -f deploy/docker-compose.yml up -d"
echo "  ✓ Services started"

# ── Step 6: Wait for healthy ─────────────────────────────────────────────────
echo ""
echo "▸ Step 6: Waiting for Steward to become healthy..."
for i in $(seq 1 30); do
  if ${SSH_CMD} "curl -sf http://localhost:3200/health" >/dev/null 2>&1; then
    echo "  ✓ Steward is healthy!"
    break
  fi
  if [[ $i -eq 30 ]]; then
    echo "  ❌ Steward failed to start within 60s"
    echo "  Check logs: ssh root@${NODE_IP} docker compose -f ${REMOTE_DIR}/deploy/docker-compose.yml logs steward"
    exit 1
  fi
  sleep 2
done

# ── Step 7: Create milady-cloud tenant (idempotent) ─────────────────────────
echo ""
echo "▸ Step 7: Creating milady-cloud tenant..."

# The platform key was written to deploy/.env in Step 3 and picked up by the
# container at boot. Create the tenant by reading the key on the REMOTE side
# (PK=$(...)) so the secret is never placed on the local->remote command line
# nor printed to this script's stdout / CI logs.
TENANT_RESP=$(${SSH_CMD} "set -e; PK=\$(sed -n 's/^STEWARD_PLATFORM_KEY=//p' ${REMOTE_DIR}/deploy/.env | head -n1); \
curl -sf -X POST http://localhost:3200/platform/tenants \
  -H 'Content-Type: application/json' \
  -H \"X-Steward-Platform-Key: \${PK}\" \
  -d '{\"id\": \"milady-cloud\", \"name\": \"Milady Cloud\"}'" 2>&1 || true)

if echo "${TENANT_RESP}" | grep -q '"ok":true'; then
  echo "  ✓ Tenant milady-cloud created"
elif echo "${TENANT_RESP}" | grep -qi 'already exists\|conflict\|duplicate'; then
  echo "  ✓ Tenant milady-cloud already exists"
else
  echo "  ⚠  Tenant creation response: ${TENANT_RESP}"
fi

# ── Output ───────────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✅ Steward deployed successfully!"
echo ""
echo "  Steward URL:    http://${NODE_IP}:3200"
echo "  Health check:   http://${NODE_IP}:3200/health"
echo "  Platform Key:   (written to ${REMOTE_DIR}/deploy/.env, mode 0600, on the node; retrieve it there, not printed here)"
echo ""
echo "  Agent config (add to container env):"
echo "    STEWARD_API_URL=http://steward:3200"
echo "    STEWARD_PROXY_REQUEST_SIGNING_SECRETS=(retrieve from ${REMOTE_DIR}/deploy/.env on the node, not printed here)"
echo "    # Agents must use this shared secret to sign proxied requests; the node-side .env is mode 0600."
echo "    (agents on milady-isolated network reach Steward by container name)"
echo ""
echo "  External access:"
echo "    STEWARD_API_URL=http://${NODE_IP}:3200"
echo "══════════════════════════════════════════════════════════════"

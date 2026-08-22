#!/bin/bash
set -euo pipefail

# =============================================================================
# Steward Node Deployer
# Usage: ./scripts/deploy.sh <node-ip> [--migrate] [--restart] [--skip-install]
# =============================================================================

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

log()  { echo -e "${CYAN}[deploy]${RESET} $*"; }
ok()   { echo -e "${GREEN}[deploy]${RESET} $*"; }
warn() { echo -e "${YELLOW}[deploy]${RESET} $*"; }
fail() { echo -e "${RED}[deploy]${RESET} $*"; }

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
NODE_IP=""
DO_MIGRATE=false
DO_RESTART=false
SKIP_INSTALL=false

for arg in "$@"; do
  case "$arg" in
    --migrate)      DO_MIGRATE=true ;;
    --restart)      DO_RESTART=true ;;
    --skip-install) SKIP_INSTALL=true ;;
    -h|--help)
      echo "Usage: $0 <node-ip> [--migrate] [--restart] [--skip-install]"
      exit 0
      ;;
    -*)
      fail "Unknown flag: $arg"
      exit 1
      ;;
    *)
      if [[ -z "$NODE_IP" ]]; then
        NODE_IP="$arg"
      else
        fail "Unexpected argument: $arg"
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$NODE_IP" ]]; then
  fail "Missing required argument: <node-ip>"
  echo "Usage: $0 <node-ip> [--migrate] [--restart] [--skip-install]"
  exit 1
fi

# Validate IP-ish format (IPv4 or hostname)
if ! [[ "$NODE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$NODE_IP" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  fail "Invalid node address: $NODE_IP"
  exit 1
fi

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REMOTE_DIR="/opt/steward"
REMOTE_MIGRATION_ENV="${REMOTE_DIR}/.env.migrate"
BUN="/root/.bun/bin/bun"

# Host-key checking: TOFU (accept-new) at minimum — never "no" (SEC-019).
# Set STRICT_HOST_KEY=yes to require a pre-pinned known_hosts entry instead.
if [[ "${STRICT_HOST_KEY:-}" == "yes" ]]; then
  SSH_OPTS="-o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o BatchMode=yes"
else
  SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes"
fi

remote() {
  ssh $SSH_OPTS "root@${NODE_IP}" "$@"
}

# ---------------------------------------------------------------------------
# 1. Rsync source
# ---------------------------------------------------------------------------
log "Syncing source to $NODE_IP:$REMOTE_DIR ..."

rsync -az --delete \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='web' \
  --exclude='.turbo' \
  --exclude='.next' \
  --exclude='dist' \
  --exclude='coverage' \
  --exclude='.env' \
  -e "ssh $SSH_OPTS" \
  "$REPO_ROOT/" "root@${NODE_IP}:${REMOTE_DIR}/"

ok "Source synced"

# ---------------------------------------------------------------------------
# 2. Install dependencies
# ---------------------------------------------------------------------------
if ! $SKIP_INSTALL; then
  log "Installing dependencies ..."
  remote "cd $REMOTE_DIR && $BUN install --frozen-lockfile 2>&1 || $BUN install 2>&1" | tail -3
  ok "Dependencies installed"
else
  warn "Skipping install (--skip-install)"
fi

# ---------------------------------------------------------------------------
# 3. Migrations
# ---------------------------------------------------------------------------
if $DO_MIGRATE; then
  log "Running complete release migrations on $NODE_IP ..."

  # Privileged database URLs must live in the root-only migration environment,
  # never in the API service's .env. Apply core + enabled-plugin journals as the
  # dedicated migrator, then restore bootstrap ownership/ACLs as the provider
  # operator, and finally activate the exact RLS inventory as the migrator.
  # rls-bootstrap.sql requires a PostgreSQL superuser or provider-equivalent
  # able to create/alter BYPASSRLS roles; CREATEROLE alone is insufficient.
  MIGRATION_COMMAND=$(cat <<EOF
cd $REMOTE_DIR &&
test -f '.env' &&
test -f '$REMOTE_MIGRATION_ENV' &&
test -O '$REMOTE_MIGRATION_ENV' &&
test "\$(stat -c '%a' '$REMOTE_MIGRATION_ENV')" = 600 &&
set -a && . '.env' && . '$REMOTE_MIGRATION_ENV' && set +a &&
: "\${STEWARD_MIGRATION_DATABASE_URL:?missing STEWARD_MIGRATION_DATABASE_URL}" &&
: "\${STEWARD_OPERATOR_DATABASE_URL:?missing STEWARD_OPERATOR_DATABASE_URL}" &&
DATABASE_URL="\$STEWARD_MIGRATION_DATABASE_URL" $BUN run --cwd packages/api migrate &&
PGDATABASE="\$STEWARD_OPERATOR_DATABASE_URL" psql --no-psqlrc \
  -v steward_app_role="\${STEWARD_APP_DATABASE_ROLE:-steward_app}" \
  -v steward_migration_role="\${STEWARD_MIGRATION_DATABASE_ROLE:-steward_migrator}" \
  -v steward_bootstrap_role="\${STEWARD_BOOTSTRAP_DATABASE_ROLE:-steward_bootstrap_owner}" \
  -v steward_platform_role="\${STEWARD_PLATFORM_DATABASE_ROLE:-steward_platform}" \
  -f scripts/postgres/rls-bootstrap.sql &&
PGDATABASE="\$STEWARD_MIGRATION_DATABASE_URL" psql --no-psqlrc \
  -v steward_migration_role="\${STEWARD_MIGRATION_DATABASE_ROLE:-steward_migrator}" \
  -f scripts/postgres/rls-activate.sql
EOF
)
  if remote "$MIGRATION_COMMAND"; then
    ok "Core/plugin migrations, bootstrap reconciliation, and RLS activation complete"
  else
    fail "Release migration/bootstrap/activation failed, aborting"
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 4. Restart services
# ---------------------------------------------------------------------------
if $DO_RESTART; then
  log "Restarting steward + steward-proxy on $NODE_IP ..."
  remote "systemctl restart steward steward-proxy"
  # Give services a moment to start
  sleep 3
  ok "Services restarted"
fi

# ---------------------------------------------------------------------------
# 5. Health check
# ---------------------------------------------------------------------------
log "Health check ..."

HEALTH_RESPONSE=$(remote "curl -sf http://localhost:3200/health" 2>/dev/null || true)

if [[ -z "$HEALTH_RESPONSE" ]]; then
  fail "Health check FAILED on $NODE_IP (no response from :3200/health)"
  exit 1
fi

VERSION=$(echo "$HEALTH_RESPONSE" | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

ok "Health check passed on $NODE_IP (version: $VERSION)"
echo "$HEALTH_RESPONSE" | head -1

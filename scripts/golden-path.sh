#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${STEWARD_ENV_FILE:-$ROOT/deploy/enterprise-reference/.env}"
COMPOSE_FILE="$ROOT/deploy/enterprise-reference/docker-compose.yml"
CLI=(bun run "$ROOT/packages/cli/src/index.ts")

if [ ! -f "$ENV_FILE" ]; then
  "${CLI[@]}" init --env "$ENV_FILE" --force
fi

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" --profile enterprise-reference up -d
"${CLI[@]}" doctor --strict --env "$ENV_FILE"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

TENANT_ID="${STEWARD_GOLDEN_TENANT_ID:-golden-demo}"
TENANT_KEY="${STEWARD_GOLDEN_TENANT_KEY:-stw_tenant_golden_demo_change_me}"

"${CLI[@]}" tenant create --id "$TENANT_ID" --name "Golden Demo" --api-key "$TENANT_KEY" || true

cat <<EOF
Golden path baseline is running.

Next manual/API-auth steps depend on a real owner/admin session with recent MFA:
  - create an agent
  - add a secret and credential route
  - set a policy template
  - trigger an approval-gated action
  - run: steward audit bundle --from 1 --out bundle.json

The current API does not expose a non-interactive owner session bootstrap in this lane,
so this script stops honestly after init, compose, doctor, and platform tenant create.
EOF

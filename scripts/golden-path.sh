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

# The tenant API key becomes a usable machine credential. Require the operator
# to supply a real one via STEWARD_GOLDEN_TENANT_KEY; never embed a default. A
# baked-in default would be a shipped credential (the exact class of finding
# this script is meant to avoid).
TENANT_KEY="${STEWARD_GOLDEN_TENANT_KEY:-}"
if [ -z "$TENANT_KEY" ]; then
  echo "ERROR: STEWARD_GOLDEN_TENANT_KEY is required. Generate a unique key, e.g.:" >&2
  echo "  export STEWARD_GOLDEN_TENANT_KEY=\"stw_tenant_\$(openssl rand -hex 24)\"" >&2
  exit 1
fi
# Reject obvious placeholder / change-me sentinels so a copy-pasted demo value
# can never be promoted into a real credential.
case "$TENANT_KEY" in
  *change_me* | *change-me* | *changeme* | *golden_demo_change* | *placeholder* | *CHANGEME*)
    echo "ERROR: STEWARD_GOLDEN_TENANT_KEY looks like a placeholder ('$TENANT_KEY')." >&2
    echo "       Supply a real, unique key instead." >&2
    exit 1
    ;;
esac

# Create the tenant. Tolerate ONLY a verified already-exists (idempotent re-run);
# any other failure aborts. We capture output+status instead of `|| true`, which
# would have swallowed real failures (auth, network, validation) and then printed
# a false success.
set +e
CREATE_OUT="$("${CLI[@]}" tenant create --id "$TENANT_ID" --name "Golden Demo" --api-key "$TENANT_KEY" 2>&1)"
CREATE_STATUS=$?
set -e

if [ "$CREATE_STATUS" -ne 0 ]; then
  # The CLI surfaces the API error message; the tenants/platform routes return
  # "Tenant already exists" for a duplicate id (HTTP 409/400). Treat ONLY that
  # exact condition as an acceptable idempotent re-run.
  if printf '%s' "$CREATE_OUT" | grep -qi "Tenant already exists"; then
    echo "Tenant '$TENANT_ID' already exists; continuing (idempotent re-run)."
  else
    echo "ERROR: tenant create failed:" >&2
    printf '%s\n' "$CREATE_OUT" >&2
    exit "$CREATE_STATUS"
  fi
else
  printf '%s\n' "$CREATE_OUT"
fi

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

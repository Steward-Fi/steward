#!/bin/bash
set -euo pipefail

# Automatic staging database release. The application credential is resolved
# from the exact Railway service configuration so a duplicated GitHub secret
# cannot silently point migrations and readiness checks at another database.
: "${STEWARD_RELEASE_SOURCE_SHA:?missing STEWARD_RELEASE_SOURCE_SHA}"
: "${STEWARD_RELEASE_IMAGE_TAG:?missing STEWARD_RELEASE_IMAGE_TAG}"
: "${STEWARD_MIGRATION_DATABASE_URL:?missing STEWARD_MIGRATION_DATABASE_URL}"
: "${STEWARD_OPERATOR_DATABASE_URL:?missing STEWARD_OPERATOR_DATABASE_URL}"
: "${STEWARD_APP_DATABASE_ROLE:?missing STEWARD_APP_DATABASE_ROLE}"
: "${STEWARD_MIGRATION_DATABASE_ROLE:?missing STEWARD_MIGRATION_DATABASE_ROLE}"
: "${STEWARD_OPERATOR_DATABASE_ROLE:?missing STEWARD_OPERATOR_DATABASE_ROLE}"
: "${STEWARD_BOOTSTRAP_DATABASE_ROLE:?missing STEWARD_BOOTSTRAP_DATABASE_ROLE}"
: "${STEWARD_PLATFORM_DATABASE_ROLE:?missing STEWARD_PLATFORM_DATABASE_ROLE}"
: "${RAILWAY_TOKEN:?missing RAILWAY_TOKEN}"
: "${RAILWAY_PROJECT_ID:?missing RAILWAY_PROJECT_ID}"
: "${RAILWAY_SERVICE_ID:?missing RAILWAY_SERVICE_ID}"
: "${RAILWAY_ENV_ID:?missing RAILWAY_ENV_ID}"
: "${RAILWAY_HEALTH_URL:?missing RAILWAY_HEALTH_URL}"
: "${RAILWAY_DIRECT_HEALTH_URL:?missing RAILWAY_DIRECT_HEALTH_URL}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
RAILWAY_API="https://backboard.railway.com/graphql/v2"
COMPATIBILITY_TIMEOUT="${RAILWAY_COMPATIBILITY_TIMEOUT:-60}"
COMPATIBILITY_INTERVAL="${RAILWAY_COMPATIBILITY_INTERVAL:-5}"
RAILWAY_APP_DATABASE_URL=""
RAILWAY_DEPLOYMENT_ID=""
RAILWAY_DEPLOYMENT_STATUS=""
RAILWAY_DEPLOYMENT_IMAGE=""

redact_release_output() {
  sed -E \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]:]*:)[^@/[:space:]]+@#\1…REDACTED…@#g' \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://)[^/:@[:space:]]+@#\1…REDACTED…@#g' \
    -e 's#([?&](access_key|access_token|api_key|apikey|auth|authorization|client_secret|code|credential|key|password|passwd|pwd|secret|signature|sig|token)=)[^&#"'"'"'[:space:]]+#\1…REDACTED…#gI' \
    -e 's/(Bearer )[A-Za-z0-9._~+\/-]+/\1…REDACTED…/g' \
    -e 's/((DATABASE_URL|PGDATABASE|SECRET|PASSWORD|TOKEN|KEY)[A-Z_]*[[:space:]]*[:=][[:space:]]*)[^[:space:],}]+/\1…REDACTED…/gI'
}

run_redacted() {
  "$@" > >(redact_release_output) 2> >(redact_release_output >&2)
}

graphql_diagnostic() {
  local response="${1:-}"
  local diagnostic
  diagnostic=$(printf '%s' "$response" | jq -c \
    '[.errors[]? | {code: (.extensions.code // "UNKNOWN"), message: (.message // "request failed")}]' \
    2>/dev/null) || diagnostic=""
  if [[ -n "$diagnostic" && "$diagnostic" != "[]" ]]; then
    printf '%s' "$diagnostic" | redact_release_output
  else
    printf '%s' '<no safe GraphQL diagnostic available>'
  fi
}

read_railway_snapshot() {
  local include_variables="${1:-false}"
  local payload response diagnostic
  payload=$(jq -nc \
    --arg projectId "$RAILWAY_PROJECT_ID" \
    --arg environmentId "$RAILWAY_ENV_ID" \
    --arg serviceId "$RAILWAY_SERVICE_ID" \
    '{query: "query($projectId: String!, $environmentId: String!, $serviceId: String!) { variablesForServiceDeployment(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId) serviceInstance(environmentId: $environmentId, serviceId: $serviceId) { source { image } latestDeployment { id status } } }", variables: {projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId}}')

  if ! response=$(curl -sS --fail-with-body \
    --connect-timeout 5 --max-time 20 \
    -X POST "$RAILWAY_API" \
    -H "Authorization: Bearer ${RAILWAY_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$payload" 2>/dev/null); then
    echo "[release] Railway configuration query failed" >&2
    return 1
  fi
  if diagnostic=$(printf '%s' "$response" | jq -er '.errors | select(type == "array" and length > 0)' 2>/dev/null); then
    echo "[release] Railway configuration query returned: $(graphql_diagnostic "$response")" >&2
    return 1
  fi

  RAILWAY_DEPLOYMENT_ID=$(printf '%s' "$response" | jq -er \
    '.data.serviceInstance.latestDeployment.id | select(type == "string" and length > 0)' 2>/dev/null) || {
    echo "[release] Railway service has no current deployment identity" >&2
    return 1
  }
  RAILWAY_DEPLOYMENT_STATUS=$(printf '%s' "$response" | jq -er \
    '.data.serviceInstance.latestDeployment.status | select(type == "string" and length > 0)' 2>/dev/null) || {
    echo "[release] Railway service has no current deployment status" >&2
    return 1
  }
  RAILWAY_DEPLOYMENT_IMAGE=$(printf '%s' "$response" | jq -er \
    '.data.serviceInstance.source.image | select(type == "string" and length > 0)' 2>/dev/null) || {
    echo "[release] Railway service is not pinned to an image source" >&2
    return 1
  }
  if [[ "$include_variables" == "true" ]]; then
    RAILWAY_APP_DATABASE_URL=$(printf '%s' "$response" | jq -er \
      '.data.variablesForServiceDeployment.DATABASE_URL | select(type == "string" and length > 0)' \
      2>/dev/null) || {
      echo "[release] Railway service has no rendered DATABASE_URL" >&2
      return 1
    }
  fi
  unset response payload diagnostic
}

assert_database_role() {
  local label="$1"
  local database_url="$2"
  local expected_role="$3"
  local output
  if ! output=$(PGDATABASE="$database_url" psql --no-psqlrc -X -A -t \
    --set ON_ERROR_STOP=1 -c 'SELECT current_user' 2>&1); then
    printf '%s\n' "$output" | redact_release_output >&2
    echo "[release] could not verify the ${label} database identity" >&2
    return 1
  fi
  output="${output//$'\r'/}"
  output="${output//$'\n'/}"
  if [[ "$output" != "$expected_role" ]]; then
    echo "[release] ${label} database identity does not match its configured role" >&2
    return 1
  fi
}

database_fingerprint() {
  local label="$1"
  local database_url="$2"
  local output
  # Require PostgreSQL's stable cluster identifier. A weaker host/OID fallback
  # can collide behind a database proxy, so lack of EXECUTE permission fails
  # closed before any migration. The Railway-rendered DATABASE_URL remains
  # authoritative; this non-secret fingerprint proves the privileged
  # credentials reach that same cluster/database without comparing URL text.
  local query="
    SELECT (SELECT system_identifier::text FROM pg_control_system())
      || ':' || current_database()
      || ':' || (SELECT oid::text FROM pg_database WHERE datname = current_database())"
  if ! output=$(PGDATABASE="$database_url" psql --no-psqlrc -X -A -t \
    --set ON_ERROR_STOP=1 -c "$query" 2>&1); then
    printf '%s\n' "$output" | redact_release_output >&2
    echo "[release] could not derive the ${label} database fingerprint" >&2
    return 1
  fi
  output="${output//$'\r'/}"
  output="${output//$'\n'/}"
  if [[ -z "$output" || "$output" == *"::"* ]]; then
    echo "[release] ${label} database fingerprint was incomplete" >&2
    return 1
  fi
  printf '%s' "$output"
}

verify_compatibility_probe() {
  local origin="$1"
  local path="$2"
  local label="$3"
  local started=$SECONDS result="000 " code="000" remote_ip="" elapsed=0
  while [[ $elapsed -lt $COMPATIBILITY_TIMEOUT ]]; do
    result=$(curl -sS --connect-timeout 5 --max-time 10 \
      -H 'Cache-Control: no-cache, no-store' \
      -o /dev/null -w '%{http_code} %{remote_ip}' "${origin}${path}" 2>/dev/null) || result="000 "
    read -r code remote_ip <<< "$result"
    if [[ "$code" == "200" ]] &&
       node "$SCRIPT_DIR/validate-public-origin.mjs" --ip "$remote_ip" >/dev/null 2>&1; then
      echo "[release] Existing-image ${label} passed."
      return 0
    fi
    elapsed=$((SECONDS - started))
    if [[ $elapsed -lt $COMPATIBILITY_TIMEOUT ]]; then
      sleep "$COMPATIBILITY_INTERVAL"
    fi
    elapsed=$((SECONDS - started))
  done
  echo "[release] existing-image ${label} failed after the schema release" >&2
  return 1
}

assert_snapshot_unchanged() {
  local expected_id="$1"
  local expected_image="$2"
  read_railway_snapshot false
  if [[ "$RAILWAY_DEPLOYMENT_ID" != "$expected_id" ||
        "$RAILWAY_DEPLOYMENT_IMAGE" != "$expected_image" ||
        "$RAILWAY_DEPLOYMENT_STATUS" != "SUCCESS" ]]; then
    echo "[release] Railway deployment changed during the database release" >&2
    return 1
  fi
}

if [[ ! "$STEWARD_RELEASE_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "[release] source SHA must be a full lowercase Git commit" >&2
  exit 1
fi
if [[ "$STEWARD_RELEASE_IMAGE_TAG" != "sha-${STEWARD_RELEASE_SOURCE_SHA}" ]]; then
  echo "[release] image tag is not bound to the exact source SHA" >&2
  exit 1
fi
if [[ "$(git rev-parse HEAD)" != "$STEWARD_RELEASE_SOURCE_SHA" ]]; then
  echo "[release] checkout does not match the release source SHA" >&2
  exit 1
fi
if ! git diff --quiet -- . || ! git diff --cached --quiet -- .; then
  echo "[release] tracked checkout differs from the exact release commit" >&2
  exit 1
fi
if [[ ! "$COMPATIBILITY_TIMEOUT" =~ ^[1-9][0-9]*$ ||
      ! "$COMPATIBILITY_INTERVAL" =~ ^[1-9][0-9]*$ ]]; then
  echo "[release] compatibility timeouts must be positive integers" >&2
  exit 1
fi

roles=(
  "$STEWARD_APP_DATABASE_ROLE"
  "$STEWARD_MIGRATION_DATABASE_ROLE"
  "$STEWARD_OPERATOR_DATABASE_ROLE"
  "$STEWARD_BOOTSTRAP_DATABASE_ROLE"
  "$STEWARD_PLATFORM_DATABASE_ROLE"
)
for role in "${roles[@]}"; do
  if [[ ! "$role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
    echo "[release] database roles must be lowercase PostgreSQL identifiers" >&2
    exit 1
  fi
done
for ((left = 0; left < ${#roles[@]}; left++)); do
  for ((right = left + 1; right < ${#roles[@]}; right++)); do
    if [[ "${roles[$left]}" == "${roles[$right]}" ]]; then
      echo "[release] app, migration, operator, bootstrap, and platform roles must be distinct" >&2
      exit 1
    fi
  done
done
if [[ "$STEWARD_MIGRATION_DATABASE_URL" == "$STEWARD_OPERATOR_DATABASE_URL" ]]; then
  echo "[release] migration and operator database credentials must be distinct" >&2
  exit 1
fi

RAILWAY_HEALTH_URL=$(node "$SCRIPT_DIR/validate-public-origin.mjs" \
  --resolve-origin "$RAILWAY_HEALTH_URL") || {
  echo "[release] public health URL must be a credential-free public HTTPS root origin" >&2
  exit 1
}
RAILWAY_DIRECT_HEALTH_URL=$(node "$SCRIPT_DIR/validate-public-origin.mjs" \
  --resolve-origin "$RAILWAY_DIRECT_HEALTH_URL") || {
  echo "[release] direct health URL must be a credential-free public HTTPS root origin" >&2
  exit 1
}
if [[ "$RAILWAY_DIRECT_HEALTH_URL" == "$RAILWAY_HEALTH_URL" ]]; then
  echo "[release] public and direct health origins must be distinct" >&2
  exit 1
fi

read_railway_snapshot true
if [[ "$RAILWAY_DEPLOYMENT_STATUS" != "SUCCESS" ]]; then
  echo "[release] current Railway deployment is not successful" >&2
  exit 1
fi
baseline_deployment_id="$RAILWAY_DEPLOYMENT_ID"
baseline_deployment_image="$RAILWAY_DEPLOYMENT_IMAGE"

assert_database_role "migration" "$STEWARD_MIGRATION_DATABASE_URL" \
  "$STEWARD_MIGRATION_DATABASE_ROLE"
assert_database_role "operator" "$STEWARD_OPERATOR_DATABASE_URL" \
  "$STEWARD_OPERATOR_DATABASE_ROLE"
assert_database_role "Railway application" "$RAILWAY_APP_DATABASE_URL" \
  "$STEWARD_APP_DATABASE_ROLE"

app_fingerprint=$(database_fingerprint "Railway application" "$RAILWAY_APP_DATABASE_URL")
migration_fingerprint=$(database_fingerprint "migration" "$STEWARD_MIGRATION_DATABASE_URL")
operator_fingerprint=$(database_fingerprint "operator" "$STEWARD_OPERATOR_DATABASE_URL")
if ! [[ "$app_fingerprint" == "$migration_fingerprint" &&
        "$app_fingerprint" == "$operator_fingerprint" ]]; then
  echo "[release] database credentials do not target the Railway service database" >&2
  exit 1
fi
unset app_fingerprint migration_fingerprint operator_fingerprint

echo "[release] Applying core and enabled-plugin migrations for ${STEWARD_RELEASE_IMAGE_TAG}."
DATABASE_URL="$STEWARD_MIGRATION_DATABASE_URL" \
  run_redacted bun run --cwd packages/api migrate

echo "[release] Reconciling bootstrap ownership and grants."
PGDATABASE="$STEWARD_OPERATOR_DATABASE_URL" run_redacted psql --no-psqlrc --set ON_ERROR_STOP=1 \
  -v steward_app_role="$STEWARD_APP_DATABASE_ROLE" \
  -v steward_migration_role="$STEWARD_MIGRATION_DATABASE_ROLE" \
  -v steward_bootstrap_role="$STEWARD_BOOTSTRAP_DATABASE_ROLE" \
  -v steward_platform_role="$STEWARD_PLATFORM_DATABASE_ROLE" \
  -f scripts/postgres/rls-bootstrap.sql

echo "[release] Activating and validating the exact forced-RLS inventory."
PGDATABASE="$STEWARD_MIGRATION_DATABASE_URL" run_redacted psql --no-psqlrc --set ON_ERROR_STOP=1 \
  -v steward_app_role="$STEWARD_APP_DATABASE_ROLE" \
  -v steward_migration_role="$STEWARD_MIGRATION_DATABASE_ROLE" \
  -v steward_bootstrap_role="$STEWARD_BOOTSTRAP_DATABASE_ROLE" \
  -v steward_platform_role="$STEWARD_PLATFORM_DATABASE_ROLE" \
  -f scripts/postgres/rls-activate.sql

echo "[release] Verifying journals and RLS through Railway's restricted API identity."
DATABASE_URL="$RAILWAY_APP_DATABASE_URL" \
  run_redacted bun run scripts/verify-database-release.ts

# The schema is intentionally released before image cutover. Prove the exact
# existing deployment remains healthy and ready on that schema; a breaking
# migration stops the workflow before it can replace the image.
assert_snapshot_unchanged "$baseline_deployment_id" "$baseline_deployment_image"
verify_compatibility_probe "$RAILWAY_HEALTH_URL" "/health" "public health"
verify_compatibility_probe "$RAILWAY_HEALTH_URL" "/ready" "public readiness"
verify_compatibility_probe "$RAILWAY_DIRECT_HEALTH_URL" "/health" "direct health"
verify_compatibility_probe "$RAILWAY_DIRECT_HEALTH_URL" "/ready" "direct readiness"
assert_snapshot_unchanged "$baseline_deployment_id" "$baseline_deployment_image"
echo "[release] Existing Railway image is compatible with the released schema."

unset RAILWAY_APP_DATABASE_URL STEWARD_MIGRATION_DATABASE_URL STEWARD_OPERATOR_DATABASE_URL

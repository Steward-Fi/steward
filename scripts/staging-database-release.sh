#!/bin/bash
set -euo pipefail

# Automatic staging database release. The three credentials are repository or
# organization Actions secrets, not Railway service variables, so the API can
# never inherit schema/operator authority.
: "${STEWARD_RELEASE_SOURCE_SHA:?missing STEWARD_RELEASE_SOURCE_SHA}"
: "${STEWARD_RELEASE_IMAGE_TAG:?missing STEWARD_RELEASE_IMAGE_TAG}"
: "${STEWARD_MIGRATION_DATABASE_URL:?missing STEWARD_MIGRATION_DATABASE_URL}"
: "${STEWARD_OPERATOR_DATABASE_URL:?missing STEWARD_OPERATOR_DATABASE_URL}"
: "${STEWARD_APP_DATABASE_URL:?missing STEWARD_APP_DATABASE_URL}"
: "${STEWARD_APP_DATABASE_ROLE:?missing STEWARD_APP_DATABASE_ROLE}"
: "${STEWARD_MIGRATION_DATABASE_ROLE:?missing STEWARD_MIGRATION_DATABASE_ROLE}"
: "${STEWARD_OPERATOR_DATABASE_ROLE:?missing STEWARD_OPERATOR_DATABASE_ROLE}"
: "${STEWARD_BOOTSTRAP_DATABASE_ROLE:?missing STEWARD_BOOTSTRAP_DATABASE_ROLE}"
: "${STEWARD_PLATFORM_DATABASE_ROLE:?missing STEWARD_PLATFORM_DATABASE_ROLE}"

# Release tools and database drivers can include connection strings in failure
# diagnostics. Keep useful context while stripping credentials before any
# command output reaches Actions logs.
redact_release_output() {
  sed -E \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]:]*:)[^@/[:space:]]+@#\1…REDACTED…@#g' \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://)[^/:@[:space:]]+@#\1…REDACTED…@#g' \
    -e 's/((DATABASE_URL|PGDATABASE|SECRET|PASSWORD|TOKEN|KEY)[A-Z_]*[[:space:]]*[:=][[:space:]]*)[^[:space:],}]+/\1…REDACTED…/gI'
}

run_redacted() {
  "$@" > >(redact_release_output) 2> >(redact_release_output >&2)
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

if [[ ! "$STEWARD_RELEASE_SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "[release] source SHA must be a full lowercase Git commit" >&2
  exit 1
fi

if [[ "$STEWARD_RELEASE_IMAGE_TAG" != "sha-${STEWARD_RELEASE_SOURCE_SHA}" ]]; then
  echo "[release] image tag is not bound to the exact source SHA" >&2
  exit 1
fi

ACTUAL_SHA=$(git rev-parse HEAD)
if [[ "$ACTUAL_SHA" != "$STEWARD_RELEASE_SOURCE_SHA" ]]; then
  echo "[release] checkout does not match the release source SHA" >&2
  exit 1
fi

if ! git diff --quiet -- . || ! git diff --cached --quiet -- .; then
  echo "[release] tracked checkout differs from the exact release commit" >&2
  exit 1
fi

for role in \
  "$STEWARD_APP_DATABASE_ROLE" \
  "$STEWARD_MIGRATION_DATABASE_ROLE" \
  "$STEWARD_OPERATOR_DATABASE_ROLE" \
  "$STEWARD_BOOTSTRAP_DATABASE_ROLE" \
  "$STEWARD_PLATFORM_DATABASE_ROLE"; do
  if [[ ! "$role" =~ ^[a-z_][a-z0-9_]{0,62}$ ]]; then
    echo "[release] database roles must be lowercase PostgreSQL identifiers" >&2
    exit 1
  fi
done

roles=(
  "$STEWARD_APP_DATABASE_ROLE"
  "$STEWARD_MIGRATION_DATABASE_ROLE"
  "$STEWARD_OPERATOR_DATABASE_ROLE"
  "$STEWARD_BOOTSTRAP_DATABASE_ROLE"
  "$STEWARD_PLATFORM_DATABASE_ROLE"
)
for ((left = 0; left < ${#roles[@]}; left++)); do
  for ((right = left + 1; right < ${#roles[@]}; right++)); do
    if [[ "${roles[$left]}" == "${roles[$right]}" ]]; then
      echo "[release] app, migration, operator, bootstrap, and platform roles must be distinct" >&2
      exit 1
    fi
  done
done

if [[ "$STEWARD_MIGRATION_DATABASE_URL" == "$STEWARD_OPERATOR_DATABASE_URL" ||
      "$STEWARD_MIGRATION_DATABASE_URL" == "$STEWARD_APP_DATABASE_URL" ||
      "$STEWARD_OPERATOR_DATABASE_URL" == "$STEWARD_APP_DATABASE_URL" ]]; then
  echo "[release] migration, operator, and app database identities must be distinct" >&2
  exit 1
fi

# URL text inequality is not an authority boundary: aliases and query-string
# changes can still connect as the same login. Prove each executable credential
# reaches the configured role before the first schema mutation.
assert_database_role "migration" "$STEWARD_MIGRATION_DATABASE_URL" \
  "$STEWARD_MIGRATION_DATABASE_ROLE"
assert_database_role "operator" "$STEWARD_OPERATOR_DATABASE_URL" \
  "$STEWARD_OPERATOR_DATABASE_ROLE"
assert_database_role "application" "$STEWARD_APP_DATABASE_URL" \
  "$STEWARD_APP_DATABASE_ROLE"

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

echo "[release] Verifying journals and RLS through the restricted API identity."
DATABASE_URL="$STEWARD_APP_DATABASE_URL" \
  run_redacted bun run scripts/verify-database-release.ts

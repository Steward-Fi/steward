#!/bin/sh
# Contract tests for the dstack packaging (deploy/dstack/).
#
# Proves, without any TEE hardware:
#   1. docker-compose.dstack.yml is valid compose and renders with sealed-env vars.
#   2. It FAILS CLOSED when required secrets are absent (the `${VAR:?}` contract).
#   3. Production compose hardcodes STEWARD_ATTESTATION_PROVIDER=dstack-tdx and
#      never references noop-dev.
#   4. The dev override is required to get noop-dev, and is loudly labeled.
#   5. All service images are pinned by digest (measurement integrity).
#   6. app-compose.json is current with docker-compose.dstack.yml (compose_hash
#      pinning would silently drift otherwise).
set -eu

if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() { docker-compose "$@"; }
else
  echo "docker compose or docker-compose is required" >&2
  exit 1
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dstack_dir="$repo_root/deploy/dstack"
base_compose="$dstack_dir/docker-compose.dstack.yml"
dev_compose="$dstack_dir/docker-compose.dstack.dev.yml"

rendered=$(mktemp)
rendered_dev=$(mktemp)
fail_log=$(mktemp)
cleanup() { rm -f "$rendered" "$rendered_dev" "$fail_log"; }
trap cleanup EXIT HUP INT TERM

# Dummy sealed-env stand-ins. CI-only; production values arrive via dstack KMS.
sentinel="dstack-contract-sentinel-value"
export POSTGRES_PASSWORD="$sentinel-pg"
export STEWARD_MASTER_PASSWORD="$sentinel-master"
export STEWARD_JWT_SECRET="dstack-contract-jwt-secret-32-chars-min"
export STEWARD_EXECUTION_AUTH_SECRET="v1:dstack-contract-execution-auth-secret-32-chars"
export STEWARD_KDF_SALT="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
export STEWARD_AUDIT_HMAC_KEY="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
export STEWARD_PROXY_REQUEST_SIGNING_SECRET="dstack-contract-proxy-signing-secret-32-chars"
export COMPOSE_PROJECT_NAME="steward-dstack-contract-$$"

echo "compose-dstack: base config renders with sealed-env vars present"
compose -f "$base_compose" config >"$rendered"

echo "compose-dstack: fails closed when a required secret is missing"
if (
  unset STEWARD_MASTER_PASSWORD
  compose -f "$base_compose" config >/dev/null 2>"$fail_log"
); then
  echo "config rendered without STEWARD_MASTER_PASSWORD; required-secret contract broken" >&2
  exit 1
fi
if ! grep -Fq "must arrive via dstack sealed env" "$fail_log"; then
  echo "missing-secret failure had an unexpected cause:" >&2
  cat "$fail_log" >&2
  exit 1
fi

echo "compose-dstack: production posture is dstack-tdx, no noop anywhere"
if ! grep -Fq "STEWARD_ATTESTATION_PROVIDER: dstack-tdx" "$rendered"; then
  echo "rendered production config does not pin STEWARD_ATTESTATION_PROVIDER=dstack-tdx" >&2
  exit 1
fi
if grep -Fq "noop-dev" "$rendered"; then
  echo "rendered production config references noop-dev" >&2
  exit 1
fi
if grep -Fq "STEWARD_ATTESTATION_NOOP_ALLOW" "$rendered"; then
  echo "rendered production config references STEWARD_ATTESTATION_NOOP_ALLOW" >&2
  exit 1
fi

echo "compose-dstack: dev override opts into noop-dev and drops the TEE socket"
compose -f "$base_compose" -f "$dev_compose" config >"$rendered_dev"
if ! grep -Fq "STEWARD_ATTESTATION_PROVIDER: noop-dev" "$rendered_dev"; then
  echo "dev override did not switch the provider to noop-dev" >&2
  exit 1
fi
if grep -Eq "source: /var/run/dstack.sock" "$rendered_dev"; then
  echo "dev override still bind-mounts the dstack guest agent socket" >&2
  exit 1
fi
if ! grep -Eq "source: /var/run/dstack.sock" "$rendered"; then
  echo "production config lost the dstack guest agent socket bind mount" >&2
  exit 1
fi

echo "compose-dstack: every image is pinned by digest"
images=$(grep -E '^\s+image:' "$base_compose" | sed 's/^ *image: *//')
for image in $images; do
  case "$image" in
    *@sha256:*) ;;
    *)
      echo "image not pinned by digest: $image" >&2
      exit 1
      ;;
  esac
done

echo "compose-dstack: app-compose.json manifest is current"
(cd "$repo_root" && bun deploy/dstack/make-app-compose.ts --check)

echo "compose-dstack: no sentinel secret value leaks into committed files"
if grep -RFq "$sentinel" "$dstack_dir"; then
  echo "sentinel value found inside deploy/dstack — committed files must never carry secret values" >&2
  exit 1
fi

echo "compose-dstack: ok"

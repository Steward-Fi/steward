#!/bin/sh
set -eu

if docker compose version >/dev/null 2>&1; then
  compose() {
    docker compose "$@"
  }
elif command -v docker-compose >/dev/null 2>&1; then
  compose() {
    docker-compose "$@"
  }
else
  echo "docker compose or docker-compose is required" >&2
  exit 1
fi

export POSTGRES_DB=steward_test
export POSTGRES_USER=steward
export POSTGRES_PASSWORD=steward_ci
export STEWARD_MASTER_PASSWORD=compose-contract-master-password
export STEWARD_JWT_SECRET=compose-contract-jwt-secret-32-chars
export STEWARD_EMAIL_CODE_SECRET=compose-contract-email-code-secret-32-chars
export STEWARD_EXECUTION_AUTH_SECRET=v1:compose-contract-execution-auth-secret-32-chars
export STEWARD_AUDIT_HMAC_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export STEWARD_KDF_SALT=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
# Compose requires an API machine request-signing root. This is a throwaway
# contract-test value only; production must supply its own.
export STEWARD_REQUEST_SIGNING_SECRET=compose-contract-api-signing-secret-32-chars
# Compose requires a proxy request-signing root for the API+proxy pair. This is
# a throwaway value for the contract test only; production must supply its own.
export STEWARD_PROXY_REQUEST_SIGNING_SECRET=compose-contract-proxy-signing-secret-32-chars
export STEWARD_REQUEST_SIGNING_SECRETS=compose-contract-api-signing-secret-32-chars
# Keep one-off contract containers and resources isolated from any local stack.
export COMPOSE_PROJECT_NAME=steward-compose-monero-contract-$$

sentinel_password=compose-monero-contract-sentinel
rendered_config=$(mktemp)
sidecar_config=$(mktemp)
unset_log=$(mktemp)
empty_log=$(mktemp)
pull_log=$(mktemp)
cleanup() {
  MONERO_WALLET_RPC_PASSWORD=cleanup compose --profile monero down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -f "$rendered_config" "$sidecar_config" "$unset_log" "$empty_log" "$pull_log"
}
trap cleanup EXIT HUP INT TERM

pull_monero_image() {
  attempt=1
  while [ "$attempt" -le 3 ]; do
    if compose --profile monero pull monero-wallet-rpc >"$pull_log" 2>&1; then
      return 0
    fi
    if [ "$attempt" -lt 3 ]; then
      echo "compose-monero: image pull attempt $attempt failed; retrying" >&2
      sleep $((attempt * 2))
    fi
    attempt=$((attempt + 1))
  done
  echo "compose-monero: failed to pull pinned sidecar image after 3 attempts" >&2
  cat "$pull_log" >&2
  return 1
}

echo "compose-monero: base config accepts unset MONERO_WALLET_RPC_PASSWORD"
(
  unset MONERO_WALLET_RPC_PASSWORD
  unset COMPOSE_PROFILES
  compose config >/dev/null
)

echo "compose-monero: profiled sidecar fails closed with unset MONERO_WALLET_RPC_PASSWORD"
pull_monero_image
if (
  unset MONERO_WALLET_RPC_PASSWORD
  export COMPOSE_PROFILES=monero
  compose run --rm --no-deps monero-wallet-rpc >/dev/null 2>"$unset_log"
); then
  echo "monero-wallet-rpc started with unset MONERO_WALLET_RPC_PASSWORD" >&2
  exit 1
fi
if ! grep -F 'MONERO_WALLET_RPC_PASSWORD' "$unset_log" >/dev/null; then
  echo "unset password failed for an unexpected reason" >&2
  cat "$unset_log" >&2
  exit 1
fi

echo "compose-monero: profiled sidecar fails closed with empty MONERO_WALLET_RPC_PASSWORD"
if (
  MONERO_WALLET_RPC_PASSWORD=
  export MONERO_WALLET_RPC_PASSWORD COMPOSE_PROFILES=monero
  compose run --rm --no-deps monero-wallet-rpc >/dev/null 2>"$empty_log"
); then
  echo "monero-wallet-rpc started with empty MONERO_WALLET_RPC_PASSWORD" >&2
  exit 1
fi
if ! grep -F 'MONERO_WALLET_RPC_PASSWORD must be set and non-empty' "$empty_log" >/dev/null; then
  echo "empty password failed for an unexpected reason" >&2
  cat "$empty_log" >&2
  exit 1
fi

echo "compose-monero: secret reaches one-off sidecar container"
(
  MONERO_WALLET_RPC_PASSWORD=$sentinel_password
  EXPECTED_MONERO_SECRET=$sentinel_password
  export MONERO_WALLET_RPC_PASSWORD EXPECTED_MONERO_SECRET COMPOSE_PROFILES=monero
  compose run --rm --no-deps \
    --entrypoint /bin/sh \
    -e EXPECTED_MONERO_SECRET \
    monero-wallet-rpc \
    -ec 'test -s /run/secrets/monero_wallet_rpc_password && value=$(cat /run/secrets/monero_wallet_rpc_password) && test "$value" = "$EXPECTED_MONERO_SECRET"' \
    >/dev/null
)

echo "compose-monero: rendered sidecar config does not contain the password"
(
  MONERO_WALLET_RPC_PASSWORD=$sentinel_password
  export MONERO_WALLET_RPC_PASSWORD COMPOSE_PROFILES=monero
  compose config >"$rendered_config"
)
sed -n '/^  monero-wallet-rpc:/,/^  [A-Za-z0-9_-][A-Za-z0-9_-]*:/p' "$rendered_config" >"$sidecar_config"
if grep -F "$sentinel_password" "$sidecar_config" >/dev/null; then
  echo "rendered monero-wallet-rpc config contains the password" >&2
  exit 1
fi

echo "compose-monero: ok"

#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Steward proxy post-deploy smoke
#
# Verifies a deployed proxy gateway is up and enforcing auth, from the OUTSIDE
# via HTTP status codes.
#
#   1. GET /health            -> 200  (service is up; unauthenticated)
#   2. unauthenticated proxy  -> 401  (auth guard is live; no Bearer token)
#   3. (--signed) a signed,   -> NOT 401/403  (proves a valid signed request
#      idempotency-keyed          reaches route matching rather than being
#      request                    rejected at the auth/signature layer)
#
# Usage:
#   smoke-proxy.sh <PROXY_URL> <TOKEN>
#   smoke-proxy.sh --signed <PROXY_URL> <TOKEN> <TENANT_ID> <AGENT_ID>
#
#     PROXY_URL   e.g. https://steward-proxy.up.railway.app  (no trailing slash)
#     TOKEN       an api:proxy-scoped agent JWT
#     TENANT_ID   (--signed only) tenant id bound into the signature
#     AGENT_ID    (--signed only) agent id bound into the signature
#
# For --signed you must also export the proxy's request-signing secret:
#     STEWARD_PROXY_REQUEST_SIGNING_SECRET=<secret> smoke-proxy.sh --signed ...
#
# The signed check targets the openai alias path /openai/v1/chat/completions
# with a POST + Idempotency-Key + X-Steward-Signature. It does NOT need a real
# credential route to pass: a 401/403 means the signature/auth layer rejected it
# (FAIL); anything else (200/404/5xx from route matching downstream) means the
# request passed auth and is being processed (PASS).
#
# Exit code: 0 = all checks pass; non-zero on any failure.
# Deps: curl, jq, openssl.
# =============================================================================

GREEN='\033[32m'; RED='\033[31m'; CYAN='\033[36m'; RESET='\033[0m'
log()  { echo -e "${CYAN}[smoke-proxy]${RESET} $*"; }
ok()   { echo -e "${GREEN}[smoke-proxy]${RESET} $*"; }
err()  { echo -e "${RED}[smoke-proxy]${RESET} $*" >&2; }

usage() {
  echo "Usage: $0 <PROXY_URL> <TOKEN>" >&2
  echo "       $0 --signed <PROXY_URL> <TOKEN> <TENANT_ID> <AGENT_ID>" >&2
  echo "       (--signed also needs STEWARD_PROXY_REQUEST_SIGNING_SECRET in env)" >&2
  exit 2
}

# --- deps --------------------------------------------------------------------
for dep in curl jq openssl; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    err "missing required dependency: $dep"
    exit 2
  fi
done

# --- args --------------------------------------------------------------------
SIGNED="no"
if [ "${1:-}" = "--signed" ]; then
  SIGNED="yes"
  shift
fi

PROXY_URL="${1:-}"
TOKEN="${2:-}"
TENANT_ID="${3:-}"
AGENT_ID="${4:-}"

[ -n "$PROXY_URL" ] || usage
[ -n "$TOKEN" ] || usage
PROXY_URL="${PROXY_URL%/}"

if [ "$SIGNED" = "yes" ]; then
  [ -n "$TENANT_ID" ] || { err "--signed requires TENANT_ID"; usage; }
  [ -n "$AGENT_ID" ] || { err "--signed requires AGENT_ID"; usage; }
  [ -n "${STEWARD_PROXY_REQUEST_SIGNING_SECRET:-}" ] || {
    err "--signed requires STEWARD_PROXY_REQUEST_SIGNING_SECRET in the environment"
    usage
  }
fi

SIGNED_PATH="/openai/v1/chat/completions"

PASS=0
FAIL=0
declare -a MATRIX=()

record() { # record <name> <PASS|FAIL> <detail>
  MATRIX+=("$1|$2|$3")
  if [ "$2" = "PASS" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
}

# sha256 hex of a string (no trailing newline)
sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 -hex | awk '{print $NF}'
}

# hmac-sha256 hex of <message> keyed by <secret>
hmac_hex() {
  local message="$1" secret="$2"
  printf '%s' "$message" | openssl dgst -sha256 -hmac "$secret" -hex | awk '{print $NF}'
}

log "target: ${PROXY_URL}  (signed: ${SIGNED})"

# --- check 1: /health -> 200 -------------------------------------------------
HEALTH_CODE="$(curl --silent --show-error --max-time 15 --output /dev/null \
  --write-out '%{http_code}' "${PROXY_URL}/health" 2>/dev/null || echo "000")"
if [ "$HEALTH_CODE" = "200" ]; then
  record "health" "PASS" "GET /health -> 200"
else
  record "health" "FAIL" "GET /health -> ${HEALTH_CODE} (want 200)"
fi

# --- check 2: unauthenticated proxy request -> 401 ---------------------------
UNAUTH_CODE="$(curl --silent --show-error --max-time 15 --output /dev/null \
  --write-out '%{http_code}' "${PROXY_URL}${SIGNED_PATH}" 2>/dev/null || echo "000")"
if [ "$UNAUTH_CODE" = "401" ]; then
  record "unauth-guard" "PASS" "GET ${SIGNED_PATH} (no token) -> 401"
else
  record "unauth-guard" "FAIL" "GET ${SIGNED_PATH} (no token) -> ${UNAUTH_CODE} (want 401)"
fi

# --- check 3 (optional): a valid signed request passes the auth layer --------
if [ "$SIGNED" = "yes" ]; then
  BODY='{"model":"gpt-4o-mini","messages":[{"role":"user","content":"smoke"}]}'
  TS="$(date +%s)"
  IDEMPOTENCY_KEY="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)"
  BODY_HASH="$(sha256_hex "$BODY")"

  # Canonical form MUST match packages/proxy/src/middleware/auth.ts:
  #   version, METHOD, path+search, tenantId, agentId, timestamp, expiresAt,
  #   idempotencyKey, sha256(body)  (joined by \n). expiresAt empty here.
  CANONICAL="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
    "steward-proxy-request-signature-v1" \
    "POST" \
    "${SIGNED_PATH}" \
    "$TENANT_ID" \
    "$AGENT_ID" \
    "$TS" \
    "" \
    "$IDEMPOTENCY_KEY" \
    "$BODY_HASH")"

  SIG_HEX="$(hmac_hex "$CANONICAL" "$STEWARD_PROXY_REQUEST_SIGNING_SECRET")"

  SIGNED_CODE="$(curl --silent --show-error --max-time 15 --output /dev/null \
    --write-out '%{http_code}' \
    -X POST \
    -H "authorization: Bearer ${TOKEN}" \
    -H "content-type: application/json" \
    -H "idempotency-key: ${IDEMPOTENCY_KEY}" \
    -H "x-steward-request-timestamp: ${TS}" \
    -H "x-steward-signature: v1=${SIG_HEX}" \
    --data "$BODY" \
    "${PROXY_URL}${SIGNED_PATH}" 2>/dev/null || echo "000")"

  if [ "$SIGNED_CODE" = "401" ] || [ "$SIGNED_CODE" = "403" ]; then
    record "signed-request" "FAIL" "POST ${SIGNED_PATH} (signed) -> ${SIGNED_CODE} (rejected at auth/signature layer)"
  elif [ "$SIGNED_CODE" = "000" ]; then
    record "signed-request" "FAIL" "POST ${SIGNED_PATH} (signed) -> ${SIGNED_CODE} (could not reach service)"
  else
    record "signed-request" "PASS" "POST ${SIGNED_PATH} (signed) -> ${SIGNED_CODE} (passed auth; processed downstream)"
  fi
fi

# --- matrix ------------------------------------------------------------------
echo
echo "  CHECK            RESULT  DETAIL"
echo "  ---------------  ------  --------------------------------------------"
for row in "${MATRIX[@]}"; do
  IFS='|' read -r name result detail <<<"$row"
  if [ "$result" = "PASS" ]; then
    printf "  %-15s  ${GREEN}%-6s${RESET}  %s\n" "$name" "$result" "$detail"
  else
    printf "  %-15s  ${RED}%-6s${RESET}  %s\n" "$name" "$result" "$detail"
  fi
done
echo

if [ "$FAIL" -eq 0 ]; then
  ok "smoke passed: ${PASS}/${PASS} checks ok"
  exit 0
fi

err "smoke FAILED: ${FAIL} check(s) failed, ${PASS} passed"
exit 1

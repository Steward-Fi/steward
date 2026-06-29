#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Steward post-deploy smoke
#
# Verifies a deployed Steward instance is up and is serving the EXPECTED feature
# profile (lean = core only, full = core + trading), purely from the OUTSIDE via
# HTTP status codes. No auth required: the test distinguishes a MOUNTED route
# (returns 200/401/403/4xx — anything but 404) from an UNMOUNTED route (404).
#
# Usage:
#   smoke-steward.sh <BASE_URL> [mode]
#     BASE_URL   e.g. https://steward-lean.up.railway.app  (no trailing slash)
#     mode       lean | full   (optional; default: auto-detect from the trading
#                               route's presence, reported as detected=<mode>)
#
# Exit code: 0 = all checks pass (and, if mode was given, profile matches);
#            non-zero on any failed check or profile mismatch.
#
# Deps: curl, jq.
# =============================================================================

GREEN='\033[32m'; RED='\033[31m'; CYAN='\033[36m'; RESET='\033[0m'
log()  { echo -e "${CYAN}[smoke]${RESET} $*"; }
ok()   { echo -e "${GREEN}[smoke]${RESET} $*"; }
err()  { echo -e "${RED}[smoke]${RESET} $*" >&2; }

usage() {
  echo "Usage: $0 <BASE_URL> [lean|full]" >&2
  exit 2
}

# ── deps ─────────────────────────────────────────────────────────────────────
for dep in curl jq; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    err "missing required dependency: $dep"
    exit 2
  fi
done

# ── args ─────────────────────────────────────────────────────────────────────
BASE_URL="${1:-}"
MODE="${2:-auto}"
[ -n "$BASE_URL" ] || usage
# strip a single trailing slash so "$BASE_URL/path" is well-formed
BASE_URL="${BASE_URL%/}"

case "$MODE" in
  lean|full|auto) ;;
  *) err "mode must be 'lean' or 'full' (got '$MODE')"; usage ;;
esac

# Routes under test.
#   - core route: mounted in BOTH modes. /agents is tenantAuth-gated, so
#     unauthenticated it returns 401/403 (NOT 404) — proof the route is mounted.
#   - trading route: mounted ONLY in full mode. POST /trade/hyperliquid/deposit
#     is a real trading route (operator-recovery deposit, /trade/:venue/deposit);
#     absent (404) in lean, present (non-404) in full.
HEALTH_PATH="/health"
CORE_PATH="/agents"
TRADE_PATH="/trade/hyperliquid/deposit"

CURL_OPTS=(--silent --show-error --max-time 15 --output /dev/null --write-out '%{http_code}')

# http_status <METHOD> <path> -> prints numeric status (000 on connection error)
http_status() {
  local method="$1" path="$2" code
  if ! code="$(curl "${CURL_OPTS[@]}" -X "$method" "${BASE_URL}${path}" 2>/dev/null)"; then
    echo "000"
    return 0
  fi
  echo "$code"
}

PASS=0
FAIL=0
declare -a MATRIX=()

record() { # record <name> <PASS|FAIL> <detail>
  MATRIX+=("$1|$2|$3")
  if [ "$2" = "PASS" ]; then PASS=$((PASS + 1)); else FAIL=$((FAIL + 1)); fi
}

log "target: ${BASE_URL}  (mode: ${MODE})"

# ── check 1: /health -> 200 ──────────────────────────────────────────────────
HEALTH_CODE="$(http_status GET "$HEALTH_PATH")"
if [ "$HEALTH_CODE" = "200" ]; then
  record "health" "PASS" "GET ${HEALTH_PATH} -> 200"
else
  record "health" "FAIL" "GET ${HEALTH_PATH} -> ${HEALTH_CODE} (want 200)"
fi

# ── check 2: core route mounted -> NOT 404 ───────────────────────────────────
# unauthenticated /agents should be 401/403 (auth-gated) or 200, never 404.
CORE_CODE="$(http_status GET "$CORE_PATH")"
if [ "$CORE_CODE" = "404" ] || [ "$CORE_CODE" = "000" ]; then
  record "core-route" "FAIL" "GET ${CORE_PATH} -> ${CORE_CODE} (want NOT 404; expected 200/401/403)"
else
  record "core-route" "PASS" "GET ${CORE_PATH} -> ${CORE_CODE} (mounted; not 404)"
fi

# ── check 3: trading route presence -> mode profile ──────────────────────────
TRADE_CODE="$(http_status POST "$TRADE_PATH")"
TRADE_PRESENT="unknown"
if [ "$TRADE_CODE" = "000" ]; then
  TRADE_PRESENT="unknown"
elif [ "$TRADE_CODE" = "404" ]; then
  TRADE_PRESENT="no"   # route NOT mounted -> lean
else
  TRADE_PRESENT="yes"  # route mounted (401/403/4xx/2xx) -> full
fi

DETECTED="unknown"
case "$TRADE_PRESENT" in
  no)  DETECTED="lean" ;;
  yes) DETECTED="full" ;;
esac

if [ "$MODE" = "auto" ]; then
  if [ "$TRADE_PRESENT" = "unknown" ]; then
    record "trading-route" "FAIL" "POST ${TRADE_PATH} -> ${TRADE_CODE} (could not reach service to detect mode)"
  else
    record "trading-route" "PASS" "POST ${TRADE_PATH} -> ${TRADE_CODE} (detected mode: ${DETECTED})"
  fi
elif [ "$MODE" = "lean" ]; then
  # LEAN: trading route MUST be 404.
  if [ "$TRADE_CODE" = "404" ]; then
    record "trading-route" "PASS" "POST ${TRADE_PATH} -> 404 (correctly absent in lean)"
  else
    record "trading-route" "FAIL" "POST ${TRADE_PATH} -> ${TRADE_CODE} (LEAN expects 404; trading appears mounted -> service is NOT lean)"
  fi
else
  # FULL: trading route MUST NOT be 404 (and must be reachable).
  if [ "$TRADE_CODE" = "404" ]; then
    record "trading-route" "FAIL" "POST ${TRADE_PATH} -> 404 (FULL expects trading mounted; route is absent -> STEWARD_PLUGINS=trading not set?)"
  elif [ "$TRADE_CODE" = "000" ]; then
    record "trading-route" "FAIL" "POST ${TRADE_PATH} -> ${TRADE_CODE} (FULL: could not reach service)"
  else
    record "trading-route" "PASS" "POST ${TRADE_PATH} -> ${TRADE_CODE} (mounted; not 404)"
  fi
fi

# ── matrix ───────────────────────────────────────────────────────────────────
echo
echo "  CHECK          RESULT  DETAIL"
echo "  -------------  ------  ----------------------------------------------"
for row in "${MATRIX[@]}"; do
  IFS='|' read -r name result detail <<<"$row"
  if [ "$result" = "PASS" ]; then
    printf "  %-13s  ${GREEN}%-6s${RESET}  %s\n" "$name" "$result" "$detail"
  else
    printf "  %-13s  ${RED}%-6s${RESET}  %s\n" "$name" "$result" "$detail"
  fi
done
echo

if [ "$MODE" = "auto" ] && [ "$DETECTED" != "unknown" ]; then
  log "detected feature profile: ${DETECTED}"
fi

if [ "$FAIL" -eq 0 ]; then
  ok "smoke passed: ${PASS}/${PASS} checks ok"
  exit 0
fi

err "smoke FAILED: ${FAIL} check(s) failed, ${PASS} passed"
exit 1

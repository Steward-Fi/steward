#!/bin/bash
set -euo pipefail

# =============================================================================
# Steward Fleet Deployer
# Usage: STEWARD_NODES="milady=<ip> core-1=<ip> ..." ./scripts/deploy-all.sh [--migrate] [--restart]
#
# Deploys to the FIRST node (canary) first, then the rest in order.
# Aborts if canary fails.
#
# Node inventory is operator-local config, NEVER committed to this public
# repo (SEC-130 — a committed inventory of custodial-wallet hosts is a
# confirmed target list for attackers). Provide it via:
#   STEWARD_NODES="milady=<ip-1> core-1=<ip-2> ..."  (space-separated name=ip,
#                                                      deploy order; first = canary)
# or a gitignored file (default: scripts/deploy-nodes.local.conf, override
# with STEWARD_NODES_CONF) with one name=<ip> per line.
# =============================================================================

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy.sh"

# Host-key checking for the inline version-poll ssh calls below: TOFU
# (accept-new) at minimum — never "no" (SEC-019). STRICT_HOST_KEY=yes
# requires a pre-pinned known_hosts entry instead.
if [[ "${STRICT_HOST_KEY:-}" == "yes" ]]; then
  SSH_OPTS="-o StrictHostKeyChecking=yes -o ConnectTimeout=10"
else
  SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"
fi

# ---------------------------------------------------------------------------
# Help before anything that can fail (e.g. a missing node inventory)
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    -h|--help)
      echo "Usage: STEWARD_NODES=\"milady=<ip> core-1=<ip> ...\" $0 [--migrate] [--restart]"
      echo "  --migrate  Run DB migrations (only on canary node)"
      echo "  --restart  Restart steward services after deploy"
      exit 0
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Nodes: operator-local inventory (see header). First entry is the canary.
# ---------------------------------------------------------------------------
NODES_CONF="${STEWARD_NODES_CONF:-$SCRIPT_DIR/deploy-nodes.local.conf}"
NODE_LIST="${STEWARD_NODES:-}"
if [[ -z "$NODE_LIST" && -f "$NODES_CONF" ]]; then
  NODE_LIST="$(grep -vE '^\s*(#|$)' "$NODES_CONF" | tr '\n' ' ')"
fi
if [[ -z "$NODE_LIST" ]]; then
  echo "No node inventory configured (SEC-130: inventories are operator-local)."
  echo "  Set STEWARD_NODES=\"milady=<ip> core-1=<ip> ...\" or create"
  echo "  $NODES_CONF (gitignored) with one name=<ip> per line."
  exit 1
fi

declare -A NODES
NODE_ORDER=()
for pair in $NODE_LIST; do
  if [[ "$pair" != *=* ]]; then
    echo "Invalid node entry (expected name=<ip>): $pair"
    exit 1
  fi
  NODES["${pair%%=*}"]="${pair#*=}"
  NODE_ORDER+=("${pair%%=*}")
done

# ---------------------------------------------------------------------------
# Forward flags to deploy.sh
# ---------------------------------------------------------------------------
EXTRA_FLAGS=()
DO_MIGRATE=false

for arg in "$@"; do
  case "$arg" in
    --migrate)  EXTRA_FLAGS+=("--migrate"); DO_MIGRATE=true ;;
    --restart)  EXTRA_FLAGS+=("--restart") ;;
    -h|--help)  ;; # handled above, before inventory loading
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Results tracking
# ---------------------------------------------------------------------------
declare -A RESULTS
declare -A VERSIONS

echo ""
echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}  Steward Fleet Deploy${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo ""

# ---------------------------------------------------------------------------
# Canary: deploy to milady first (with --migrate if requested)
# ---------------------------------------------------------------------------
CANARY="${NODE_ORDER[0]}"
CANARY_IP="${NODES[$CANARY]}"

echo -e "${CYAN}[fleet]${RESET} ${BOLD}Canary deploy: $CANARY ($CANARY_IP)${RESET}"
echo ""

CANARY_FLAGS=("${EXTRA_FLAGS[@]}")

if "$DEPLOY_SCRIPT" "$CANARY_IP" "${CANARY_FLAGS[@]+"${CANARY_FLAGS[@]}"}"; then
  RESULTS[$CANARY]="OK"
  # Grab version from health
  VERSIONS[$CANARY]=$(ssh $SSH_OPTS "root@${CANARY_IP}" \
    "curl -sf http://localhost:3200/health" 2>/dev/null \
    | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
  echo ""
  echo -e "${GREEN}[fleet] Canary passed. Rolling out to fleet...${RESET}"
  echo ""
else
  RESULTS[$CANARY]="FAILED"
  VERSIONS[$CANARY]="n/a"
  echo ""
  echo -e "${RED}[fleet] CANARY FAILED. Aborting fleet deploy.${RESET}"
  echo ""
  # Print summary with just canary
  printf "\n${BOLD}%-12s %-10s %-12s${RESET}\n" "NODE" "STATUS" "VERSION"
  printf "%-12s ${RED}%-10s${RESET} %-12s\n" "$CANARY" "FAILED" "n/a"
  exit 1
fi

# ---------------------------------------------------------------------------
# Roll out to remaining nodes (no --migrate, DB is shared)
# ---------------------------------------------------------------------------
# Remove --migrate for agent nodes since DB is shared (already migrated on canary)
AGENT_FLAGS=()
for f in "${EXTRA_FLAGS[@]+"${EXTRA_FLAGS[@]}"}"; do
  [[ "$f" != "--migrate" ]] && AGENT_FLAGS+=("$f")
done

for node in "${NODE_ORDER[@]}"; do
  [[ "$node" == "$CANARY" ]] && continue

  node_ip="${NODES[$node]}"
  echo -e "${CYAN}[fleet]${RESET} Deploying to ${BOLD}$node${RESET} ($node_ip) ..."

  if "$DEPLOY_SCRIPT" "$node_ip" "${AGENT_FLAGS[@]+"${AGENT_FLAGS[@]}"}"; then
    RESULTS[$node]="OK"
    VERSIONS[$node]=$(ssh $SSH_OPTS "root@${node_ip}" \
      "curl -sf http://localhost:3200/health" 2>/dev/null \
      | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
  else
    RESULTS[$node]="FAILED"
    VERSIONS[$node]="n/a"
  fi
  echo ""
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}  Deploy Summary${RESET}"
echo -e "${BOLD}========================================${RESET}"
echo ""
printf "${BOLD}%-12s %-12s %-12s${RESET}\n" "NODE" "STATUS" "VERSION"
printf "%-12s %-12s %-12s\n" "----" "------" "-------"

TOTAL_OK=0
TOTAL_FAIL=0

for node in "${NODE_ORDER[@]}"; do
  status="${RESULTS[$node]:-SKIPPED}"
  version="${VERSIONS[$node]:-n/a}"

  if [[ "$status" == "OK" ]]; then
    printf "%-12s ${GREEN}%-12s${RESET} %-12s\n" "$node" "$status" "$version"
    TOTAL_OK=$((TOTAL_OK + 1))
  else
    printf "%-12s ${RED}%-12s${RESET} %-12s\n" "$node" "$status" "$version"
    TOTAL_FAIL=$((TOTAL_FAIL + 1))
  fi
done

echo ""
echo -e "${BOLD}Total: ${GREEN}$TOTAL_OK OK${RESET}, ${RED}$TOTAL_FAIL FAILED${RESET}"
echo ""

exit $TOTAL_FAIL

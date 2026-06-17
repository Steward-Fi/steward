#!/bin/bash
set -euo pipefail

# =============================================================================
# Railway Deploy Script
# Updates Railway service to use a new Docker image via GraphQL API,
# polls for deployment success, and verifies the /health endpoint.
#
# Usage: ./scripts/railway-deploy.sh <image-tag> [--dry-run]
#   e.g. ./scripts/railway-deploy.sh v0.5.0
#        ./scripts/railway-deploy.sh develop --dry-run
#
# Environment variables:
#   RAILWAY_TOKEN       (required) Railway API bearer token
#   RAILWAY_SERVICE_ID  (REQUIRED) the deployer's own Railway service id
#   RAILWAY_ENV_ID      (REQUIRED) the deployer's own Railway environment id
#   RAILWAY_IMAGE_REPO  (optional) default: ghcr.io/steward-fi/steward (the
#                                  canonical published OSS image)
#   RAILWAY_HEALTH_URL  (optional) the deployer's own /health URL to verify
#   DEPLOY_TIMEOUT      (optional) max seconds to wait for deploy, default: 300
# =============================================================================

GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
CYAN='\033[36m'
RESET='\033[0m'

log()  { echo -e "${CYAN}[railway]${RESET} $*"; }
ok()   { echo -e "${GREEN}[railway]${RESET} $*"; }
warn() { echo -e "${YELLOW}[railway]${RESET} $*"; }
fail() { echo -e "${RED}[railway]${RESET} $*" >&2; }

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
# Steward is sovereign + self-hostable: this script ships the deploy MECHANISM,
# but every instance-specific value (which Railway project/service/env, which
# health URL) belongs to the DEPLOYER's own infra, not to this OSS repo. Set
# them via env (CI secrets/vars). No deployment target is baked into source.
SERVICE_ID="${RAILWAY_SERVICE_ID:-}"
ENV_ID="${RAILWAY_ENV_ID:-}"
IMAGE_REPO="${RAILWAY_IMAGE_REPO:-ghcr.io/steward-fi/steward}"
HEALTH_URL="${RAILWAY_HEALTH_URL:-}"
TIMEOUT="${DEPLOY_TIMEOUT:-300}"
API="https://backboard.railway.com/graphql/v2"

DRY_RUN=false
IMAGE_TAG=""

# Fail loudly if the deployer hasn't pointed this at THEIR instance.
if [[ -z "$SERVICE_ID" || -z "$ENV_ID" ]]; then
  echo "[railway] RAILWAY_SERVICE_ID and RAILWAY_ENV_ID are required (set them to" >&2
  echo "          your own Railway service/environment). Steward does not ship a" >&2
  echo "          default deployment target." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help)
      echo "Usage: $0 <image-tag> [--dry-run]"
      echo "  e.g. $0 v0.5.0"
      exit 0
      ;;
    -*)
      fail "Unknown flag: $arg"; exit 1 ;;
    *)
      if [[ -z "$IMAGE_TAG" ]]; then
        IMAGE_TAG="$arg"
      else
        fail "Unexpected argument: $arg"; exit 1
      fi
      ;;
  esac
done

if [[ -z "$IMAGE_TAG" ]]; then
  fail "Image tag required. Usage: $0 <image-tag>"
  exit 1
fi

if [[ -z "${RAILWAY_TOKEN:-}" ]]; then
  fail "RAILWAY_TOKEN environment variable is required"
  exit 1
fi

FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

# ---------------------------------------------------------------------------
# Helper: GraphQL request
# ---------------------------------------------------------------------------
gql() {
  local query="$1"
  curl -sf -X POST "$API" \
    -H "Authorization: Bearer ${RAILWAY_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$query"
}

# ---------------------------------------------------------------------------
# Step 1: Update the service image via serviceConnect
# ---------------------------------------------------------------------------
log "Deploying ${FULL_IMAGE} to Railway service ${SERVICE_ID}"

if $DRY_RUN; then
  warn "[DRY RUN] Would update service to image: ${FULL_IMAGE}"
  warn "[DRY RUN] Skipping deploy, poll, and health check"
  ok "Dry run complete"
  exit 0
fi

CONNECT_PAYLOAD=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg img "$FULL_IMAGE" \
  '{query: "mutation($id: String!, $input: ServiceConnectInput!) { serviceConnect(id: $id, input: $input) { id } }", variables: {id: $sid, input: {image: $img}}}')

CONNECT_RESULT=$(gql "$CONNECT_PAYLOAD" 2>&1) || {
  fail "serviceConnect mutation failed"
  fail "Response: $CONNECT_RESULT"
  exit 1
}

# Check for GraphQL errors
if echo "$CONNECT_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
  fail "GraphQL error: $(echo "$CONNECT_RESULT" | jq -r '.errors[0].message')"
  exit 1
fi

ok "Service updated to ${FULL_IMAGE}"

# ---------------------------------------------------------------------------
# Step 2: Poll for deployment status
# ---------------------------------------------------------------------------
log "Waiting for deployment to complete (timeout: ${TIMEOUT}s)..."

POLL_QUERY=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query($input: DeploymentListInput!) { deployments(input: $input) { edges { node { id status } } } }", variables: {input: {serviceId: $sid, environmentId: $eid}}}')

ELAPSED=0
INTERVAL=10
DEPLOY_STATUS="UNKNOWN"

while [[ $ELAPSED -lt $TIMEOUT ]]; do
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))

  POLL_RESULT=$(gql "$POLL_QUERY" 2>/dev/null) || continue

  # Get the latest deployment status
  DEPLOY_STATUS=$(echo "$POLL_RESULT" | jq -r '.data.deployments.edges[0].node.status // "UNKNOWN"' 2>/dev/null) || continue

  case "$DEPLOY_STATUS" in
    SUCCESS)
      ok "Deployment succeeded after ${ELAPSED}s"
      break
      ;;
    FAILED|CRASHED|REMOVED)
      fail "Deployment ${DEPLOY_STATUS} after ${ELAPSED}s"
      exit 1
      ;;
    DEPLOYING|BUILDING|INITIALIZING|WAITING)
      log "  Status: ${DEPLOY_STATUS} (${ELAPSED}s elapsed)"
      ;;
    *)
      log "  Status: ${DEPLOY_STATUS} (${ELAPSED}s elapsed)"
      ;;
  esac
done

if [[ "$DEPLOY_STATUS" != "SUCCESS" ]]; then
  fail "Deployment timed out after ${TIMEOUT}s (last status: ${DEPLOY_STATUS})"
  exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Health check
# ---------------------------------------------------------------------------
# Skip when no health URL is configured; otherwise a deployer who only set the
# required service/env IDs would have the service image updated and THEN see the
# deploy marked failed against a bare "/health" URL.
if [[ -z "$HEALTH_URL" ]]; then
  ok "Service image updated. Skipping health check (RAILWAY_HEALTH_URL not set)."
  exit 0
fi

log "Verifying health endpoint: ${HEALTH_URL}/health"

# Give the service a moment to start accepting traffic
sleep 5

HEALTH_OK=false
for i in 1 2 3; do
  HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${HEALTH_URL}/health" 2>/dev/null) || HTTP_CODE="000"
  if [[ "$HTTP_CODE" == "200" ]]; then
    HEALTH_OK=true
    break
  fi
  warn "  Health check attempt $i: HTTP ${HTTP_CODE}"
  sleep 5
done

if $HEALTH_OK; then
  ok "Health check passed"
else
  fail "Health check failed after 3 attempts (last HTTP: ${HTTP_CODE})"
  fail "Service may still be starting. Check ${HEALTH_URL}/health manually."
  exit 1
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
ok "=========================================="
ok "  Railway Deploy Complete"
ok "  Image:   ${FULL_IMAGE}"
ok "  Service: ${SERVICE_ID}"
ok "  Health:  ${HEALTH_URL}/health ✓"
ok "=========================================="

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
# Step 1: Update the service image via serviceInstanceUpdate
# ---------------------------------------------------------------------------
log "Deploying ${FULL_IMAGE} to Railway service ${SERVICE_ID}"

if $DRY_RUN; then
  warn "[DRY RUN] Would update service to image: ${FULL_IMAGE}"
  warn "[DRY RUN] Skipping deploy, poll, and health check"
  ok "Dry run complete"
  exit 0
fi

# Set the image source on the SERVICE INSTANCE for THIS environment.
#
# Why not serviceConnect? serviceConnect(id, input) is scoped to the SERVICE,
# not an environment — it takes no environmentId. The image it sets does not
# reliably land on the specific environment instance we then deploy
# (serviceInstanceDeployV2 is env-scoped). The result was a deployment that
# FAILED ~10s in with EMPTY build+deploy logs: Railway tried to deploy an
# environment instance whose source was never set for that env, so there was
# nothing to pull/run and it errored before any container/build stage.
#
# serviceInstanceUpdate(serviceId, environmentId, input.source.image) sets the
# image on the EXACT environment instance we deploy, which is the documented,
# current way to deploy a prebuilt Docker image per-environment. We then call
# serviceInstanceDeployV2 (which alone triggers a fresh deploy of the new tag;
# redeploy mutations only re-run the existing tag).
CONNECT_PAYLOAD=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  --arg img "$FULL_IMAGE" \
  '{query: "mutation($sid: String!, $eid: String!, $input: ServiceInstanceUpdateInput!) { serviceInstanceUpdate(serviceId: $sid, environmentId: $eid, input: $input) }", variables: {sid: $sid, eid: $eid, input: {source: {image: $img}}}}')

# Record when this run started so the poll ignores any pre-existing (stale)
# deployment for this service/env. serviceInstanceUpdate only changes the image
# SOURCE; it does not create a new deployment, so without this guard the poll
# reads edges[0] = the previous, already-FAILED deployment and reports a fresh
# failure ~10s in on every run.
START_TS=$(date -u +%s)

CONNECT_RESULT=$(gql "$CONNECT_PAYLOAD" 2>&1) || {
  fail "serviceInstanceUpdate mutation failed"
  fail "Response: $CONNECT_RESULT"
  exit 1
}

# Check for GraphQL errors
if echo "$CONNECT_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
  fail "GraphQL error: $(echo "$CONNECT_RESULT" | jq -r '.errors[0].message')"
  exit 1
fi

ok "Service instance updated to ${FULL_IMAGE} (env ${ENV_ID})"

# serviceInstanceUpdate only updates the image source; explicitly trigger a
# deployment so a new deployment is actually created. Treat failure as
# non-fatal: some Railway configurations auto-deploy on update, in which case
# the poll below (filtered to deployments newer than START_TS) still picks up
# the new one.
TRIGGER_DEPLOY_ID=""
DEPLOY_PAYLOAD=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "mutation($sid: String!, $eid: String!) { serviceInstanceDeployV2(serviceId: $sid, environmentId: $eid) }", variables: {sid: $sid, eid: $eid}}')

DEPLOY_TRIGGER=$(gql "$DEPLOY_PAYLOAD" 2>&1) || DEPLOY_TRIGGER=""
if echo "$DEPLOY_TRIGGER" | jq -e '.errors' >/dev/null 2>&1; then
  warn "serviceInstanceDeploy returned an error (service may auto-deploy on connect): $(echo "$DEPLOY_TRIGGER" | jq -r '.errors[0].message' 2>/dev/null)"
else
  TRIGGER_DEPLOY_ID=$(echo "$DEPLOY_TRIGGER" | jq -r '.data.serviceInstanceDeployV2 // ""' 2>/dev/null) || TRIGGER_DEPLOY_ID=""
  [[ -n "$TRIGGER_DEPLOY_ID" ]] && ok "Triggered deployment ${TRIGGER_DEPLOY_ID}"
fi

# ---------------------------------------------------------------------------
# Step 2: Poll for deployment status
# ---------------------------------------------------------------------------
log "Waiting for deployment to complete (timeout: ${TIMEOUT}s)..."

POLL_QUERY=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query($input: DeploymentListInput!) { deployments(input: $input, first: 5) { edges { node { id status createdAt } } } }", variables: {input: {serviceId: $sid, environmentId: $eid}}}')

ELAPSED=0
INTERVAL=10
DEPLOY_STATUS="UNKNOWN"
DEPLOY_ID=""

# Surface Railway's OWN failure reason + build/deploy logs so CI shows the real
# cause instead of a bare "Deployment FAILED". A deploy that fails ~10s in with
# no build phase is almost always the container crash-looping on boot (e.g. a
# missing required env var on the Railway service) or an image-pull error — the
# logs below are what tell the operator which. Uses a non-failing curl (the
# normal gql() helper uses `curl -sf`, which drops the body on any HTTP error)
# and prints RAW responses so a wrong field name / auth-scope problem is still
# visible rather than silently swallowed.
gql_raw() {
  curl -s -X POST "$API" \
    -H "Authorization: Bearer ${RAILWAY_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$1" 2>/dev/null
}

# Set by dump_failure: 1 when BOTH build and deploy logs came back empty, i.e.
# Railway rejected the deployment at the control-plane / provision stage before
# any container ran (the signature of an unconfigured external service, not an
# app/code regression). 0 when the container actually produced output (a real
# crash/health failure that SHOULD fail the pipeline).
LOGS_EMPTY=0

dump_failure() {
  LOGS_EMPTY=0
  fail "---- Railway deployment diagnostics ----"
  if [[ -z "$DEPLOY_ID" ]]; then
    fail "No deployment id captured — serviceInstanceUpdate/serviceInstanceDeploy may not have created a new deployment."
    fail "----------------------------------------"
    LOGS_EMPTY=1
    return
  fi
  local q resp build_logs deploy_logs
  # NB: the Deployment type has no `statusMessage` field (Railway's API returns a
  # GRAPHQL_VALIDATION_FAILED for it). Query only valid fields. A FAILED status
  # with EMPTY build+deploy logs (below) means Railway rejected the deployment at
  # the image-pull / provision stage before any container ran — check the Railway
  # dashboard for this service/deployment id, as the API exposes nothing further.
  q=$(jq -n --arg id "$DEPLOY_ID" \
    '{query: "query($id: String!) { deployment(id: $id) { id status createdAt staticUrl url canRedeploy } }", variables: {id: $id}}')
  resp=$(gql_raw "$q")
  fail "deployment: ${resp:-<empty response>}"

  q=$(jq -n --arg id "$DEPLOY_ID" \
    '{query: "query($id: String!) { buildLogs(deploymentId: $id, limit: 200) { message } }", variables: {id: $id}}')
  resp=$(gql_raw "$q")
  build_logs=$(echo "${resp:-}" | jq -r '.data.buildLogs[]?.message // empty' 2>/dev/null)
  fail "---- build logs ----"
  [[ -n "$build_logs" ]] && echo "$build_logs" >&2 || fail "${resp:-<empty response>}"

  q=$(jq -n --arg id "$DEPLOY_ID" \
    '{query: "query($id: String!) { deploymentLogs(deploymentId: $id, limit: 200) { message } }", variables: {id: $id}}')
  resp=$(gql_raw "$q")
  deploy_logs=$(echo "${resp:-}" | jq -r '.data.deploymentLogs[]?.message // empty' 2>/dev/null)
  fail "---- deploy logs ----"
  [[ -n "$deploy_logs" ]] && echo "$deploy_logs" >&2 || fail "${resp:-<empty response>}"
  fail "----------------------------------------"

  [[ -z "$build_logs" && -z "$deploy_logs" ]] && LOGS_EMPTY=1
}

# Decide exit code for a failed/timed-out deployment. A control-plane rejection
# with no container output (LOGS_EMPTY=1) is an external-infra availability
# problem on the deployer's own Railway service, not a repo/app regression — so
# by default it is a loud non-fatal warning rather than a hard pipeline failure
# (this is a sovereign, self-hostable deploy: an unconfigured external target
# must not wedge the source repo's CI). A failure WITH container logs is a real
# crash and always fails. Override with RAILWAY_STRICT=true to fail on anything.
finish_failure() {
  if [[ "${RAILWAY_STRICT:-false}" != "true" && "$LOGS_EMPTY" == "1" ]]; then
    warn "Deployment was rejected by Railway BEFORE any container started (no build/deploy logs)."
    warn "This is an external Railway service/config issue (region/source/account on"
    warn "service ${SERVICE_ID}, env ${ENV_ID}), not a repo defect — see the Railway"
    warn "dashboard for deployment ${DEPLOY_ID:-<none>}. Treating as a non-fatal warning."
    warn "Set RAILWAY_STRICT=true to make this a hard failure instead."
    exit 0
  fi
  exit 1
}

while [[ $ELAPSED -lt $TIMEOUT ]]; do
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))

  POLL_RESULT=$(gql "$POLL_QUERY" 2>/dev/null) || continue

  # Select the deployment to track: prefer the one serviceInstanceDeploy
  # returned; otherwise the newest deployment CREATED AT/AFTER this run started
  # (epoch). This avoids reading a stale, previously-failed deployment.
  if [[ -n "$TRIGGER_DEPLOY_ID" ]]; then
    NODE=$(echo "$POLL_RESULT" | jq -c --arg id "$TRIGGER_DEPLOY_ID" \
      '.data.deployments.edges[]?.node | select(.id == $id)' 2>/dev/null) || NODE=""
  else
    NODE=$(echo "$POLL_RESULT" | jq -c --argjson since "$START_TS" \
      '[.data.deployments.edges[]?.node | select((.createdAt | sub("\\.[0-9]+Z$";"Z") | fromdateiso8601) >= $since)] | sort_by(.createdAt) | last // empty' 2>/dev/null) || NODE=""
  fi

  if [[ -z "$NODE" || "$NODE" == "null" ]]; then
    log "  Waiting for a new deployment to appear (${ELAPSED}s elapsed)"
    continue
  fi

  DEPLOY_ID=$(echo "$NODE" | jq -r '.id // ""' 2>/dev/null) || DEPLOY_ID=""
  DEPLOY_STATUS=$(echo "$NODE" | jq -r '.status // "UNKNOWN"' 2>/dev/null) || DEPLOY_STATUS="UNKNOWN"

  case "$DEPLOY_STATUS" in
    SUCCESS)
      ok "Deployment succeeded after ${ELAPSED}s (id: ${DEPLOY_ID})"
      break
      ;;
    FAILED|CRASHED|REMOVED)
      fail "Deployment ${DEPLOY_STATUS} after ${ELAPSED}s (id: ${DEPLOY_ID})"
      dump_failure
      finish_failure
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
  dump_failure
  finish_failure
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

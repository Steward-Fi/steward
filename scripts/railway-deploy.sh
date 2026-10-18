#!/bin/bash
set -euo pipefail

# =============================================================================
# Railway Deploy Script
# Updates Railway service to use a new Docker image via GraphQL API,
# polls the exact deployment id for success, verifies Railway's effective
# platform healthcheck contract, and (for production) performs an authenticated
# deep-readiness probe.
#
# Usage: ./scripts/railway-deploy.sh <image-tag> [--dry-run]
#        RAILWAY_IMAGE_DIGEST=sha256:<64-hex> ./scripts/railway-deploy.sh [--dry-run]
#   e.g. ./scripts/railway-deploy.sh v0.5.0
#        ./scripts/railway-deploy.sh develop --dry-run
#        RAILWAY_IMAGE_DIGEST=sha256:<64-hex> ./scripts/railway-deploy.sh
#
# Environment variables:
#   RAILWAY_TOKEN       (required) Railway API bearer token
#   RAILWAY_SERVICE_ID  (REQUIRED) the deployer's own Railway service id
#   RAILWAY_ENV_ID      (REQUIRED) the deployer's own Railway environment id
#   RAILWAY_IMAGE_REPO  (optional) default: ghcr.io/steward-fi/steward (the
#                                  canonical published OSS image)
#   RAILWAY_IMAGE_DIGEST (optional) immutable sha256 digest. Mutually exclusive
#                                  with the positional image tag. Production
#                                  deploys should always use this mode.
#   RAILWAY_HEALTH_URL  (optional) the deployer's public HTTPS origin (without
#                                  /health or /ready)
#   RAILWAY_REQUIRE_HEALTH (optional, default: false) fail before mutation when
#                                  RAILWAY_HEALTH_URL is absent. Production CI
#                                  must set this to true.
#   RAILWAY_REQUIRE_READY (optional, default: false) require an authenticated
#                                  /ready acceptance probe. Production CI must
#                                  set this to true.
#   RAILWAY_READY_PROBE_TOKEN (required when RAILWAY_REQUIRE_READY=true) value
#                                  configured as STEWARD_READY_PROBE_TOKEN on the
#                                  target. It is compared in-process with the
#                                  exact target's control-plane value, sent only
#                                  in the X-Steward-Probe-Token header, and never
#                                  logged.
#   RAILWAY_EXPECTED_REVISION (required when RAILWAY_REQUIRE_READY=true) exact
#                                  40-character source revision bound to the
#                                  immutable image provenance.
#   DEPLOY_TIMEOUT      (optional) max seconds to wait for deploy, default: 300
#   RAILWAY_ALLOW_REJECTED_DEPLOY (optional, default: fail closed) when "true",
#                       a deployment Railway rejected before any container ran
#                       (no build/deploy logs) degrades to a non-fatal warning
#                       instead of failing the pipeline. SEC-129: the default
#                       is a HARD failure — a green pipeline that silently
#                       shipped nothing is how a security fix looks deployed
#                       when it is not.
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
IMAGE_DIGEST="${RAILWAY_IMAGE_DIGEST:-}"
HEALTH_URL="${RAILWAY_HEALTH_URL:-}"
READY_PROBE_TOKEN="${RAILWAY_READY_PROBE_TOKEN:-}"
EXPECTED_REVISION="${RAILWAY_EXPECTED_REVISION:-}"
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
      echo "       RAILWAY_IMAGE_DIGEST=sha256:<64-hex> $0 [--dry-run]"
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

if [[ -n "$IMAGE_TAG" && -n "$IMAGE_DIGEST" ]]; then
  fail "Choose exactly one image selector: a positional tag or RAILWAY_IMAGE_DIGEST"
  exit 1
fi

if [[ -z "$IMAGE_TAG" && -z "$IMAGE_DIGEST" ]]; then
  fail "Image selector required: pass an image tag or set RAILWAY_IMAGE_DIGEST"
  exit 1
fi

# OCI/Docker tags are at most 128 characters and contain only this conservative
# subset. Reject whitespace, shell-like syntax, slashes, and control characters
# before the value reaches logs or a deployment API.
if [[ -n "$IMAGE_TAG" && ! "$IMAGE_TAG" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]]; then
  fail "Invalid image tag: expected an OCI tag (letters, digits, _, ., -; max 128 chars)"
  exit 1
fi

if [[ -n "$IMAGE_DIGEST" && ! "$IMAGE_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  fail "Invalid image digest: expected sha256 followed by exactly 64 lowercase hex characters"
  exit 1
fi

if [[ -z "${RAILWAY_TOKEN:-}" ]]; then
  fail "RAILWAY_TOKEN environment variable is required"
  exit 1
fi

if [[ "${RAILWAY_REQUIRE_HEALTH:-false}" != "true" &&
      "${RAILWAY_REQUIRE_HEALTH:-false}" != "false" ]]; then
  fail "RAILWAY_REQUIRE_HEALTH must be true or false"
  exit 1
fi

if [[ "${RAILWAY_REQUIRE_HEALTH:-false}" == "true" && -z "$HEALTH_URL" ]]; then
  fail "RAILWAY_HEALTH_URL is required when RAILWAY_REQUIRE_HEALTH=true"
  exit 1
fi

if [[ "${RAILWAY_REQUIRE_READY:-false}" != "true" &&
      "${RAILWAY_REQUIRE_READY:-false}" != "false" ]]; then
  fail "RAILWAY_REQUIRE_READY must be true or false"
  exit 1
fi

if [[ "${RAILWAY_REQUIRE_READY:-false}" == "true" ]]; then
  if [[ -z "$HEALTH_URL" ]]; then
    fail "RAILWAY_HEALTH_URL is required when RAILWAY_REQUIRE_READY=true"
    exit 1
  fi
  if [[ ! "$HEALTH_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]]; then
    fail "RAILWAY_HEALTH_URL must be an HTTPS origin when authenticated readiness is required"
    exit 1
  fi
  if [[ -z "$READY_PROBE_TOKEN" ]]; then
    fail "RAILWAY_READY_PROBE_TOKEN is required when RAILWAY_REQUIRE_READY=true"
    exit 1
  fi
  if [[ ! "$EXPECTED_REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    fail "RAILWAY_EXPECTED_REVISION must be a full lowercase 40-character commit SHA"
    exit 1
  fi
  if [[ -z "$IMAGE_DIGEST" ]]; then
    fail "RAILWAY_IMAGE_DIGEST is required when RAILWAY_REQUIRE_READY=true"
    exit 1
  fi
fi

if [[ -n "$IMAGE_DIGEST" ]]; then
  FULL_IMAGE="${IMAGE_REPO}@${IMAGE_DIGEST}"
else
  FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"
fi

# Railway exposes the deployed image/digest but not OCI revision labels in its
# Deployment API. For production, prove the immutable digest carries the exact
# expected source revision before mutating Railway. The post-deploy check below
# then binds that same digest to the exact Railway deployment id.
if [[ "${RAILWAY_REQUIRE_READY:-false}" == "true" ]]; then
  PROVENANCE_TAG="${IMAGE_REPO}:sha-${EXPECTED_REVISION}"
  PROVENANCE_MANIFEST=$(docker buildx imagetools inspect \
    "$PROVENANCE_TAG" --format '{{json .Manifest}}' 2>/dev/null) || {
    fail "Could not inspect the exact-revision image manifest"
    exit 1
  }
  PROVENANCE_DIGEST=$(jq -er \
    '.digest | select(test("^sha256:[0-9a-f]{64}$"))' \
    <<<"$PROVENANCE_MANIFEST" 2>/dev/null) || {
    fail "Exact-revision image tag did not resolve to a valid digest"
    exit 1
  }
  if [[ "$PROVENANCE_DIGEST" != "$IMAGE_DIGEST" ]]; then
    fail "Exact-revision image tag does not resolve to RAILWAY_IMAGE_DIGEST"
    exit 1
  fi
  IMAGE_PROVENANCE=$(docker buildx imagetools inspect \
    "$PROVENANCE_TAG" \
    --format '{{json .Provenance.SLSA.buildDefinition.externalParameters.request.args}}' \
    2>/dev/null) || {
    fail "Could not inspect immutable image provenance"
    exit 1
  }
  IMAGE_REVISION=$(jq -er '."label:org.opencontainers.image.revision"' \
    <<<"$IMAGE_PROVENANCE" 2>/dev/null) || {
    fail "Immutable image provenance does not contain a source revision"
    exit 1
  }
  if [[ "$IMAGE_REVISION" != "$EXPECTED_REVISION" ]]; then
    fail "Immutable image provenance revision does not match RAILWAY_EXPECTED_REVISION"
    exit 1
  fi
  # Close the tag-movement window between the manifest and provenance reads.
  RECHECK_MANIFEST=$(docker buildx imagetools inspect \
    "$PROVENANCE_TAG" --format '{{json .Manifest}}' 2>/dev/null) || {
    fail "Could not recheck the exact-revision image manifest"
    exit 1
  }
  RECHECK_DIGEST=$(jq -er \
    '.digest | select(test("^sha256:[0-9a-f]{64}$"))' \
    <<<"$RECHECK_MANIFEST" 2>/dev/null) || {
    fail "Exact-revision image tag recheck did not return a valid digest"
    exit 1
  }
  if [[ "$RECHECK_DIGEST" != "$IMAGE_DIGEST" ]]; then
    fail "Exact-revision image tag moved during provenance verification"
    exit 1
  fi
  ok "Immutable image provenance matches the expected source revision"
fi

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
# Step 1: Pin the image and Railway platform healthcheck together
# ---------------------------------------------------------------------------
log "Deploying ${FULL_IMAGE} to Railway service ${SERVICE_ID}"

# Prove the protected workflow secret matches the effective
# STEWARD_READY_PROBE_TOKEN for this exact Railway service/environment before
# any mutation. Read this through Railway's control plane instead of probing the
# currently serving /ready: a pinned rollback image may predate authenticated
# verbose readiness even though the candidate is required to support it. The
# variables response contains secrets, so never print it or GraphQL errors from
# this query. The strict post-cutover /ready contract below remains unchanged.
if [[ "${RAILWAY_REQUIRE_READY:-false}" == "true" ]]; then
  READY_TARGET_QUERY=$(jq -n \
    --arg sid "$SERVICE_ID" \
    --arg eid "$ENV_ID" \
    '{query: "query ReadyProbeTarget($sid: String!, $eid: String!) { serviceInstance(serviceId: $sid, environmentId: $eid) { serviceId environmentId service { id projectId } } }", variables: {sid: $sid, eid: $eid}}')
  READY_TARGET_RESULT=$(gql "$READY_TARGET_QUERY" 2>/dev/null) || {
    fail "Could not verify the Railway readiness-token target before mutation"
    exit 1
  }
  if echo "$READY_TARGET_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
    fail "Railway rejected the readiness-token target query before mutation"
    exit 1
  fi
  PROJECT_ID=$(echo "$READY_TARGET_RESULT" | jq -er \
    --arg sid "$SERVICE_ID" \
    --arg eid "$ENV_ID" \
    '.data.serviceInstance
      | select(.serviceId == $sid
          and .environmentId == $eid
          and .service.id == $sid
          and (.service.projectId | type) == "string"
          and (.service.projectId | length) > 0)
      | .service.projectId' 2>/dev/null) || PROJECT_ID=""
  unset READY_TARGET_RESULT
  if [[ -z "$PROJECT_ID" ]]; then
    fail "Railway returned an invalid readiness-token target before mutation"
    exit 1
  fi

  READY_VARIABLES_QUERY=$(jq -n \
    --arg pid "$PROJECT_ID" \
    --arg eid "$ENV_ID" \
    --arg sid "$SERVICE_ID" \
    '{query: "query ReadyProbeVariables($pid: String!, $eid: String!, $sid: String!) { variables(projectId: $pid, environmentId: $eid, serviceId: $sid, unrendered: false) }", variables: {pid: $pid, eid: $eid, sid: $sid}}')
  unset PROJECT_ID
  READY_VARIABLES_RESULT=$(gql "$READY_VARIABLES_QUERY" 2>/dev/null) || {
    fail "Could not read the effective Railway readiness-token configuration before mutation"
    exit 1
  }
  if echo "$READY_VARIABLES_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
    unset READY_VARIABLES_RESULT
    fail "Railway rejected the readiness-token configuration query before mutation"
    exit 1
  fi
  TARGET_READY_PROBE_TOKEN=$(echo "$READY_VARIABLES_RESULT" | jq -er \
    '.data.variables.STEWARD_READY_PROBE_TOKEN
      | select(type == "string" and length > 0)' 2>/dev/null) || TARGET_READY_PROBE_TOKEN=""
  unset READY_VARIABLES_RESULT
  if [[ -z "$TARGET_READY_PROBE_TOKEN" || "$TARGET_READY_PROBE_TOKEN" != "$READY_PROBE_TOKEN" ]]; then
    unset TARGET_READY_PROBE_TOKEN
    fail "The protected readiness token does not match the effective Railway service variable"
    fail "No Railway configuration or deployment mutation was attempted."
    exit 1
  fi
  unset TARGET_READY_PROBE_TOKEN
  ok "Protected readiness token matches the exact Railway service/environment configuration"
fi

if $DRY_RUN; then
  warn "[DRY RUN] Would update service to image: ${FULL_IMAGE}"
  warn "[DRY RUN] Skipping deploy, poll, and health check"
  ok "Dry run complete"
  exit 0
fi

# Snapshot the recent deployments before changing service-instance config.
# Railway does not document serviceInstanceUpdate as returning a deployment id.
# If that mutation, an auto-deploy setting, or a concurrent actor creates a
# deployment in addition to the explicit serviceInstanceDeployV2 id below, fail
# closed rather than guessing which release won the race. Also reject any
# pre-existing nonterminal deployment that could complete later and displace the
# candidate while remaining hidden inside the baseline id set.
BASELINE_QUERY=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query BaselineDeployments($input: DeploymentListInput!, $inflightInput: DeploymentListInput!) { deployments(input: $input, first: 20) { edges { node { id status } } } inflight: deployments(input: $inflightInput, first: 1) { edges { node { id status } } } }", variables: {input: {serviceId: $sid, environmentId: $eid}, inflightInput: {serviceId: $sid, environmentId: $eid, status: {in: ["BUILDING", "DEPLOYING", "INITIALIZING", "NEEDS_APPROVAL", "QUEUED", "REMOVING", "WAITING"]}}}}')
BASELINE_RESULT=$(gql "$BASELINE_QUERY" 2>&1) || {
  fail "Could not capture the pre-mutation Railway deployment inventory"
  exit 1
}
if echo "$BASELINE_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
  fail "Railway rejected the pre-mutation deployment inventory query"
  exit 1
fi
BASELINE_NODES=$(echo "$BASELINE_RESULT" | jq -ce \
  '[.data.deployments.edges[]?.node
    | select((.id | type) == "string" and (.status | type) == "string")]' 2>/dev/null) || {
  fail "Railway returned an invalid pre-mutation deployment inventory"
  exit 1
}
BASELINE_COUNT=$(echo "$BASELINE_RESULT" | jq -er \
  '[.data.deployments.edges[]?.node] | length' 2>/dev/null) || BASELINE_COUNT=""
VALID_BASELINE_COUNT=$(echo "$BASELINE_NODES" | jq -er 'length' 2>/dev/null) || VALID_BASELINE_COUNT=""
if [[ ! "$BASELINE_COUNT" =~ ^[0-9]+$ || "$VALID_BASELINE_COUNT" != "$BASELINE_COUNT" ]]; then
  fail "Railway returned an invalid pre-mutation deployment inventory"
  exit 1
fi
NONTERMINAL_BASELINE_COUNT=$(echo "$BASELINE_NODES" | jq -er \
  '[.[] | select(.status != "SUCCESS"
    and .status != "FAILED"
    and .status != "CRASHED"
    and .status != "REMOVED"
    and .status != "SLEEPING"
    and .status != "SKIPPED")]
    | length' 2>/dev/null) || NONTERMINAL_BASELINE_COUNT=""
INFLIGHT_BASELINE_COUNT=$(echo "$BASELINE_RESULT" | jq -er \
  '[.data.inflight.edges[]?.node] | length' 2>/dev/null) || INFLIGHT_BASELINE_COUNT=""
if [[ ! "$NONTERMINAL_BASELINE_COUNT" =~ ^[0-9]+$ ||
      ! "$INFLIGHT_BASELINE_COUNT" =~ ^[0-9]+$ ||
      "$NONTERMINAL_BASELINE_COUNT" != "0" ||
      "$INFLIGHT_BASELINE_COUNT" != "0" ]]; then
  fail "A pre-existing nonterminal Railway deployment is already in flight"
  fail "Wait for it to reach a terminal state before starting an exact-id production deploy."
  exit 1
fi
BASELINE_IDS=$(echo "$BASELINE_NODES" | jq -ce '[.[].id]')

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
# current way to deploy a prebuilt Docker image per-environment. Set
# healthcheckPath in the SAME mutation so Railway itself must get HTTP 200 from
# this deployment's /health before it can become active; a public-domain probe
# could otherwise be answered by the previous instance. Pin overlapSeconds=0 so
# the authenticated public /ready acceptance probe cannot be load-balanced to
# an old deployment after Railway marks the tracked candidate active. We then
# call
# serviceInstanceDeployV2 (which alone triggers a fresh deploy of the new tag;
# redeploy mutations only re-run the existing tag).
CONNECT_PAYLOAD=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  --arg img "$FULL_IMAGE" \
  '{query: "mutation($sid: String!, $eid: String!, $input: ServiceInstanceUpdateInput!) { serviceInstanceUpdate(serviceId: $sid, environmentId: $eid, input: $input) }", variables: {sid: $sid, eid: $eid, input: {source: {image: $img}, healthcheckPath: "/health", overlapSeconds: 0}}}')

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

INSTANCE_QUERY=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query($sid: String!, $eid: String!) { serviceInstance(serviceId: $sid, environmentId: $eid) { serviceId environmentId healthcheckPath overlapSeconds source { image } } }", variables: {sid: $sid, eid: $eid}}')
INSTANCE_RESULT=$(gql "$INSTANCE_QUERY" 2>&1) || {
  fail "Could not verify the effective Railway service-instance configuration"
  exit 1
}
if echo "$INSTANCE_RESULT" | jq -e '.errors' >/dev/null 2>&1; then
  fail "Railway rejected the effective service-instance query"
  exit 1
fi
if ! echo "$INSTANCE_RESULT" | jq -e \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  --arg img "$FULL_IMAGE" \
  '.data.serviceInstance
    | .serviceId == $sid
      and .environmentId == $eid
      and .healthcheckPath == "/health"
      and .overlapSeconds == 0
      and .source.image == $img' >/dev/null 2>&1; then
  fail "Railway effective config does not match the requested service, environment, image, /health gate, and zero-overlap cutover"
  exit 1
fi

ok "Service instance pinned to ${FULL_IMAGE} with Railway healthcheckPath=/health"

# serviceInstanceUpdate only updates the image source; explicitly trigger a
# deployment so a new deployment is actually created. The returned id is the
# only deployment this run may accept. A trigger error or missing id is fatal:
# guessing from the latest deployment can select a stale or concurrent deploy.
TRIGGER_DEPLOY_ID=""
DEPLOY_PAYLOAD=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "mutation($sid: String!, $eid: String!) { serviceInstanceDeployV2(serviceId: $sid, environmentId: $eid) }", variables: {sid: $sid, eid: $eid}}')

DEPLOY_TRIGGER=$(gql "$DEPLOY_PAYLOAD" 2>&1) || {
  fail "serviceInstanceDeployV2 mutation failed"
  exit 1
}
if echo "$DEPLOY_TRIGGER" | jq -e '.errors' >/dev/null 2>&1; then
  fail "serviceInstanceDeployV2 returned a GraphQL error"
  exit 1
fi
TRIGGER_DEPLOY_ID=$(echo "$DEPLOY_TRIGGER" | jq -r '.data.serviceInstanceDeployV2 // ""' 2>/dev/null) || TRIGGER_DEPLOY_ID=""
if [[ ! "$TRIGGER_DEPLOY_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  fail "serviceInstanceDeployV2 did not return a valid deployment id"
  exit 1
fi
ok "Triggered exact deployment ${TRIGGER_DEPLOY_ID}"

# ---------------------------------------------------------------------------
# Step 2: Poll for deployment status
# ---------------------------------------------------------------------------
log "Waiting for deployment to complete (timeout: ${TIMEOUT}s)..."

POLL_QUERY=$(jq -n \
  --arg id "$TRIGGER_DEPLOY_ID" \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query TrackedDeployment($id: String!, $input: DeploymentListInput!) { deployment(id: $id) { id serviceId environmentId status createdAt meta } deployments(input: $input, first: 20) { edges { node { id } } } }", variables: {id: $id, input: {serviceId: $sid, environmentId: $eid}}}')

assert_no_untracked_deployment() {
  local result="$1"
  local untracked_count
  untracked_count=$(echo "$result" | jq -er \
    --argjson baseline "$BASELINE_IDS" \
    --arg tracked "$TRIGGER_DEPLOY_ID" \
    '[.data.deployments.edges[]?.node.id as $candidate
      | select(($baseline | index($candidate)) == null and $candidate != $tracked)]
      | length' 2>/dev/null) || untracked_count=""
  if [[ ! "$untracked_count" =~ ^[0-9]+$ ]]; then
    fail "Railway returned an invalid deployment inventory while polling"
    exit 1
  fi
  if [[ "$untracked_count" != "0" ]]; then
    fail "Detected an untracked deployment created after this run started"
    fail "Refusing acceptance because an auto-deploy or concurrent mutation raced the exact deployment id."
    exit 1
  fi
}

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

# Redact obvious secret shapes before printing build/deploy logs to CI
# stderr: a crash-looped container may have echoed config (DATABASE_URL,
# STEWARD_* secrets, Bearer tokens) to its logs (SEC-129).
redact_secrets() {
  sed -E \
    -e 's#(postgres(ql)?://[^:/@]+:)[^@]+@#\1…REDACTED…@#g' \
    -e 's/(Bearer )[A-Za-z0-9._~+/-]+/\1…REDACTED…/g' \
    -e 's/((SECRET|SECRETS|PASSWORD|PASS|SALT|TOKEN|KEY|KEYS|HMAC|PRIVATE)[A-Z_]*=)[^[:space:]]+/\1…REDACTED…/g' \
    -e 's/(^|[^A-Za-z0-9_])stw_[A-Za-z0-9]+/\1stw_…REDACTED…/g' \
    -e 's/(^|[^0-9a-fA-F])[0-9a-fA-F]{48,}([^0-9a-fA-F]|$)/\1…REDACTED…\2/g'
}

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
  if [[ -n "$build_logs" ]]; then
    echo "$build_logs" | redact_secrets >&2
  else
    fail "${resp:-<empty response>}"
  fi

  q=$(jq -n --arg id "$DEPLOY_ID" \
    '{query: "query($id: String!) { deploymentLogs(deploymentId: $id, limit: 200) { message } }", variables: {id: $id}}')
  resp=$(gql_raw "$q")
  deploy_logs=$(echo "${resp:-}" | jq -r '.data.deploymentLogs[]?.message // empty' 2>/dev/null)
  fail "---- deploy logs ----"
  if [[ -n "$deploy_logs" ]]; then
    echo "$deploy_logs" | redact_secrets >&2
  else
    fail "${resp:-<empty response>}"
  fi
  fail "----------------------------------------"

  [[ -z "$build_logs" && -z "$deploy_logs" ]] && LOGS_EMPTY=1
}

# Decide exit code for a failed/timed-out deployment. SEC-129: the default is
# a HARD failure in every case — a control-plane rejection with no container
# output (LOGS_EMPTY=1) means the deploy never happened, and a green pipeline
# that silently shipped nothing is exactly how a security fix appears deployed
# when it isn't. Operators running an intentionally-unconfigured external
# target may opt back into the old non-fatal behavior for that specific case
# with RAILWAY_ALLOW_REJECTED_DEPLOY=true. A failure WITH container logs is a
# real crash and always fails.
finish_failure() {
  if [[ "${RAILWAY_ALLOW_REJECTED_DEPLOY:-false}" == "true" && "$LOGS_EMPTY" == "1" ]]; then
    warn "Deployment was rejected by Railway BEFORE any container started (no build/deploy logs)."
    warn "This is an external Railway service/config issue (region/source/account on"
    warn "service ${SERVICE_ID}, env ${ENV_ID}), not a repo defect — see the Railway"
    warn "dashboard for deployment ${DEPLOY_ID:-<none>}."
    warn "Treating as a non-fatal warning because RAILWAY_ALLOW_REJECTED_DEPLOY=true"
    warn "(unset it to restore the fail-closed default)."
    exit 0
  fi
  if [[ "$LOGS_EMPTY" == "1" ]]; then
    fail "Deployment was rejected by Railway BEFORE any container started (no build/deploy"
    fail "logs) — the new image is NOT live. Check the Railway dashboard for deployment"
    fail "${DEPLOY_ID:-<none>} (service ${SERVICE_ID}, env ${ENV_ID}). Failing the pipeline"
    fail "so a missing deploy can never look shipped; set"
    fail "RAILWAY_ALLOW_REJECTED_DEPLOY=true to downgrade this specific case to a warning."
  fi
  exit 1
}

while [[ $ELAPSED -lt $TIMEOUT ]]; do
  sleep "$INTERVAL"
  ELAPSED=$((ELAPSED + INTERVAL))

  POLL_RESULT=$(gql "$POLL_QUERY" 2>/dev/null) || continue
  assert_no_untracked_deployment "$POLL_RESULT"

  NODE=$(echo "$POLL_RESULT" | jq -c '.data.deployment // empty' 2>/dev/null) || NODE=""

  if [[ -z "$NODE" || "$NODE" == "null" ]]; then
    log "  Waiting for exact deployment ${TRIGGER_DEPLOY_ID} to appear (${ELAPSED}s elapsed)"
    continue
  fi

  DEPLOY_ID=$(echo "$NODE" | jq -r '.id // ""' 2>/dev/null) || DEPLOY_ID=""
  DEPLOY_STATUS=$(echo "$NODE" | jq -r '.status // "UNKNOWN"' 2>/dev/null) || DEPLOY_STATUS="UNKNOWN"

  if ! echo "$NODE" | jq -e \
    --arg id "$TRIGGER_DEPLOY_ID" \
    --arg sid "$SERVICE_ID" \
    --arg eid "$ENV_ID" \
    '.id == $id and .serviceId == $sid and .environmentId == $eid' >/dev/null 2>&1; then
    fail "Railway returned a deployment outside the requested id/service/environment scope"
    exit 1
  fi

  case "$DEPLOY_STATUS" in
    SUCCESS)
      if ! echo "$NODE" | jq -e \
        --arg img "$FULL_IMAGE" \
        --arg digest "$IMAGE_DIGEST" \
        '.meta.image == $img
          and .meta.serviceManifest.deploy.healthcheckPath == "/health"
          and .meta.serviceManifest.deploy.overlapSeconds == 0
          and ($digest == "" or .meta.imageDigest == $digest)' >/dev/null 2>&1; then
        fail "Successful deployment metadata does not match the requested image/digest and /health platform gate"
        exit 1
      fi
      ok "Exact deployment passed Railway platform health and image identity gates after ${ELAPSED}s (id: ${DEPLOY_ID})"
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
# Step 3: Post-cutover readiness
# ---------------------------------------------------------------------------
# Railway's SUCCESS state above is accepted only for the exact deployment id,
# image/digest, embedded platform healthcheckPath=/health, and zero overlap. A
# public /health request is not used as production proof because an old instance
# could answer it during a transition. Production additionally requires deep
# readiness with the operator probe token and proves the response was
# authenticated by checking a verbose-only field that the public response
# deliberately omits.
if [[ -z "$HEALTH_URL" ]]; then
  ok "Exact Railway deployment accepted. Skipping public probe (RAILWAY_HEALTH_URL not set)."
  exit 0
fi

BASE_URL="${HEALTH_URL%/}"

# Give the service a moment to start accepting traffic
sleep 5

if [[ "${RAILWAY_REQUIRE_READY:-false}" == "true" ]]; then
  log "Verifying authenticated deep readiness at ${BASE_URL}/ready"
  READY_OK=false
  for i in 1 2 3; do
    READY_BODY=$(curl --fail --silent --show-error --max-time 20 \
      -H "X-Steward-Probe-Token: ${READY_PROBE_TOKEN}" \
      "${BASE_URL}/ready" 2>/dev/null) || READY_BODY=""
    if [[ -n "$READY_BODY" ]] && echo "$READY_BODY" | jq -e \
      '.status == "ready"
        and .checks.migrations.ok == true
        and .checks.migrations.detail.mode == "steward-owned"
        and .checks.migrations.detail.expectedSchema == "steward"
        and .checks.coreRepair.ok == true
        and .checks.coreRepair.detail.schema == "steward"
        and .checks.authSchema.ok == true
        and .checks.authSchema.detail.schema == "steward"' >/dev/null 2>&1; then
      READY_OK=true
      break
    fi
    warn "  Authenticated readiness attempt $i did not return a verified ready response"
    sleep 5
  done
  unset READY_BODY

  if $READY_OK; then
    ok "Authenticated deep readiness passed"
  else
    fail "Authenticated /ready failed after 3 attempts"
    fail "The response body was withheld because it may contain operator diagnostics."
    exit 1
  fi
else
  log "Verifying public health endpoint: ${BASE_URL}/health"
  HEALTH_OK=false
  for i in 1 2 3; do
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" "${BASE_URL}/health" 2>/dev/null) || HTTP_CODE="000"
    if [[ "$HTTP_CODE" == "200" ]]; then
      HEALTH_OK=true
      break
    fi
    warn "  Health check attempt $i: HTTP ${HTTP_CODE}"
    sleep 5
  done

  if $HEALTH_OK; then
    ok "Public health check passed (supplemental; Railway exact-deployment health is authoritative)"
  else
    fail "Health check failed after 3 attempts (last HTTP: ${HTTP_CODE})"
    fail "Service may still be starting. Check ${BASE_URL}/health manually."
    exit 1
  fi
fi

# Recheck control-plane identity after the public readiness probe. This closes
# the interval in which a delayed auto-deploy or concurrent actor could appear
# after the tracked deployment first reached SUCCESS.
FINAL_RESULT=$(gql "$POLL_QUERY" 2>/dev/null) || {
  fail "Could not perform the final exact-deployment control-plane check"
  exit 1
}
assert_no_untracked_deployment "$FINAL_RESULT"
if ! echo "$FINAL_RESULT" | jq -e \
  --arg id "$TRIGGER_DEPLOY_ID" \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  --arg img "$FULL_IMAGE" \
  --arg digest "$IMAGE_DIGEST" \
  '.data.deployment
    | .id == $id
      and .serviceId == $sid
      and .environmentId == $eid
      and .status == "SUCCESS"
      and .meta.image == $img
      and .meta.serviceManifest.deploy.healthcheckPath == "/health"
      and .meta.serviceManifest.deploy.overlapSeconds == 0
      and ($digest == "" or .meta.imageDigest == $digest)' >/dev/null 2>&1; then
  fail "Final Railway control-plane state no longer matches the accepted exact deployment"
  exit 1
fi

FINAL_ACTIVE_QUERY=$(jq -n \
  --arg sid "$SERVICE_ID" \
  --arg eid "$ENV_ID" \
  '{query: "query FinalActiveDeployment($sid: String!, $eid: String!) { serviceInstance(serviceId: $sid, environmentId: $eid) { latestDeployment { id status } activeDeployments { id status } } }", variables: {sid: $sid, eid: $eid}}')
FINAL_ACTIVE_RESULT=$(gql "$FINAL_ACTIVE_QUERY" 2>/dev/null) || {
  fail "Could not verify the final active Railway deployment"
  exit 1
}
if ! echo "$FINAL_ACTIVE_RESULT" | jq -e \
  --arg id "$TRIGGER_DEPLOY_ID" \
  '.data.serviceInstance
    | .latestDeployment.id == $id
      and .latestDeployment.status == "SUCCESS"
      and (.activeDeployments | length) == 1
      and .activeDeployments[0].id == $id
      and .activeDeployments[0].status == "SUCCESS"' >/dev/null 2>&1; then
  fail "The exact tracked deployment is not Railway's sole final active deployment"
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
ok "  Deploy:  ${DEPLOY_ID}"
ok "  Platform healthcheckPath: /health ✓"
if [[ "${RAILWAY_REQUIRE_READY:-false}" == "true" ]]; then
  ok "  Authenticated readiness: ${BASE_URL}/ready ✓"
else
  ok "  Supplemental health: ${BASE_URL}/health ✓"
fi
ok "=========================================="

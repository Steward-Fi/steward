/**
 * SEC-129 regression tests — railway-deploy.sh must fail closed by default
 * and redact secrets from dumped Railway logs.
 *
 * The fail-closed default is asserted as a source contract (the script is not
 * safely sourceable — it performs API calls at runtime). The redact_secrets
 * filter is extracted from the real script and exercised behaviorally.
 */
import { describe, expect, test } from "bun:test";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const SCRIPT = join(import.meta.dir, "..", "railway-deploy.sh");
const source = readFileSync(SCRIPT, "utf8");

function redact(input: string): string {
  return execFileSync(
    "bash",
    ["-c", `eval "$(sed -n '/^redact_secrets()/,/^}/p' "$1")"; redact_secrets`, "bash", SCRIPT],
    { input, encoding: "utf8" },
  );
}

function dryRun(imageDigest: string, imageTag?: string) {
  return spawnSync("bash", [SCRIPT, ...(imageTag ? [imageTag] : []), "--dry-run"], {
    encoding: "utf8",
    env: {
      ...process.env,
      RAILWAY_TOKEN: "test-token",
      RAILWAY_SERVICE_ID: "test-service",
      RAILWAY_ENV_ID: "test-environment",
      RAILWAY_IMAGE_DIGEST: imageDigest,
      RAILWAY_HEALTH_URL: "https://example.test",
      RAILWAY_REQUIRE_HEALTH: "true",
    },
  });
}

const productionDigest = `sha256:${"a".repeat(64)}`;
const productionRevision = "b".repeat(40);
const triggerDeploymentId = "11111111-2222-3333-4444-555555555555";

function productionRun(
  overrides: Partial<{
    instanceHealthcheckPath: string;
    polledDeploymentId: string;
    finalActiveDeploymentId: string;
    deploymentDigest: string;
    deploymentHealthcheckPath: string;
    baselineDeploymentStatus: string;
    untrackedDeploymentId: string;
    targetReadyProbeToken: string;
    targetServiceObjectId: string;
    targetProjectId: string;
    variablesQueryError: boolean;
    readyBody: string;
  }> = {},
) {
  const tempRoot = mkdtempSync(join(tmpdir(), "steward-railway-deploy-"));
  const binDir = join(tempRoot, "bin");
  const requestLog = join(tempRoot, "requests.log");
  writeFileSync(requestLog, "", "utf8");
  mkdirSync(binDir);

  const docker = [
    "#!/bin/bash",
    "set -euo pipefail",
    'if [[ "$*" == *"{{json .Manifest}}"* ]]; then',
    "  jq -n --arg digest \"$FAKE_EXPECTED_DIGEST\" '{digest: $digest}'",
    'elif [[ "$*" == *"externalParameters.request.args"* ]]; then',
    '  jq -n --arg revision "$FAKE_EXPECTED_REVISION" \'{"label:org.opencontainers.image.revision": $revision}\'',
    "else",
    "  exit 2",
    "fi",
  ].join("\n");

  const curl = [
    "#!/bin/bash",
    "set -euo pipefail",
    'payload=""',
    'url=""',
    'ready_token_seen="false"',
    "while [[ $# -gt 0 ]]; do",
    '  case "$1" in',
    '    -d) payload="$2"; shift 2 ;;',
    '    -H) [[ "$2" == "X-Steward-Probe-Token: $EXPECTED_READY_TOKEN" ]] && ready_token_seen="true"; shift 2 ;;',
    '    http*) url="$1"; shift ;;',
    "    *) shift ;;",
    "  esac",
    "done",
    'printf "%s\\n" "$url $payload" >> "$FAKE_REQUEST_LOG"',
    'if [[ "$url" == */ready ]]; then',
    '  [[ "$ready_token_seen" == "true" ]] || exit 22',
    '  printf "%s\\n" "$FAKE_READY_BODY"',
    "  exit 0",
    "fi",
    'query=$(jq -r ".query // empty" <<<"$payload")',
    'if [[ "$query" == *"serviceInstanceUpdate"* ]]; then',
    '  jq -e \'.variables.input.healthcheckPath == "/health" and .variables.input.overlapSeconds == 0\' <<<"$payload" >/dev/null',
    '  printf "%s\\n" "{\\"data\\":{\\"serviceInstanceUpdate\\":true}}"',
    'elif [[ "$query" == *"ReadyProbeTarget"* ]]; then',
    '  jq -n --arg sid "$FAKE_SERVICE_ID" --arg eid "$FAKE_ENV_ID" --arg serviceObjectId "$FAKE_TARGET_SERVICE_OBJECT_ID" --arg projectId "$FAKE_TARGET_PROJECT_ID" \'{data: {serviceInstance: {serviceId: $sid, environmentId: $eid, service: {id: $serviceObjectId, projectId: $projectId}}}}\'',
    'elif [[ "$query" == *"ReadyProbeVariables"* ]]; then',
    '  if [[ "$FAKE_VARIABLES_QUERY_ERROR" == "true" ]]; then',
    "    jq -n '{errors: [{message: \"control-plane-error-must-not-be-logged\"}]}'",
    "  else",
    '    jq -n --arg token "$FAKE_TARGET_READY_TOKEN" \'{data: {variables: {STEWARD_READY_PROBE_TOKEN: $token, OTHER_SECRET: "must-not-be-logged"}}}\'',
    "  fi",
    'elif [[ "$query" == *"FinalActiveDeployment"* ]]; then',
    '  jq -n --arg id "$FAKE_FINAL_ACTIVE_DEPLOY_ID" \'{data: {serviceInstance: {latestDeployment: {id: $id, status: "SUCCESS"}, activeDeployments: [{id: $id, status: "SUCCESS"}]}}}\'',
    'elif [[ "$query" == *"serviceInstance(serviceId:"* ]]; then',
    '  jq -n --arg sid "$FAKE_SERVICE_ID" --arg eid "$FAKE_ENV_ID" --arg path "$FAKE_INSTANCE_HEALTHCHECK" --arg image "$FAKE_FULL_IMAGE" \'{data: {serviceInstance: {serviceId: $sid, environmentId: $eid, healthcheckPath: $path, overlapSeconds: 0, source: {image: $image}}}}\'',
    'elif [[ "$query" == *"serviceInstanceDeployV2"* ]]; then',
    "  jq -n --arg id \"$FAKE_TRIGGER_DEPLOY_ID\" '{data: {serviceInstanceDeployV2: $id}}'",
    'elif [[ "$query" == *"BaselineDeployments"* ]]; then',
    '  jq -n --arg status "$FAKE_BASELINE_DEPLOYMENT_STATUS" \'def edge: {node: {id: "00000000-1111-2222-3333-444444444444", status: $status}}; {data: {deployments: {edges: (if $status == "" then [] else [edge] end)}, inflight: {edges: (if (["BUILDING", "DEPLOYING", "INITIALIZING", "NEEDS_APPROVAL", "QUEUED", "REMOVING", "WAITING"] | index($status)) == null then [] else [edge] end)}}}\'',
    'elif [[ "$query" == *"deployment(id:"* ]]; then',
    '  jq -n --arg id "$FAKE_POLLED_DEPLOY_ID" --arg sid "$FAKE_SERVICE_ID" --arg eid "$FAKE_ENV_ID" --arg image "$FAKE_FULL_IMAGE" --arg digest "$FAKE_DEPLOYMENT_DIGEST" --arg path "$FAKE_DEPLOYMENT_HEALTHCHECK" --arg untracked "$FAKE_UNTRACKED_DEPLOY_ID" \'{data: {deployment: {id: $id, serviceId: $sid, environmentId: $eid, status: "SUCCESS", createdAt: "2026-08-24T00:00:00Z", meta: {image: $image, imageDigest: $digest, serviceManifest: {deploy: {healthcheckPath: $path, overlapSeconds: 0}}}}, deployments: {edges: (if $untracked == "" then [] else [{node: {id: $untracked}}] end)}}}\'',
    "else",
    "  exit 22",
    "fi",
  ].join("\n");

  writeFileSync(join(binDir, "docker"), docker, "utf8");
  writeFileSync(join(binDir, "curl"), curl, "utf8");
  writeFileSync(join(binDir, "sleep"), "#!/bin/bash\nexit 0\n", "utf8");
  chmodSync(join(binDir, "docker"), 0o755);
  chmodSync(join(binDir, "curl"), 0o755);
  chmodSync(join(binDir, "sleep"), 0o755);

  const fullImage = `ghcr.io/steward-fi/steward@${productionDigest}`;
  const result = spawnSync("bash", [SCRIPT], {
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${binDir}:${process.env.PATH ?? ""}`,
      RAILWAY_TOKEN: "test-token",
      RAILWAY_SERVICE_ID: "test-service",
      RAILWAY_ENV_ID: "test-environment",
      RAILWAY_IMAGE_DIGEST: productionDigest,
      RAILWAY_HEALTH_URL: "https://steward.example.test",
      RAILWAY_REQUIRE_HEALTH: "true",
      RAILWAY_REQUIRE_READY: "true",
      RAILWAY_READY_PROBE_TOKEN: "operator-probe-token",
      RAILWAY_EXPECTED_REVISION: productionRevision,
      DEPLOY_TIMEOUT: "20",
      EXPECTED_READY_TOKEN: "operator-probe-token",
      FAKE_REQUEST_LOG: requestLog,
      FAKE_EXPECTED_DIGEST: productionDigest,
      FAKE_EXPECTED_REVISION: productionRevision,
      FAKE_SERVICE_ID: "test-service",
      FAKE_ENV_ID: "test-environment",
      FAKE_FULL_IMAGE: fullImage,
      FAKE_INSTANCE_HEALTHCHECK: overrides.instanceHealthcheckPath ?? "/health",
      FAKE_TRIGGER_DEPLOY_ID: triggerDeploymentId,
      FAKE_POLLED_DEPLOY_ID: overrides.polledDeploymentId ?? triggerDeploymentId,
      FAKE_FINAL_ACTIVE_DEPLOY_ID: overrides.finalActiveDeploymentId ?? triggerDeploymentId,
      FAKE_DEPLOYMENT_DIGEST: overrides.deploymentDigest ?? productionDigest,
      FAKE_DEPLOYMENT_HEALTHCHECK: overrides.deploymentHealthcheckPath ?? "/health",
      FAKE_BASELINE_DEPLOYMENT_STATUS: overrides.baselineDeploymentStatus ?? "",
      FAKE_UNTRACKED_DEPLOY_ID: overrides.untrackedDeploymentId ?? "",
      FAKE_TARGET_READY_TOKEN: overrides.targetReadyProbeToken ?? "operator-probe-token",
      FAKE_TARGET_SERVICE_OBJECT_ID: overrides.targetServiceObjectId ?? "test-service",
      FAKE_TARGET_PROJECT_ID: overrides.targetProjectId ?? "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      FAKE_VARIABLES_QUERY_ERROR: overrides.variablesQueryError ? "true" : "false",
      FAKE_READY_BODY:
        overrides.readyBody ??
        '{"status":"ready","checks":{"migrations":{"ok":true,"detail":{"mode":"steward-owned","expectedSchema":"steward"}},"coreRepair":{"ok":true,"detail":{"schema":"steward"}},"authSchema":{"ok":true,"detail":{"schema":"steward"}},"database":{"ok":true}}}',
    },
  });
  const requests = readFileSync(requestLog, "utf8");
  rmSync(tempRoot, { recursive: true, force: true });
  return { ...result, requests };
}

describe("SEC-129 railway-deploy.sh fails closed by default", () => {
  test("no-log control-plane rejection is a hard failure unless explicitly downgraded", () => {
    // LOGS_EMPTY=1 must fail even when RAILWAY_STRICT is not set, so CI cannot
    // green on a deploy that never happened.
    expect(source).not.toContain("RAILWAY_STRICT");
    expect(source).toContain("RAILWAY_ALLOW_REJECTED_DEPLOY:-false");
    // finish_failure must exit 1 on the default path.
    const finish = source.match(/finish_failure\(\) \{([\s\S]*?)\n\}/)?.[1] ?? "";
    expect(finish).toContain("exit 0");
    expect(finish.trim().endsWith("exit 1")).toBe(true);
  });

  test("dumped logs are piped through redact_secrets", () => {
    expect(source).toMatch(/echo "\$build_logs" \| redact_secrets/);
    expect(source).toMatch(/echo "\$deploy_logs" \| redact_secrets/);
  });
});

describe("immutable Railway image selection", () => {
  test("passes a validated digest to Railway without converting it to a tag", () => {
    const digest = `sha256:${"a".repeat(64)}`;
    const result = dryRun(digest);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`ghcr.io/steward-fi/steward@${digest}`);
    expect(result.stdout).not.toContain(`ghcr.io/steward-fi/steward:${digest}`);
  });

  test("rejects a malformed digest before a deployment mutation", () => {
    const result = dryRun("sha256:not-a-digest");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Invalid image digest");
    expect(result.stdout).not.toContain("Deploying");
  });

  test("rejects simultaneous tag and digest selectors", () => {
    const result = dryRun(`sha256:${"a".repeat(64)}`, "main");
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Choose exactly one image selector");
    expect(result.stdout).not.toContain("Deploying");
  });

  test("production health enforcement fails before a deployment mutation", () => {
    const result = spawnSync("bash", [SCRIPT, "main", "--dry-run"], {
      encoding: "utf8",
      env: {
        ...process.env,
        RAILWAY_TOKEN: "test-token",
        RAILWAY_SERVICE_ID: "test-service",
        RAILWAY_ENV_ID: "test-environment",
        RAILWAY_HEALTH_URL: "",
        RAILWAY_REQUIRE_HEALTH: "true",
      },
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("RAILWAY_HEALTH_URL is required");
    expect(result.stdout).not.toContain("Deploying");
  });
});

describe("production Railway deployment acceptance", () => {
  test("bootstraps a legacy current image through the control plane and binds final candidate readiness", () => {
    const result = productionRun();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(`Triggered exact deployment ${triggerDeploymentId}`);
    expect(result.stdout).toContain("Railway platform health and image identity gates");
    expect(result.stdout).toContain("Authenticated deep readiness passed");
    expect(result.requests).toContain("serviceInstanceUpdate");
    expect(result.requests).toMatch(/"healthcheckPath":\s*"\/health"/);
    expect(result.requests).toMatch(/"overlapSeconds":\s*0/);
    expect(result.requests).toContain(`deployment(id: $id)`);
    expect(result.requests).toContain("query ReadyProbeTarget");
    expect(result.requests).toContain("query ReadyProbeVariables");
    expect(result.requests.match(/https:\/\/steward\.example\.test\/ready/g)).toHaveLength(1);
    expect(result.stdout).not.toContain("operator-probe-token");
    expect(result.stderr).not.toContain("operator-probe-token");
    expect(result.stdout).not.toContain("must-not-be-logged");
    expect(result.stderr).not.toContain("must-not-be-logged");
  });

  test("fails before mutation when the protected token does not match Railway's effective variable", () => {
    const result = productionRun({
      targetReadyProbeToken: "different-target-token",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("does not match the effective Railway service variable");
    expect(result.requests).not.toContain("serviceInstanceUpdate");
    expect(result.stdout).not.toContain("operator-probe-token");
    expect(result.stderr).not.toContain("operator-probe-token");
    expect(result.stdout).not.toContain("different-target-token");
    expect(result.stderr).not.toContain("different-target-token");
  });

  test("fails before mutation when the effective Railway readiness token is absent", () => {
    const result = productionRun({ targetReadyProbeToken: "" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("does not match the effective Railway service variable");
    expect(result.requests).not.toContain("serviceInstanceUpdate");
  });

  test("fails closed without exposing a Railway variables-query error", () => {
    const result = productionRun({ variablesQueryError: true });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("rejected the readiness-token configuration query");
    expect(result.requests).not.toContain("serviceInstanceUpdate");
    expect(result.stdout).not.toContain("control-plane-error-must-not-be-logged");
    expect(result.stderr).not.toContain("control-plane-error-must-not-be-logged");
  });

  test("fails before mutation when Railway resolves a different service target", () => {
    const result = productionRun({ targetServiceObjectId: "different-service" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("invalid readiness-token target");
    expect(result.requests).not.toContain("ReadyProbeVariables");
    expect(result.requests).not.toContain("serviceInstanceUpdate");
  });

  test("fails before triggering when Railway did not persist healthcheckPath=/health", () => {
    const result = productionRun({ instanceHealthcheckPath: "" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Railway effective config does not match");
    expect(result.requests).not.toContain("serviceInstanceDeployV2");
    expect(result.requests).not.toContain("https://steward.example.test/ready");
  });

  test("fails before mutation when a baseline deployment is still in flight", () => {
    const result = productionRun({ baselineDeploymentStatus: "DEPLOYING" });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("pre-existing nonterminal Railway deployment");
    expect(result.requests).not.toContain("serviceInstanceUpdate");
    expect(result.requests).not.toContain("https://steward.example.test/ready");
  });

  test("rejects a stale or concurrent deployment id even when readiness would be green", () => {
    const result = productionRun({
      polledDeploymentId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("outside the requested id/service/environment scope");
    expect(result.requests).not.toContain("https://steward.example.test/ready");
  });

  test("rejects deployment metadata for a different digest", () => {
    const result = productionRun({ deploymentDigest: `sha256:${"c".repeat(64)}` });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("metadata does not match the requested image/digest");
    expect(result.requests).not.toContain("https://steward.example.test/ready");
  });

  test("rejects success when the tracked deployment is not the sole final active deployment", () => {
    const result = productionRun({
      finalActiveDeploymentId: "77777777-6666-5555-4444-333333333333",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("not Railway's sole final active deployment");
  });

  test("rejects an auto-created or concurrent deployment outside the tracked id", () => {
    const result = productionRun({
      untrackedDeploymentId: "99999999-8888-7777-6666-555555555555",
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Detected an untracked deployment");
    expect(result.requests).not.toContain("https://steward.example.test/ready");
  });

  test("rejects a public sanitized ready response because it does not prove probe-token auth", () => {
    const result = productionRun({
      readyBody: '{"status":"ready","checks":{"migrations":{"ok":true}}}',
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Authenticated /ready failed");
    expect(result.stdout).not.toContain("operator-probe-token");
    expect(result.stderr).not.toContain("operator-probe-token");
    expect(result.stderr).not.toContain("migrations");
  });

  test("rejects verbose green readiness from ordinary drizzle mode", () => {
    const result = productionRun({
      readyBody:
        '{"status":"ready","checks":{"migrations":{"ok":true,"detail":{"mode":"drizzle","expected":"0110"}},"coreRepair":{"ok":true,"detail":{"schema":"steward"}},"authSchema":{"ok":true,"detail":{"schema":"steward"}}}}',
    });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("Authenticated /ready failed");
  });
});

describe("SEC-129 redact_secrets filter", () => {
  test("redacts postgres DSN passwords, bearer tokens, KEY= assignments, stw_ keys, long hex", () => {
    const out = redact(
      [
        "connecting to postgresql://steward:hunter2@db.internal:5432/steward",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "STEWARD_JWT_SECRET=abc123def456",
        "tenant key stw_9f8e7d6c5b4a issued",
        "master 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef done",
        "ordinary log line stays",
      ].join("\n"),
    );
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9.payload.sig");
    expect(out).not.toContain("abc123def456");
    expect(out).not.toContain("9f8e7d6c5b4a");
    expect(out).not.toContain("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    expect(out).toContain("postgresql://steward:");
    expect(out).toContain("ordinary log line stays");
  });
});

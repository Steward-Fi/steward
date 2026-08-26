import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "../..");
const workflow = readFileSync(resolve(repoRoot, ".github/workflows/deploy-railway.yml"), "utf8");
const railwayConfig = JSON.parse(readFileSync(resolve(repoRoot, "railway.json"), "utf8"));
const deployScript = readFileSync(resolve(repoRoot, "scripts/railway-deploy.sh"), "utf8");

describe("production deploy policy", () => {
  test("accepts only a full main commit and verifies its exact main Docker build", () => {
    expect(workflow).toContain("main_sha:");
    expect(workflow).not.toContain("image_tag:");
    expect(workflow).not.toContain("workflow_call:");
    expect(workflow).toContain("^[0-9a-f]{40}$");
    expect(workflow).toContain('git merge-base --is-ancestor "$MAIN_SHA" refs/remotes/origin/main');
    expect(workflow).toContain("actions/workflows/docker.yml/runs");
    expect(workflow).toContain("-f branch=main");
    expect(workflow).toContain('-f head_sha="$MAIN_SHA"');
    expect(workflow).toContain("-f event=push");
    expect(workflow).toContain("-f status=success");
    expect(workflow).toContain("label:org.opencontainers.image.revision");
    expect(workflow).toContain('"$VERSION" != "main"');
    expect(workflow).toContain('"$SOURCE" != "https://github.com/${TARGET_REPOSITORY}"');
  });

  test("resolves and passes an immutable digest to Railway", () => {
    expect(workflow).toContain('"${IMAGE_REPO}:sha-${MAIN_SHA}"');
    expect(workflow).toContain('test("^sha256:[0-9a-f]{64}$")');
    expect(workflow).toContain("RAILWAY_IMAGE_DIGEST: ${{ steps.resolve.outputs.digest }}");
    expect(workflow).not.toContain("RESOLVED_TAG");
  });

  test("ships a Railway platform health gate", () => {
    expect(railwayConfig.deploy.healthcheckPath).toBe("/health");
    expect(railwayConfig.deploy.healthcheckTimeout).toBeGreaterThanOrEqual(45);
    expect(workflow).toContain('RAILWAY_REQUIRE_HEALTH: "true"');
    expect(workflow).toContain('RAILWAY_REQUIRE_READY: "true"');
    expect(workflow).toContain(
      "RAILWAY_READY_PROBE_TOKEN: ${{ secrets.STEWARD_READY_PROBE_TOKEN }}",
    );
    expect(workflow).toContain("RAILWAY_EXPECTED_REVISION: ${{ steps.resolve.outputs.sha }}");
    expect(deployScript).toContain('RAILWAY_REQUIRE_HEALTH:-false}" == "true"');
    expect(deployScript).toContain("RAILWAY_HEALTH_URL is required");
    expect(deployScript).toContain('healthcheckPath: "/health"');
    expect(deployScript).toContain('.healthcheckPath == "/health"');
    expect(deployScript).toContain("overlapSeconds: 0");
    expect(deployScript).toContain(".overlapSeconds == 0");
    expect(deployScript).toContain("query ReadyProbeTarget");
    expect(deployScript).toContain("query ReadyProbeVariables");
    expect(deployScript).toContain("unrendered: false");
    expect(deployScript).toContain(".data.variables.STEWARD_READY_PROBE_TOKEN");
    expect(deployScript).toContain('"$TARGET_READY_PROBE_TOKEN" != "$READY_PROBE_TOKEN"');
    expect(deployScript).toContain("X-Steward-Probe-Token: ${READY_PROBE_TOKEN}");
    expect(deployScript).not.toContain("X-Steward-Probe-Purpose: deployment-preflight");
    expect(deployScript).toContain(
      "Protected readiness token matches the exact Railway service/environment configuration",
    );
    expect(deployScript).toContain('.checks.migrations.detail.mode == "steward-owned"');
    expect(deployScript).toContain('.checks.migrations.detail.expectedSchema == "steward"');
    expect(deployScript).toContain('.checks.coreRepair.detail.schema == "steward"');
    expect(deployScript).toContain('.checks.authSchema.detail.schema == "steward"');
  });

  test("accepts only the exact Railway deployment id and immutable image identity", () => {
    expect(deployScript).toContain("serviceInstanceDeployV2");
    expect(deployScript).toContain(
      "query TrackedDeployment($id: String!, $input: DeploymentListInput!)",
    );
    expect(deployScript).toContain(
      "query BaselineDeployments($input: DeploymentListInput!, $inflightInput: DeploymentListInput!)",
    );
    expect(deployScript).toContain("A pre-existing nonterminal Railway deployment");
    expect(deployScript).toContain("Detected an untracked deployment");
    expect(deployScript).toContain("query FinalActiveDeployment");
    expect(deployScript).toContain("(.activeDeployments | length) == 1");
    expect(deployScript).toContain(".id == $id and .serviceId == $sid");
    expect(deployScript).toContain(".meta.image == $img");
    expect(deployScript).toContain(".meta.imageDigest == $digest");
    expect(deployScript).toContain('.meta.serviceManifest.deploy.healthcheckPath == "/health"');
    expect(deployScript).toContain(".meta.serviceManifest.deploy.overlapSeconds == 0");
  });

  test("does not create or mark a GitHub Production deployment during dry run", () => {
    expect(workflow).toMatch(
      /- name: Create GitHub deployment\n\s+if: \$\{\{ inputs\.dry_run == false \}\}/,
    );
    expect(workflow).toMatch(
      /- name: Update deployment status \(success\)\n\s+if: \$\{\{ inputs\.dry_run == false && success\(\) \}\}/,
    );
    expect(workflow).toMatch(
      /- name: Update deployment status \(failure\)\n\s+if: \$\{\{ inputs\.dry_run == false && failure\(\) && steps\.deployment\.outputs\.deployment_id != '' \}\}/,
    );
  });
});

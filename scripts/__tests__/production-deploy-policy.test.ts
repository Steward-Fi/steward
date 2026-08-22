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
    expect(deployScript).toContain('RAILWAY_REQUIRE_HEALTH:-false}" == "true"');
    expect(deployScript).toContain("RAILWAY_HEALTH_URL is required");
  });
});

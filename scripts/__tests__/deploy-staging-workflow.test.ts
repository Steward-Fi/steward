import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const workflowPath = resolve(import.meta.dir, "../../.github/workflows/deploy-staging.yml");

describe("staging deployment workflow", () => {
  test("releases the exact-SHA database before changing the Railway image", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    const release = workflow.indexOf(
      "name: Release staging database and prove old-image compatibility",
    );
    const deployment = workflow.indexOf("name: Create GitHub deployment (staging)");
    const rollout = workflow.indexOf("name: Deploy to Railway staging");
    expect(release).toBeGreaterThan(deployment);
    expect(rollout).toBeGreaterThan(release);
    expect(workflow).toContain("STEWARD_RELEASE_SOURCE_SHA: ${{ steps.resolve.outputs.sha }}");
    expect(workflow).toContain("tag=sha-${TARGET_SHA}");
    expect(workflow).toContain('RAILWAY_REQUIRE_DIRECT_HEALTH: "true"');
  });

  test("uses the protected staging environment and has no mutable manual bypass", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    expect(workflow).toMatch(/^ {4}environment: staging$/m);
    expect(workflow).not.toContain("inputs.image_tag");
    expect(workflow).not.toContain("DISPATCH_TAG");
  });

  test("binds release verification to Railway's rendered application database", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    expect(workflow).toContain("vars.STAGING_RAILWAY_PROJECT_ID");
    expect(workflow).toContain("vars.STAGING_RAILWAY_SERVICE_ID");
    expect(workflow).toContain("vars.STAGING_RAILWAY_ENV_ID");
    expect(workflow).toContain("secrets.RAILWAY_TOKEN");
    expect(workflow).not.toContain("STAGING_APP_DATABASE_URL");
    const releaseStep = workflow.slice(
      workflow.indexOf("name: Release staging database"),
      workflow.indexOf("name: Deploy to Railway staging"),
    );
    expect(releaseStep).not.toContain("continue-on-error");
  });
});

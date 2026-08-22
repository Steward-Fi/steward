import { describe, expect, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const workflowPath = resolve(import.meta.dir, "../../.github/workflows/deploy-staging.yml");

describe("staging deployment workflow", () => {
  test("releases the exact-SHA database before changing the Railway image", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    const release = workflow.indexOf("name: Release staging database");
    const deployment = workflow.indexOf("name: Create GitHub deployment (staging)");
    const rollout = workflow.indexOf("name: Deploy to Railway staging");
    expect(release).toBeGreaterThan(0);
    expect(deployment).toBeGreaterThan(0);
    expect(release).toBeGreaterThan(deployment);
    expect(rollout).toBeGreaterThan(release);
    expect(workflow).toContain("STEWARD_RELEASE_SOURCE_SHA: ${{ steps.resolve.outputs.sha }}");
    expect(workflow).toContain("tag=sha-${TARGET_SHA}");
    expect(workflow).toContain('RAILWAY_REQUIRE_DIRECT_HEALTH: "true"');
  });

  test("uses the protected staging environment and has no mutable manual image bypass", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    expect(workflow).toMatch(/^ {4}environment: staging$/m);
    expect(workflow).not.toContain("inputs.image_tag");
    expect(workflow).not.toContain("DISPATCH_TAG");
  });

  test("keeps privileged URLs in release-only secrets", async () => {
    const workflow = await readFile(workflowPath, "utf8");
    expect(workflow).toContain("secrets.STAGING_MIGRATION_DATABASE_URL");
    expect(workflow).toContain("secrets.STAGING_OPERATOR_DATABASE_URL");
    expect(workflow).toContain("secrets.STAGING_APP_DATABASE_URL");
    expect(workflow).toContain("vars.STAGING_OPERATOR_DATABASE_ROLE");
    const deployStep = workflow.slice(workflow.indexOf("name: Deploy to Railway staging"));
    expect(deployStep).not.toContain("STAGING_MIGRATION_DATABASE_URL");
    expect(deployStep).not.toContain("STAGING_OPERATOR_DATABASE_URL");
  });
});

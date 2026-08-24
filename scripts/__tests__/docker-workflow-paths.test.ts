/**
 * Responsibility: keep the required pull-request Docker build eligible for
 * every source or configuration input copied into the Steward API image.
 *
 * The main branch requires the build-and-push check. A narrower path filter can
 * leave source-only release PRs permanently blocked without ever building the
 * candidate image, so this test protects the complete Docker context boundary.
 */
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const WORKFLOW = join(import.meta.dir, "..", "..", ".github", "workflows", "docker.yml");
const source = readFileSync(WORKFLOW, "utf8");
const pullRequestTrigger =
  source.match(/ {2}pull_request:\n([\s\S]*?)(?=\n\n# A branch tag is mutable)/)?.[1] ?? "";

describe("Docker pull-request path coverage", () => {
  test("includes every root configuration input copied by the Dockerfile", () => {
    for (const path of [
      "Dockerfile",
      ".dockerignore",
      "package.json",
      "bun.lock",
      "turbo.json",
      "tsconfig.json",
      "web/package.json",
    ]) {
      expect(pullRequestTrigger).toContain(`- "${path}"`);
    }
  });

  test("builds for source-only package changes and workflow changes", () => {
    expect(pullRequestTrigger).toContain('- "packages/**"');
    expect(pullRequestTrigger).toContain('- ".github/workflows/docker.yml"');
    expect(pullRequestTrigger).not.toContain('- "packages/**/package.json"');
  });
});

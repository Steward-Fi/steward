import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const repoRoot = join(import.meta.dir, "..", "..");

function readScript(name: string): string {
  return readFileSync(join(repoRoot, "scripts", name), "utf8");
}

describe("SEC-201 mutation-proof temporary-file cleanup", () => {
  test("custody proof never restores from an uninitialized backup", () => {
    const script = readScript("custody-ack-gate-mutation-proofs.sh");
    expect(script.indexOf("trap cleanup EXIT")).toBeLessThan(script.indexOf('BACKUP="$(mktemp)"'));
    expect(script.indexOf("BACKUP_READY=true")).toBeGreaterThan(
      script.indexOf('cp "$FACTORY" "$BACKUP"'),
    );
    expect(script).toContain("if $BACKUP_READY; then");
  });

  test("key-rotation proof arms restoration only after both backups exist", () => {
    const script = readScript("key-rotation-mutation-proofs.sh");
    expect(script.indexOf("trap restore EXIT")).toBeLessThan(
      script.indexOf("rotation_copy=$(mktemp)"),
    );
    expect(script.indexOf("backups_ready=true")).toBeGreaterThan(
      script.indexOf('cp "$auth" "$auth_copy"'),
    );
    expect(script).toContain("if $backups_ready; then");
  });
});

describe("post-merge infrastructure ownership and update policy", () => {
  test("sensitive operational trees have both infrastructure owners", () => {
    const owners = readFileSync(join(repoRoot, ".github", "CODEOWNERS"), "utf8");
    expect(owners).toContain("deploy/ @0xSolace @lalalune");
    expect(owners).toContain("scripts/ @0xSolace @lalalune");
  });

  test("routine action and base-image automation excludes major migrations", () => {
    const dependabot = readFileSync(join(repoRoot, ".github", "dependabot.yml"), "utf8");
    for (const ecosystem of ["github-actions", "docker"]) {
      const start = dependabot.indexOf(`package-ecosystem: "${ecosystem}"`);
      expect(start).toBeGreaterThanOrEqual(0);
      const next = dependabot.indexOf("package-ecosystem:", start + 1);
      const block = dependabot.slice(start, next < 0 ? undefined : next);
      expect(block).toContain('update-types: ["version-update:semver-major"]');
    }
  });
});

import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, normalize } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf8");
}

function doctorRequiredNames(source: string): string[] {
  const block = source.match(/const required = \[([\s\S]*?)\];/)?.[1];
  if (!block) throw new Error("doctor required-secret list was not found");
  return [...block.matchAll(/"([A-Z][A-Z0-9_]*)"/g)].map((match) => match[1]);
}

function composeRequiredNames(source: string): string[] {
  return [...source.matchAll(/\$\{([A-Z][A-Z0-9_]*):\?/g)].map((match) => match[1]);
}

describe("backup/restore documentation contract", () => {
  const runbookPath = "docs/runbooks/backup-restore.md";
  const runbook = read(runbookPath);

  test("mentions every root configuration value required by doctor or Compose", () => {
    const names = new Set([
      ...doctorRequiredNames(read("packages/cli/src/doctor.ts")),
      ...composeRequiredNames(read("docker-compose.yml")),
    ]);

    expect(names.size).toBeGreaterThan(0);
    for (const name of names) {
      expect(runbook, `${name} must be included in out-of-band recovery guidance`).toContain(name);
    }
  });

  test("carries fail-closed recovery warnings for uncertain dispatch and secret loss", () => {
    expect(runbook).toContain("database dump is not a complete Steward backup");
    expect(runbook).toContain("The secrets are not stored in the database");
    expect(runbook).toContain("never blindly\n  retried or reset to `none`");
    expect(runbook).toContain("no exactly-once recovery claim");
    expect(runbook).toContain(
      "A skipped secret,\naudit, nonce, or approval assertion is a failed drill",
    );
  });

  test("is linked from deployment docs and local Markdown links resolve", () => {
    const deployment = read("docs/deployment.md");
    expect(deployment).toContain(
      "[backup, restore, and disaster-recovery runbook](runbooks/backup-restore.md)",
    );

    for (const match of runbook.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
      const target = match[1];
      if (/^(?:https?:|mailto:|#)/.test(target)) continue;
      const path = target.split("#", 1)[0];
      expect(
        existsSync(normalize(join(ROOT, dirname(runbookPath), path))),
        `broken local link in ${runbookPath}: ${target}`,
      ).toBe(true);
    }
  });
});

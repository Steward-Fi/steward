import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");
const CLI_SOURCE = join(REPO_ROOT, "packages", "cli", "src", "index.ts");

describe("steward evidence verify command", () => {
  test("is wired as the dedicated offline verifier wrapper", () => {
    const source = readFileSync(CLI_SOURCE, "utf8");
    expect(source).toContain("steward evidence verify --bundle bundle.json [--fp HEX]");
    expect(source).toContain("async function evidenceCommand");
    expect(source).toContain('if (action !== "verify")');
    expect(source).toContain("scripts/verify-evidence-bundle.mjs");
    expect(source).toContain("evidence: evidenceCommand");
  });
});

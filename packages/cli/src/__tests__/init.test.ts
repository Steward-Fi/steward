import { describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInit } from "../init";

describe("steward init", () => {
  test("writes supported audit signing key material", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      const result = runInit({ envPath });
      const env = readFileSync(envPath, "utf8");

      expect(result.auditSigningKeyFormat).toBe("hex-seed");
      expect(env).toContain("STEWARD_AUDIT_SIGNING_KEY=");
      expect(env).toMatch(/STEWARD_AUDIT_SIGNING_KEY=[0-9a-f]{64}/);
      expect(env).toContain("platform:tenant:create");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

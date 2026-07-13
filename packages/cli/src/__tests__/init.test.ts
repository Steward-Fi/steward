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
      // Auth placeholders emitted for symmetry so operators can fill them in.
      expect(env).toContain("STEWARD_TENANT_ID=");
      expect(env).toContain("STEWARD_TOKEN=");
      expect(env).toContain("STEWARD_TENANT_KEY=");
      // Defaults must target the enterprise-reference compose network, not host
      // loopback, or compose's postgres:5432 fallback is silently overridden.
      expect(env).toContain(
        "DATABASE_URL=postgresql://steward:steward-change-me@postgres:5432/steward",
      );
      expect(env).toContain("REDIS_URL=redis://redis:6379");
      expect(env).not.toContain("127.0.0.1:5432");
      expect(env).not.toContain("http://127.0.0.1:3200");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("honors --database-url and --api-url overrides", () => {
    const dir = mkdtempSync(join(tmpdir(), "steward-cli-"));
    try {
      const envPath = join(dir, ".env");
      runInit({
        envPath,
        databaseUrl: "postgresql://u:p@db.internal:5432/steward",
        apiUrl: "http://127.0.0.1:3200",
      });
      const env = readFileSync(envPath, "utf8");
      expect(env).toContain("DATABASE_URL=postgresql://u:p@db.internal:5432/steward");
      expect(env).toContain("STEWARD_API_URL=http://127.0.0.1:3200");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

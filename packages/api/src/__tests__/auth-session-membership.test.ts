import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const contextSource = readFileSync(join(import.meta.dir, "..", "services", "context.ts"), "utf8");
const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("session membership hardening", () => {
  it("rejects missing users and rechecks tenant membership during session verification", () => {
    for (const source of [contextSource, authSource]) {
      expect(source).toContain("!user || user.deactivatedAt");
      expect(source).toContain("from(userTenants)");
      expect(source).toContain("eq(userTenants.tenantId, payload.tenantId)");
      expect(source).toContain("if (!membership) return null");
    }
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const contextSource = readFileSync(join(import.meta.dir, "..", "services", "context.ts"), "utf8");
const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("session membership hardening", () => {
  it("rejects missing users and rechecks tenant membership during session verification", () => {
    expect(contextSource).toContain("steward_bootstrap.session_subject(");
    expect(contextSource).toContain("!user || user.deactivated_at");
    expect(contextSource).toContain("if (payload.tenantId && !user.membership_role) return null");

    expect(authSource).toContain("!user || user.deactivatedAt");
    expect(authSource).toContain("from(userTenants)");
    expect(authSource).toContain("eq(userTenants.tenantId, payload.tenantId)");
    expect(authSource).toContain("if (!membership) return null");
  });
});

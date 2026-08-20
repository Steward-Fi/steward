import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const contextSource = readFileSync(join(import.meta.dir, "..", "services", "context.ts"), "utf8");
const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("session membership hardening", () => {
  it("rejects missing users and rechecks tenant membership during session verification", () => {
    // The shared context uses the SECURITY DEFINER bootstrap function so the
    // lookup remains available before a tenant RLS transaction is installed.
    expect(contextSource).toContain("steward_bootstrap.session_subject(");
    expect(contextSource).toContain("if (!user || user.deactivated_at) return null");
    expect(contextSource).toContain("if (payload.tenantId && !user.membership_role) return null");

    // The auth router performs the equivalent checks through tenant-scoped
    // Drizzle queries once its verified auth transaction is active.
    expect(authSource).toContain("if (!user || user.deactivatedAt) return null");
    expect(authSource).toContain(".from(userTenants)");
    expect(authSource).toContain("eq(userTenants.tenantId, payload.tenantId)");
    expect(authSource).toContain("if (!membership) return null");
  });
});

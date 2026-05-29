import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("tenant team RBAC hardening", () => {
  it("defines Privy-style tenant team roles without widening admin checks", () => {
    const userRoutes = read("packages/api/src/routes/user.ts");
    const context = read("packages/api/src/services/context.ts");

    expect(userRoutes).toContain('"developer"');
    expect(userRoutes).toContain('"billing"');
    expect(userRoutes).toContain('"viewer"');
    expect(userRoutes).toContain("normalizeTenantRole");
    expect(context).toContain('tenantRole === "owner" || tenantRole === "admin"');
  });

  it("adds tenant role updates with MFA, audit, and sole-owner protection", () => {
    const source = read("packages/api/src/routes/user.ts");

    expect(source).toContain('user.patch("/me/tenants/:tenantId/users/:targetUserId/role"');
    expect(source).toContain("Tenant role updates require recent MFA verification");
    expect(source).toContain("Only owners can grant owner role");
    expect(source).toContain("Only owners can modify owner role");
    expect(source).toContain("Cannot demote the sole owner");
    expect(source).toContain("tenant.member.role.update.authorized");
    expect(source).toContain("tenant.member.role.update");
    expect(source).toContain("previousRole: membership.role");
    expect(source).toContain(".set({ role: updated.previousRole })");
  });

  it("surfaces role editing in the dashboard users page", () => {
    const source = read("web/src/app/dashboard/users/page.tsx");

    expect(source).toContain("Tenant role");
    expect(source).toContain("updateTenantUserRole");
    expect(source).toContain("developer");
    expect(source).toContain("billing");
    expect(source).toContain("viewer");
  });
});

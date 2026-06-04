import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "tenants.ts"), "utf8");

describe("tenant audit rollback hardening", () => {
  it("rolls back tenant creation if the final audit event cannot be written", () => {
    const createStart = routeSource.indexOf('tenantRoutes.post("/", platformAuthMiddleware()');
    expect(createStart).toBeGreaterThanOrEqual(0);
    const createRoute = routeSource.slice(
      createStart,
      routeSource.indexOf('tenantRoutes.get("/:id"', createStart),
    );

    expect(createRoute).toContain('action: "tenant.create.authorized"');
    expect(createRoute).toContain('action: "tenant.create"');
    expect(createRoute).toContain("try {");
    expect(createRoute).toContain("tenantConfigs.delete(body.id)");
    expect(createRoute).toContain("db.delete(tenants).where(eq(tenants.id, body.id))");
  });

  it("restores previous tenant webhook/config state if the final update audit fails", () => {
    const updateStart = routeSource.indexOf('tenantRoutes.put("/:id/webhook"');
    expect(updateStart).toBeGreaterThanOrEqual(0);
    const updateRoute = routeSource.slice(updateStart);

    expect(updateRoute).toContain('action: "tenant.update.authorized"');
    expect(updateRoute).toContain('action: "tenant.update"');
    expect(updateRoute).toContain("const previousConfig: TenantConfig = { ...tenantConfig }");
    expect(updateRoute).toContain("snapshotLegacyTenantWebhooks(tenant.id)");
    expect(updateRoute).toContain("tenantConfigs.set(tenant.id, previousConfig)");
    expect(updateRoute).toContain("restoreLegacyTenantWebhooks(tenant.id, legacyWebhookSnapshot)");
    expect(updateRoute).toContain('actorId: c.get("userId") ?? tenant.id');
  });
});

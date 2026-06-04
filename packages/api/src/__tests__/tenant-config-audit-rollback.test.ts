import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const routeSource = readFileSync(join(import.meta.dir, "..", "routes", "tenant-config.ts"), "utf8");

describe("tenant config audit rollback hardening", () => {
  it("restores the previous tenant config row when final config audits fail", () => {
    expect(routeSource).toContain("type TenantConfigRow = typeof tenantConfigsTable.$inferSelect");
    expect(routeSource).toContain("async function snapshotTenantConfigRow");
    expect(routeSource).toContain("async function restoreTenantConfigRow");
    expect(routeSource).toContain("tx.delete(tenantConfigsTable)");
    expect(routeSource).toContain("tx.insert(tenantConfigsTable).values(snapshot)");
    expect(routeSource).toContain("invalidateTenantCorsCache(tenantId)");

    for (const marker of [
      'tenantConfigRoutes.put("/:id/oidc-providers"',
      'tenantConfigRoutes.put("/:id/auth-abuse-config"',
      'tenantConfigRoutes.post("/:id/redirect-urls"',
      'tenantConfigRoutes.delete("/:id/redirect-urls"',
      'tenantConfigRoutes.post("/:id/app-origins"',
      'tenantConfigRoutes.delete("/:id/app-origins"',
      'tenantConfigRoutes.post("/:id/test-account"',
      'tenantConfigRoutes.delete("/:id/test-account"',
      'tenantConfigRoutes.put("/:id/config"',
    ]) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = routeSource.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = routeSource.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain("snapshotTenantConfigRow(tenantId)");
      expect(route).toContain("try {");
      expect(route).toContain("restoreTenantConfigRow(tenantId, previousConfigRow)");
    }
  });

  it("audits redirect and app-origin alias authorization before mutation", () => {
    for (const [marker, authorizedAction, persistCall] of [
      [
        'tenantConfigRoutes.post("/:id/redirect-urls"',
        'action: "tenant.redirect_url.add.authorized"',
        "persistAllowedRedirectUrlsForTenant(tenantId, next)",
      ],
      [
        'tenantConfigRoutes.delete("/:id/redirect-urls"',
        'action: "tenant.redirect_url.remove.authorized"',
        "persistAllowedRedirectUrlsForTenant(",
      ],
      [
        'tenantConfigRoutes.post("/:id/app-origins"',
        'action: "tenant.app_origin.add.authorized"',
        "persistAllowedOriginsForTenant(tenantId, next)",
      ],
      [
        'tenantConfigRoutes.delete("/:id/app-origins"',
        'action: "tenant.app_origin.remove.authorized"',
        "persistAllowedOriginsForTenant(",
      ],
    ] as const) {
      const start = routeSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = routeSource.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = routeSource.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route.indexOf(authorizedAction)).toBeGreaterThanOrEqual(0);
      expect(route.indexOf(authorizedAction)).toBeLessThan(route.indexOf(persistCall));
    }
  });
});

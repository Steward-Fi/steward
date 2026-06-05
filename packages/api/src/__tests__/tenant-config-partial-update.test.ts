import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const tenantConfigSource = readFileSync(
  join(import.meta.dir, "..", "routes", "tenant-config.ts"),
  "utf8",
);

describe("tenant config partial update hardening", () => {
  it("preserves existing/default config fields when omitted from PUT /:id/config", () => {
    const routeStart = tenantConfigSource.indexOf('tenantConfigRoutes.put("/:id/config"');
    expect(routeStart).toBeGreaterThanOrEqual(0);

    const existingSelect = tenantConfigSource.indexOf(
      "const [existingConfig] = await db",
      routeStart,
    );
    const valuesStart = tenantConfigSource.indexOf("const values = {", routeStart);
    expect(existingSelect).toBeGreaterThan(routeStart);
    expect(valuesStart).toBeGreaterThan(existingSelect);

    for (const field of [
      "policyExposure",
      "policyTemplates",
      "secretRoutePresets",
      "approvalConfig",
      "featureFlags",
      "theme",
      "gasSponsorshipConfig",
    ]) {
      expect(
        tenantConfigSource.indexOf(`${field}: tenantConfigsTable.${field}`, existingSelect),
      ).toBeLessThan(valuesStart);
      expect(
        tenantConfigSource.indexOf(`body.${field} !== undefined`, valuesStart),
      ).toBeGreaterThan(valuesStart);
      if (field === "featureFlags") {
        expect(tenantConfigSource.indexOf("existingFeatureFlags", valuesStart)).toBeGreaterThan(
          valuesStart,
        );
      } else {
        expect(tenantConfigSource.indexOf(`existingConfig?.${field}`, valuesStart)).toBeGreaterThan(
          valuesStart,
        );
      }
      if (field === "featureFlags") {
        expect(
          tenantConfigSource.indexOf("defaultConfig.featureFlags", existingSelect),
        ).toBeLessThan(valuesStart);
      } else {
        expect(tenantConfigSource.indexOf(`defaultConfig.${field}`, valuesStart)).toBeGreaterThan(
          valuesStart,
        );
      }
    }

    expect(tenantConfigSource.indexOf("body.policyTemplates ?? []", routeStart)).toBe(-1);
  });

  it("exposes app-origin aliases without weakening tenant-admin MFA on mutations", () => {
    expect(tenantConfigSource).toContain('tenantConfigRoutes.get("/:id/app-origins"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.post("/:id/app-origins"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.delete("/:id/app-origins"');
    expect(tenantConfigSource).toContain('requireRecentTenantAdminMfa(c, "App origin access")');
    expect(tenantConfigSource).toContain('requireRecentTenantAdminMfa(c, "App origin updates")');
    expect(tenantConfigSource).toContain("persistAllowedOriginsForTenant(");
    expect(tenantConfigSource).toContain("invalidateTenantCorsCache(tenantId)");
  });

  it("exposes redirect-url aliases separate from app origins", () => {
    expect(tenantConfigSource).toContain('tenantConfigRoutes.get("/:id/redirect-urls"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.post("/:id/redirect-urls"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.delete("/:id/redirect-urls"');
    expect(tenantConfigSource).toContain('requireRecentTenantAdminMfa(c, "Redirect URL access")');
    expect(tenantConfigSource).toContain('requireRecentTenantAdminMfa(c, "Redirect URL updates")');
    expect(tenantConfigSource).toContain("normalizeAllowedRedirectUrls(");
    expect(tenantConfigSource).toContain("persistAllowedRedirectUrlsForTenant(");
    expect(tenantConfigSource).toContain("tenant.redirect_url.add");
    expect(tenantConfigSource).toContain("tenant.redirect_url.remove");
  });

  it("exposes app access allowlist aliases backed by normalized auth abuse config", () => {
    expect(tenantConfigSource).toContain('tenantConfigRoutes.get("/:id/access-allowlist"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.post("/:id/access-allowlist"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.delete("/:id/access-allowlist"');
    expect(tenantConfigSource).toContain(
      'requireRecentTenantAdminMfa(c, "Access allowlist access")',
    );
    expect(tenantConfigSource).toContain(
      'requireRecentTenantAdminMfa(c, "Access allowlist updates")',
    );
    expect(tenantConfigSource).toContain("toAccessAllowlistEntries(");
    expect(tenantConfigSource).toContain("normalizeAuthAbuseConfig({ ...config");
    expect(tenantConfigSource).toContain("tenant.access_allowlist.add");
    expect(tenantConfigSource).toContain("tenant.access_allowlist.remove");
  });

  it("exposes MFA-gated gas sponsorship config for paymaster setup", () => {
    expect(tenantConfigSource).toContain('tenantConfigRoutes.get("/:id/gas-sponsorship"');
    expect(tenantConfigSource).toContain('tenantConfigRoutes.patch("/:id/gas-sponsorship"');
    expect(tenantConfigSource).toContain(
      'requireRecentTenantAdminMfa(c, "Gas sponsorship config access")',
    );
    expect(tenantConfigSource).toContain(
      'requireRecentTenantAdminMfa(c, "Gas sponsorship config updates")',
    );
    expect(tenantConfigSource).toContain("normalizeGasSponsorshipConfig(");
    expect(tenantConfigSource).toContain("tenant.gas_sponsorship.update");
  });
});

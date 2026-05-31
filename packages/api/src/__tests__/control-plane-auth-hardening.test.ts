import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const tenantConfigSource = readFileSync(
  join(import.meta.dir, "..", "routes", "tenant-config.ts"),
  "utf8",
);
const webhookSource = readFileSync(join(import.meta.dir, "..", "routes", "webhooks.ts"), "utf8");
const tenantsSource = readFileSync(join(import.meta.dir, "..", "routes", "tenants.ts"), "utf8");

describe("control-plane auth hardening", () => {
  it("requires owner/admin sessions with recent MFA for tenant config writes and template application", () => {
    for (const marker of [
      'tenantConfigRoutes.put("/:id/config"',
      'tenantConfigRoutes.post("/:id/config/templates/:name/apply"',
    ]) {
      const start = tenantConfigSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const adminCheck = tenantConfigSource.indexOf("requireRecentTenantAdminMfa(c,", start);
      const tenantLevelCheck = tenantConfigSource.indexOf("requireTenantLevel(c)", start);
      expect(adminCheck).toBeGreaterThan(start);
      expect(tenantLevelCheck === -1 || adminCheck < tenantLevelCheck).toBe(true);
    }
    expect(tenantConfigSource).toContain("data: redactAdminOnlyConfigForTenantAuth(c, config)");
    expect(tenantConfigSource).toContain("requireTenantAdminSession(c) && hasRecentSessionMfa(c)");
  });

  it("requires recent MFA before tenant admins can read or rotate sensitive login config", () => {
    expect(tenantConfigSource).toContain("function requireRecentTenantAdminMfa");
    expect(tenantConfigSource).toContain("readTenantMfaPolicy");
    expect(tenantConfigSource).toContain("tenantMfaMaxAgeMs");
    expect(tenantConfigSource).toContain("policy.requireFor?.tenantAdmin === false");
    expect(tenantConfigSource).toContain("hasRecentSessionMfa(c, tenantMfaMaxAgeMs(policy))");
    for (const marker of [
      'tenantConfigRoutes.get("/:id/oidc-providers"',
      'tenantConfigRoutes.put("/:id/oidc-providers"',
      'tenantConfigRoutes.get("/:id/auth-abuse-config"',
      'tenantConfigRoutes.put("/:id/auth-abuse-config"',
      'tenantConfigRoutes.get("/:id/security-checklist"',
      'tenantConfigRoutes.get("/:id/request-signing-keys"',
      'tenantConfigRoutes.post("/:id/request-signing-keys"',
      'tenantConfigRoutes.delete("/:id/request-signing-keys/:keyId"',
      'tenantConfigRoutes.get("/:id/test-account"',
      'tenantConfigRoutes.post("/:id/test-account"',
      'tenantConfigRoutes.delete("/:id/test-account"',
    ]) {
      const start = tenantConfigSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const mfaCheck = tenantConfigSource.indexOf("requireRecentTenantAdminMfa(c,", start);
      expect(mfaCheck).toBeGreaterThan(start);
    }
  });

  it("redacts hidden policy details from tenant-level config reads", () => {
    expect(tenantConfigSource).toContain("function redactPolicyTemplatesForTenantAuth");
    expect(tenantConfigSource).toContain('policyExposure === "hidden"');
    expect(tenantConfigSource).toContain('policyExposure === "enforced"');
    expect(tenantConfigSource).toContain("config: {}");
    expect(tenantConfigSource).toContain("secretRoutePresets: []");
    expect(tenantConfigSource).toContain("approvalConfig: {}");
    expect(tenantConfigSource).toContain("function redactPolicyExposureForTenantAuth");
    expect(tenantConfigSource).toContain('policyExposure === "visible"');
    expect(tenantConfigSource).toContain("allowedOrigins: []");

    const templatesRouteStart = tenantConfigSource.indexOf(
      'tenantConfigRoutes.get("/:id/config/templates"',
    );
    expect(templatesRouteStart).toBeGreaterThanOrEqual(0);
    const templatesRoute = tenantConfigSource.slice(
      templatesRouteStart,
      tenantConfigSource.indexOf(
        'tenantConfigRoutes.post("/:id/config/templates/:name/apply"',
        templatesRouteStart,
      ),
    );
    expect(templatesRoute).toContain("redactPolicyTemplatesForTenantAuth");
    expect(templatesRoute).toContain("requireTenantAdminSession(c) && hasRecentSessionMfa(c)");
    expect(templatesRoute).not.toContain("data: row.policyTemplates as PolicyTemplate[]");
  });

  it("does not apply policy templates with globally predictable policy ids", () => {
    const applyStart = tenantConfigSource.indexOf(
      'tenantConfigRoutes.post("/:id/config/templates/:name/apply"',
    );
    expect(applyStart).toBeGreaterThanOrEqual(0);
    const applyRoute = tenantConfigSource.slice(
      applyStart,
      tenantConfigSource.indexOf('tenantConfigRoutes.get("/:id/oidc-providers"', applyStart),
    );

    expect(applyRoute).toContain("id: crypto.randomUUID()");
    expect(applyRoute).toContain("insertedRows.length !== persistedPolicies.length");
    expect(applyRoute).not.toContain("id: `${body.agentId}-${p.type}`");
    expect(applyRoute).not.toContain(".onConflictDoNothing()");
  });

  it("does not allow tenant API keys or stale admin sessions to manage persistent webhooks", () => {
    expect(webhookSource).toContain("function requireRecentTenantAdminMfa");
    expect(webhookSource).toContain("readTenantMfaPolicy");
    expect(webhookSource).toContain("tenantMfaMaxAgeMs");
    expect(webhookSource).toContain("policy.requireFor?.tenantAdmin === false");
    expect(webhookSource).toContain("hasRecentSessionMfa(c, tenantMfaMaxAgeMs(policy))");
    for (const [source, marker] of [
      [webhookSource, 'webhookRoutes.post("/",'],
      [webhookSource, 'webhookRoutes.put("/:id",'],
      [webhookSource, 'webhookRoutes.delete("/:id",'],
      [webhookSource, 'webhookRoutes.post("/:id/test",'],
      [webhookSource, 'webhookRoutes.get("/:id/deliveries",'],
      [webhookSource, 'webhookRoutes.get("/:id/deliveries/export",'],
      [webhookSource, 'webhookRoutes.post("/deliveries/:id/replay",'],
      [webhookSource, 'webhookRoutes.post("/deliveries/:id/retry",'],
      [tenantsSource, 'tenantRoutes.put("/:id/webhook",'],
    ] as const) {
      const start = source.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const adminCheck = source.indexOf("requireRecentTenantAdminMfa(c,", start);
      const tenantLevelCheck = source.indexOf("requireTenantLevel(c)", start);
      expect(adminCheck).toBeGreaterThan(start);
      expect(tenantLevelCheck === -1 || adminCheck < tenantLevelCheck).toBe(true);
    }
  });

  it("redacts legacy tenant webhook and default policies from lower-trust tenant reads", () => {
    const getStart = tenantsSource.indexOf('tenantRoutes.get("/:id"');
    expect(getStart).toBeGreaterThanOrEqual(0);
    const getRoute = tenantsSource.slice(
      getStart,
      tenantsSource.indexOf('tenantRoutes.put("/:id/webhook"', getStart),
    );
    expect(tenantsSource).toContain("function getTenantPayloadForRequest");
    expect(tenantsSource).toContain("requireTenantAdminSession(c) && hasRecentSessionMfa(c)");
    expect(tenantsSource).toContain(
      "const { webhookUrl: _webhookUrl, defaultPolicies: _defaultPolicies, ...redacted } = payload",
    );
    expect(getRoute).toContain("getTenantPayloadForRequest(c, tenant)");
    expect(getRoute).not.toContain("getTenantPayload(tenant)");
  });
});

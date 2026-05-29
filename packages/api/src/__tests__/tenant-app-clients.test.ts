import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("tenant app clients hardening", () => {
  it("persists app clients as a tenant-scoped registry with exact allowlists", () => {
    const schema = read("packages/db/src/schema.ts");
    const migration = read("packages/db/drizzle/0046_tenant_app_clients.sql");

    expect(schema).toContain("export const tenantAppClients");
    expect(schema).toContain('varchar("tenant_id"');
    expect(schema).toContain(
      'allowedOrigins: text("allowed_origins").array().notNull().default([])',
    );
    expect(schema).toContain(
      'allowedRedirectUrls: text("allowed_redirect_urls").array().notNull().default([])',
    );
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS "tenant_app_clients"');
    expect(migration).toContain('"tenant_id" varchar(64) NOT NULL REFERENCES "tenants"("id")');
    expect(migration).toContain('"allowed_redirect_urls" text[] DEFAULT');
  });

  it("keeps app-client mutations behind owner/admin recent MFA and validates redirect/origin inputs", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");

    expect(source).toContain('tenantConfigRoutes.get("/:id/app-clients"');
    expect(source).toContain('tenantConfigRoutes.put("/:id/app-clients"');
    expect(source).toContain('tenantConfigRoutes.post("/:id/app-clients"');
    expect(source).toContain('tenantConfigRoutes.delete("/:id/app-clients/:clientId"');
    expect(source).toContain('requireRecentTenantAdminMfa(c, "App client updates")');
    expect(source).toContain("normalizeTenantAppClients");
    expect(source).toContain("normalizeAllowedOrigins(raw.allowedOrigins ?? [])");
    expect(source).toContain("normalizeAllowedRedirectUrls(raw.allowedRedirectUrls ?? [])");
    expect(source).toContain("allowedOrigins cannot include wildcard");
  });

  it("audits app-client create/delete authorization before mutation and rolls back on final audit failure", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");

    for (const [marker, authorizedAction, finalAction] of [
      [
        'tenantConfigRoutes.post("/:id/app-clients"',
        'action: "tenant.app_client.create.authorized"',
        'action: "tenant.app_client.create"',
      ],
      [
        'tenantConfigRoutes.delete("/:id/app-clients/:clientId"',
        'action: "tenant.app_client.delete.authorized"',
        'action: "tenant.app_client.delete"',
      ],
    ] as const) {
      const start = source.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = source.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = source.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route.indexOf(authorizedAction)).toBeGreaterThanOrEqual(0);
      expect(route.indexOf(authorizedAction)).toBeLessThan(
        route.indexOf("persistTenantAppClientsForTenant"),
      );
      expect(route).toContain(
        "const previousAppClients = await snapshotTenantAppClients(tenantId)",
      );
      expect(route).toContain(
        "const previousAppClientSecrets = await snapshotTenantAppClientSecretsForTenant(tenantId)",
      );
      expect(route).toContain("try {");
      expect(route).toContain(finalAction);
      expect(route).toContain(
        "await restoreTenantAppClients(tenantId, previousAppClients, previousAppClientSecrets)",
      );
    }
  });

  it("preserves secrets for surviving app clients during registry rewrites", () => {
    const source = read("packages/api/src/routes/tenant-config.ts");
    const helperStart = source.indexOf("async function persistTenantAppClientsForTenant");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const helperEnd = source.indexOf(
      "\nasync function validatePolicyTemplatesForTenant",
      helperStart,
    );
    const helper = source.slice(helperStart, helperEnd);

    expect(helper).toContain(".from(tenantAppClientSecrets)");
    expect(helper).toContain(
      "const nextClientIds = new Set(normalized.map((client) => client.id))",
    );
    expect(helper).toContain("const secretsToPreserve = existingSecrets.filter");
    expect(helper).toContain("nextClientIds.has(secret.clientId)");
    expect(helper).toContain("await tx.insert(tenantAppClientSecrets).values(secretsToPreserve)");
  });

  it("folds enabled app clients into runtime CORS and OAuth redirect enforcement", () => {
    const cors = read("packages/api/src/middleware/tenant-cors.ts");
    const auth = read("packages/api/src/routes/auth.ts");

    expect(cors).toContain("tenantAppClientsTable");
    expect(cors).toContain("eq(tenantAppClientsTable.enabled, true)");
    expect(auth).toContain("tenantAppClients");
    expect(auth).toContain("client_id");
    expect(auth).toContain("stateData.clientId");
    expect(auth).toContain("getTenantAppClientLoginMethods");
    expect(auth).toContain("assertAllowedOAuthRedirectUri(redirectUri, tenantId, clientId)");
  });

  it("adds Privy-style app-client secrets without weakening session-MFA control plane", () => {
    const schema = read("packages/db/src/schema.ts");
    const migration = read("packages/db/drizzle/0047_tenant_app_client_secrets.sql");
    const tenantConfig = read("packages/api/src/routes/tenant-config.ts");
    const context = read("packages/api/src/services/context.ts");

    expect(schema).toContain("export const tenantAppClientSecrets");
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS "tenant_app_client_secrets"');
    expect(migration).toContain('"secret_hash" text NOT NULL');
    expect(tenantConfig).toContain('tenantConfigRoutes.post("/:id/app-clients/:clientId/secrets"');
    expect(tenantConfig).toContain("appSecret: generated.secret");
    expect(tenantConfig).toContain("snapshotTenantAppClientSecrets");
    expect(tenantConfig).toContain("restoreTenantAppClientSecrets");
    expect(tenantConfig).toContain("tenant.app_client_secret.rotate.authorized");
    expect(tenantConfig).toContain("tenant.app_client_secret.rotate");
    expect(tenantConfig).toContain("tenant.app_client_secret.revoke.authorized");
    expect(tenantConfig).toContain("tenant.app_client_secret.revoke");
    expect(context).toContain('authType", "app-secret"');
    expect(context).toContain("App secret auth requires Basic auth and X-Steward-App-Id");
  });

  it("rolls back app-client secret mutations when final audits fail", () => {
    const tenantConfig = read("packages/api/src/routes/tenant-config.ts");

    for (const [marker, finalAction] of [
      [
        'tenantConfigRoutes.post("/:id/app-clients/:clientId/secrets"',
        'action: "tenant.app_client_secret.rotate"',
      ],
      [
        'tenantConfigRoutes.delete("/:id/app-clients/:clientId/secrets/:secretId"',
        'action: "tenant.app_client_secret.revoke"',
      ],
    ] as const) {
      let start = tenantConfig.indexOf(marker);
      if (start < 0 && marker.includes('delete')) {
        start = tenantConfig.indexOf('tenantConfigRoutes.delete(\n  "/:id/app-clients/:clientId/secrets/:secretId"');
      }
      if (start < 0) start = tenantConfig.indexOf(marker.slice(0, -2));
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = tenantConfig.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = tenantConfig.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain("const previousSecrets = await snapshotTenantAppClientSecrets");
      expect(route).toContain("try {");
      expect(route).toContain(finalAction);
      expect(route).toContain(
        "await restoreTenantAppClientSecrets(tenantId, clientId, previousSecrets)",
      );
    }
  });
});

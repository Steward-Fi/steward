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
    expect(schema).toContain('globalWalletEnabled: boolean("global_wallet_enabled")');
    expect(schema).toContain('globalWalletAllowedScopes: text("global_wallet_allowed_scopes")');
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
    expect(source).toContain("globalWalletAllowedScopes");
    expect(source).toContain("allowedOrigins cannot include wildcard");
  });

  it("adds provider-side global wallet app-client and consent storage foundations", () => {
    const schema = read("packages/db/src/schema.ts");
    const authSchema = read("packages/db/src/schema-auth.ts");
    const migration = read("packages/db/drizzle/0057_global_wallet_consents.sql");
    const sharedTypes = read("packages/shared/src/index.ts");
    const sdkTypes = read("packages/sdk/src/types.ts");

    expect(schema).toContain('globalWalletEnabled: boolean("global_wallet_enabled")');
    expect(schema).toContain('globalWalletAllowedScopes: text("global_wallet_allowed_scopes")');
    expect(authSchema).toContain("export const userWalletAppConsents");
    expect(authSchema).toContain("user_wallet_app_consents_active_unique_idx");
    expect(authSchema).toContain("user_wallet_app_consents_app_client_fk");
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS "user_wallet_app_consents"');
    expect(migration).toContain('"global_wallet_enabled" boolean DEFAULT false NOT NULL');
    expect(sharedTypes).toContain("globalWalletEnabled?: boolean");
    expect(sdkTypes).toContain("globalWalletAllowedScopes?: string[]");
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
    expect(helper).toContain("const secretsToPreserve = existingSecrets.filter((secret) =>");
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

  it("keeps app access allowlist aliases MFA-gated, tenant-isolated, normalized, and batch-safe", () => {
    const tenantConfig = read("packages/api/src/routes/tenant-config.ts");

    for (const [marker, mfaReason] of [
      ['tenantConfigRoutes.get("/:id/access-allowlist"', "Access allowlist access"],
      ['tenantConfigRoutes.post("/:id/access-allowlist"', "Access allowlist updates"],
      ['tenantConfigRoutes.delete("/:id/access-allowlist"', "Access allowlist updates"],
    ] as const) {
      const start = tenantConfig.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = tenantConfig.indexOf("\ntenantConfigRoutes.", start + marker.length);
      const route = tenantConfig.slice(start, nextRoute === -1 ? undefined : nextRoute);

      expect(route).toContain(`${marker}, requireTenantId`);
      expect(route).toContain(`requireRecentTenantAdminMfa(c, "${mfaReason}")`);
      expect(route.indexOf("requireRecentTenantAdminMfa")).toBeLessThan(
        route.indexOf('c.req.param("id")'),
      );
      expect(route).toContain("tenantId");
    }

    expect(tenantConfig).toContain(
      'const ACCESS_ALLOWLIST_TYPES = new Set(["email", "email_domain", "wallet", "phone"] as const)',
    );
    expect(tenantConfig).toContain("function normalizeAccessAllowlistEntry");
    expect(tenantConfig).toContain("normalizeAuthAbuseConfig(candidate)");
    expect(tenantConfig).toContain("function normalizeAccessAllowlistEntries");
    expect(tenantConfig).toContain("const values = Array.isArray(value) ? value : [value]");
    expect(tenantConfig).toContain("readAuthAbuseConfigForTenant(tenantId)");
    expect(tenantConfig).toContain("persistAuthAbuseConfigForTenant(tenantId, next)");
    expect(tenantConfig).toContain("toAccessAllowlistEntries(tenantId, persisted)");

    const postStart = tenantConfig.indexOf('tenantConfigRoutes.post("/:id/access-allowlist"');
    const deleteStart = tenantConfig.indexOf('tenantConfigRoutes.delete("/:id/access-allowlist"');
    const postRoute = tenantConfig.slice(postStart, deleteStart);
    const deleteRoute = tenantConfig.slice(deleteStart);
    expect(postRoute).toContain("body.entries !== undefined");
    expect(postRoute).toContain("normalizeAccessAllowlistEntries(rawEntries)");
    expect(postRoute).toContain('action: "tenant.access_allowlist.add.authorized"');
    expect(postRoute).toContain('action: "tenant.access_allowlist.add"');
    expect(postRoute).toContain(
      "const previousConfigRow = await snapshotTenantConfigRow(tenantId)",
    );
    expect(postRoute).toContain("await restoreTenantConfigRow(tenantId, previousConfigRow)");
    expect(deleteRoute).toContain("body.ids !== undefined");
    expect(deleteRoute).toContain("body.entries !== undefined");
    expect(deleteRoute).toContain("removeAccessAllowlistEntriesFromConfig(tenantId, current");
    expect(deleteRoute).toContain('action: "tenant.access_allowlist.remove.authorized"');
    expect(deleteRoute).toContain('action: "tenant.access_allowlist.remove"');
    expect(deleteRoute).toContain(
      "const previousConfigRow = await snapshotTenantConfigRow(tenantId)",
    );
    expect(deleteRoute).toContain("await restoreTenantConfigRow(tenantId, previousConfigRow)");
  });

  it("rolls back app-client secret mutations when final audits fail", () => {
    const tenantConfig = read("packages/api/src/routes/tenant-config.ts");

    for (const [marker, finalAction] of [
      [
        'tenantConfigRoutes.post("/:id/app-clients/:clientId/secrets"',
        'action: "tenant.app_client_secret.rotate"',
      ],
      [
        '"/:id/app-clients/:clientId/secrets/:secretId"',
        'action: "tenant.app_client_secret.revoke"',
      ],
    ] as const) {
      const start = tenantConfig.indexOf(marker);
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

  it("adds encrypted tenant request-signing keys with MFA, audit, and rollback", () => {
    const schema = read("packages/db/src/schema.ts");
    const migration = read("packages/db/drizzle/0056_tenant_request_signing_keys.sql");
    const tenantConfig = read("packages/api/src/routes/tenant-config.ts");
    const middleware = read("packages/api/src/middleware/authorization-signature.ts");
    const sdk = read("packages/sdk/src/client.ts");

    expect(schema).toContain("export const tenantRequestSigningKeys");
    expect(migration).toContain('CREATE TABLE IF NOT EXISTS "tenant_request_signing_keys"');
    expect(migration).toContain('"secret_ciphertext" text NOT NULL');
    expect(tenantConfig).toContain('tenantConfigRoutes.get("/:id/request-signing-keys"');
    expect(tenantConfig).toContain('tenantConfigRoutes.post("/:id/request-signing-keys"');
    expect(tenantConfig).toContain('tenantConfigRoutes.delete("/:id/request-signing-keys/:keyId"');
    expect(tenantConfig).toContain("requestSigningKeyStore().encrypt");
    expect(tenantConfig).toContain("signingSecret: generated.secret");
    expect(tenantConfig).toContain("tenant.request_signing_key.rotate.authorized");
    expect(tenantConfig).toContain("tenant.request_signing_key.rotate");
    expect(tenantConfig).toContain("tenant.request_signing_key.revoke.authorized");
    expect(tenantConfig).toContain("tenant.request_signing_key.revoke");
    expect(tenantConfig).toContain("restoreTenantRequestSigningKeys");
    expect(middleware).toContain("tenantRequestSigningKeyCandidates");
    expect(middleware).toContain("X-Steward-Signing-Key-Id");
    expect(middleware).toContain("keyStore.decrypt");
    expect(sdk).toContain("listTenantRequestSigningKeys");
    expect(sdk).toContain("rotateTenantRequestSigningKey");
    expect(sdk).toContain("revokeTenantRequestSigningKey");
    expect(sdk).toContain("requestSigningKeyId");
  });
});

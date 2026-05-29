import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const platformSource = readFileSync(join(apiRoot, "routes", "platform.ts"), "utf8");
const tenantRoutesSource = readFileSync(join(apiRoot, "routes", "tenants.ts"), "utf8");
const platformAuthSource = readFileSync(
  join(apiRoot, "..", "..", "auth", "src", "platform.ts"),
  "utf8",
);
const revocationSource = readFileSync(
  join(apiRoot, "..", "..", "auth", "src", "revocation.ts"),
  "utf8",
);

function expectBefore(first: string, second: string) {
  const firstIndex = platformSource.indexOf(first);
  const secondIndex = platformSource.indexOf(second, firstIndex);
  expect(firstIndex).toBeGreaterThanOrEqual(0);
  expect(secondIndex).toBeGreaterThanOrEqual(0);
  expect(firstIndex).toBeLessThan(secondIndex);
}

describe("platform security hardening", () => {
  it("requires explicit scoped platform keys for platform write routes", () => {
    expect(platformAuthSource).toContain("STEWARD_PLATFORM_KEY_SCOPES");
    expect(platformAuthSource).toContain('c.set("platformScopes"');
    expect(platformAuthSource).toContain("hasPlatformScope");

    const platformWriteGuard = platformSource.indexOf(
      '!hasPlatformScope(scopes, "platform:write")',
    );
    expect(platformWriteGuard).toBeGreaterThanOrEqual(0);
    expect(platformWriteGuard).toBeLessThan(platformSource.indexOf('platform.post("/tenants"'));

    const tenantCreateStart = tenantRoutesSource.indexOf(
      'tenantRoutes.post("/", platformAuthMiddleware()',
    );
    expect(tenantCreateStart).toBeGreaterThanOrEqual(0);
    expect(
      tenantRoutesSource.indexOf(
        'requirePlatformRouteScope(c, "platform:write")',
        tenantCreateStart,
      ),
    ).toBeGreaterThan(tenantCreateStart);
    expect(
      tenantRoutesSource.indexOf(
        'requirePlatformRouteScope(c, "platform:tenant:create")',
        tenantCreateStart,
      ),
    ).toBeGreaterThan(tenantCreateStart);
  });

  it("requires explicit scoped platform keys for platform read routes", () => {
    const platformReadGuard = platformSource.indexOf('!hasPlatformScope(scopes, "platform:read")');
    const platformWriteGuard = platformSource.indexOf(
      '!hasPlatformScope(scopes, "platform:write")',
    );
    expect(platformReadGuard).toBeGreaterThanOrEqual(0);
    expect(platformWriteGuard).toBeGreaterThanOrEqual(0);
    expect(platformReadGuard).toBeLessThan(platformWriteGuard);
    expect(platformSource).toContain("Platform read routes require a scoped platform key");
  });

  it("reserves internal tenant ids from platform tenant creation", () => {
    expect(platformSource).toContain('const PLATFORM_AUDIT_TENANT_ID = "platform"');
    expect(platformSource).toContain("function isReservedTenantId");
    const tenantCreateStart = platformSource.indexOf('platform.post("/tenants"');
    expect(tenantCreateStart).toBeGreaterThanOrEqual(0);
    expect(platformSource.indexOf("isReservedTenantId(body.id)", tenantCreateStart)).toBeLessThan(
      platformSource.indexOf(".insert(tenants)", tenantCreateStart),
    );
  });

  it("prevents tenant id reuse when retained tenant-scoped state exists", () => {
    expect(platformSource).toContain("async function tenantIdHasRetainedState");
    expect(platformSource).toContain("secrets.tenantId");
    expect(platformSource).toContain("secretRoutes.tenantId");
    expect(platformSource).toContain("proxyAuditLog.tenantId");
    expect(platformSource).toContain("auditEvents.tenantId");

    const tenantCreateStart = platformSource.indexOf('platform.post("/tenants"');
    expect(tenantCreateStart).toBeGreaterThanOrEqual(0);
    const tenantCreateRoute = platformSource.slice(
      tenantCreateStart,
      platformSource.indexOf('platform.get("/tenants"', tenantCreateStart),
    );
    expect(tenantCreateRoute).toContain("tenantIdHasRetainedState(body.id)");
    expect(tenantCreateRoute).toContain(
      "Tenant id has retained historical state and cannot be reused",
    );
    expect(tenantCreateRoute.indexOf("tenantIdHasRetainedState(body.id)")).toBeLessThan(
      tenantCreateRoute.indexOf('action: "tenant.create.authorized"'),
    );

    const legacyTenantCreateStart = tenantRoutesSource.indexOf(
      'tenantRoutes.post("/", platformAuthMiddleware()',
    );
    expect(legacyTenantCreateStart).toBeGreaterThanOrEqual(0);
    const legacyTenantCreateRoute = tenantRoutesSource.slice(
      legacyTenantCreateStart,
      tenantRoutesSource.indexOf('tenantRoutes.get("/:id"', legacyTenantCreateStart),
    );
    expect(legacyTenantCreateRoute).toContain("tenantIdHasRetainedState(body.id)");
    expect(legacyTenantCreateRoute).toContain(
      "Tenant id has retained historical state and cannot be reused",
    );
    expect(legacyTenantCreateRoute.indexOf("tenantIdHasRetainedState(body.id)")).toBeLessThan(
      legacyTenantCreateRoute.indexOf('action: "tenant.create.authorized"'),
    );
  });

  it("requires fine-grained platform scopes for token, member, and identity routes", () => {
    expect(platformSource).toContain("function requirePlatformRouteScope");
    expectBefore(
      'requirePlatformRouteScope(c, "platform:stats:read")',
      "db.select({ total: count() }).from(tenants)",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant:read")',
      ".select({\n      id: tenants.id",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:agent:read")',
      "vault().listAgentsByTenant",
    );
    expect(platformSource).toContain('requirePlatformRouteScope(c, "platform:user:read")');
    expect(platformSource).toContain("candidateUserId");
    expectBefore(
      'requirePlatformRouteScope(c, "platform:user:read")',
      "serializePlatformUserIdentity(userId)",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-user:read")',
      ".select(tenantUserSelection())",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-member:read")',
      ".select({\n      userId: userTenants.userId",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:agent-token:create")',
      "createAgentToken(agentId, tenantId",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:agent-token:revoke")',
      "revocationStore.revokeAgentTokens(agentId)",
    );
    expectBefore('requirePlatformRouteScope(c, "platform:agent:create")', "vault().createAgent");
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-member:write")',
      ".insert(userTenants)",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:user:write")',
      'action: "user.provision.create"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-user:write")',
      'action: "tenant.user.metadata.update"',
    );
    expect(platformSource).toContain('requirePlatformRouteScope(c, "platform:identity-migration")');
    expect(platformSource).toContain(
      'requirePlatformRouteScope(c, "platform:identity-migration:force")',
    );
  });

  it("requires fine-grained platform scopes for destructive and credential-bearing routes", () => {
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-email-config:read")',
      ".select({ emailConfig: tenantConfigs.emailConfig })",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-oidc:read")',
      ".select({ oidcProviders: tenantConfigs.oidcProviders })",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-test-account:read")',
      ".select({ testAccount: tenantConfigs.testAccount })",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant:create")',
      'action: "tenant.create.authorized"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-email-config:write")',
      'action: "tenant.email_config.update.authorized"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-oidc:write")',
      'action: "tenant.oidc_providers.update.authorized"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-test-account:write")',
      "createTenantTestAccountConfig()",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant:delete")',
      'action: "tenant.delete.authorized"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:tenant-policy:write")',
      ".select({ id: tenants.id })",
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:user-lifecycle:write")',
      'action: deactivated ? "user.deactivate.authorized" : "user.reactivate.authorized"',
    );
    expectBefore(
      'requirePlatformRouteScope(c, "platform:user:delete")',
      'action: "user.delete.authorized"',
    );
  });

  it("writes authorization audit events before sensitive platform mutations", () => {
    expectBefore('action: "tenant.create.authorized"', ".insert(tenants)");
    expectBefore('action: "tenant.api_key.create.authorized"', ".insert(tenants)");
    expectBefore('action: "tenant.email_config.update.authorized"', ".set({ emailConfig");
    expectBefore('action: "tenant.oidc_providers.update.authorized"', ".set({ oidcProviders");
    expectBefore('action: "tenant.test_account.enable.authorized"', ".set({ testAccount");
    expectBefore(
      'action: "tenant.test_account.disable.authorized"',
      ".set({ testAccount: disabled",
    );
    expectBefore('action: "tenant.email_config.delete.authorized"', ".set({ emailConfig: null");
    expectBefore('action: "tenant.delete.authorized"', "revocationStore.revokeAgentTokens");
    expectBefore('action: "tenant.delete.authorized"', "revocationStore.revokeUserTokens");
    expectBefore(
      'action: "agent.token.revoke_all.authorized"',
      "revocationStore.revokeAgentTokens(agentId)",
    );
    expectBefore('action: "agent.create.authorized"', "vault().createAgent");
    expectBefore('action: "user.metadata.update.authorized"', ".update(users)");
  });

  it("restores platform-managed tenant config when final audit events fail", () => {
    expect(platformSource).toContain(
      "type PlatformTenantConfigRow = typeof tenantConfigs.$inferSelect",
    );
    expect(platformSource).toContain("async function snapshotPlatformTenantConfigRow");
    expect(platformSource).toContain("async function restorePlatformTenantConfigRow");
    expect(platformSource).toContain("tx.delete(tenantConfigs)");
    expect(platformSource).toContain("tx.insert(tenantConfigs).values(snapshot)");

    for (const marker of [
      'platform.patch("/tenants/:tenantId/email-config"',
      'platform.put("/tenants/:tenantId/oidc-providers"',
      'platform.post("/tenants/:tenantId/test-account"',
      'platform.delete("/tenants/:tenantId/test-account"',
      'platform.delete("/tenants/:tenantId/email-config"',
    ]) {
      const start = platformSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = platformSource.indexOf("\nplatform.", start + marker.length);
      const route = platformSource.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain("snapshotPlatformTenantConfigRow(tenantId)");
      expect(route).toContain("try {");
      expect(route).toContain("restorePlatformTenantConfigRow(tenantId, previousConfigRow)");
    }
  });

  it("rolls back platform tenant and agent creation when final audit events fail", () => {
    expect(platformSource).toContain("async function deletePlatformCreatedTenant");
    expect(platformSource).toContain("async function deletePlatformCreatedAgent");
    expect(platformSource).toContain("tx.delete(encryptedChainKeys)");
    expect(platformSource).toContain("tx.delete(encryptedKeys)");
    expect(platformSource).toContain("tx.delete(agentWallets)");

    const tenantCreateStart = platformSource.indexOf('platform.post("/tenants"');
    const tenantCreateRoute = platformSource.slice(
      tenantCreateStart,
      platformSource.indexOf('platform.get("/tenants"', tenantCreateStart),
    );
    const tenantInsert = tenantCreateRoute.indexOf(".insert(tenants)");
    const finalTenantAudit = tenantCreateRoute.indexOf('action: "tenant.create"', tenantInsert);
    const tenantRollback = tenantCreateRoute.indexOf("deletePlatformCreatedTenant(tenant.id)");
    expect(tenantInsert).toBeGreaterThanOrEqual(0);
    expect(finalTenantAudit).toBeGreaterThan(tenantInsert);
    expect(tenantRollback).toBeGreaterThan(finalTenantAudit);

    const agentCreateStart = platformSource.indexOf('platform.post("/tenants/:id/agents"');
    const agentCreateRoute = platformSource.slice(
      agentCreateStart,
      platformSource.indexOf('platform.post("/tenants/:id/agents/batch"', agentCreateStart),
    );
    const createAgent = agentCreateRoute.indexOf("vault().createAgent");
    const finalAgentAudit = agentCreateRoute.indexOf('action: "agent.create"', createAgent);
    const agentRollback = agentCreateRoute.indexOf("deletePlatformCreatedAgent(body.id, tenantId)");
    expect(createAgent).toBeGreaterThanOrEqual(0);
    expect(finalAgentAudit).toBeGreaterThan(createAgent);
    expect(agentRollback).toBeGreaterThan(finalAgentAudit);
  });

  it("restores platform user and membership mutations when final audit events fail", () => {
    for (const [marker, rollback] of [
      ['platform.patch("/users/:userId/metadata"', "customMetadata: existing.customMetadata"],
      ['platform.patch("/users/:userId/deactivate"', "deactivatedAt: result.previous.deactivatedAt"],
      [
        'platform.post("/users/:userId/accounts/:provider/:providerAccountId/transfer"',
        "set({ userId: fromUserId })",
      ],
      ['platform.patch("/tenants/:id/members/:userId"', "set({ role: updated.previousRole })"],
    ] as const) {
      const start = platformSource.indexOf(marker);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextRoute = platformSource.indexOf("\nplatform.", start + marker.length);
      const route = platformSource.slice(start, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain("try {");
      expect(route).toContain(rollback);
    }
  });

  it("locks account unlink and transfer last-login checks through mutation", () => {
    expect(platformSource).toContain("platform_user_account_");
    expect(platformSource).toContain("pg_advisory_xact_lock");
    expect(platformSource).toContain("lockUserSession(tx, userId)");
    expect(platformSource).toContain("lockUserSessions(tx, [fromUserId, toUserId])");
    expect(platformSource).toContain('action: "user.delete.authorized"');
    expect(platformSource).toContain("Cannot unlink the user's last login method");
    expect(platformSource).toContain("Cannot transfer the source user's last login method");
  });

  it("fails closed for global identity migration account mutations", () => {
    expect(platformSource).toContain("STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION");
    expect(platformSource).toContain("platformIdentityMigrationAllowed()");
    expect(platformSource).toContain("platformIdentityMigrationDisabledResponse(c)");
    const linkStart = platformSource.indexOf('platform.post("/users/:userId/accounts"');
    const unlinkStart = platformSource.indexOf(
      'platform.delete("/users/:userId/accounts/:provider/:providerAccountId"',
    );
    const transferStart = platformSource.indexOf(
      'platform.post("/users/:userId/accounts/:provider/:providerAccountId/transfer"',
    );
    expect(linkStart).toBeGreaterThanOrEqual(0);
    expect(unlinkStart).toBeGreaterThanOrEqual(0);
    expect(transferStart).toBeGreaterThanOrEqual(0);
    expect(platformSource.indexOf("platformIdentityMigrationAllowed()", linkStart)).toBeLessThan(
      platformSource.indexOf(".insert(accounts)", linkStart),
    );
    expect(platformSource.indexOf("platformIdentityMigrationAllowed()", unlinkStart)).toBeLessThan(
      platformSource.indexOf(".delete(accounts)", unlinkStart),
    );
    expect(
      platformSource.indexOf("platformIdentityMigrationAllowed()", transferStart),
    ).toBeLessThan(platformSource.indexOf(".update(accounts)", transferStart));
  });

  it("does not expose tenant test-account OTPs through read-only platform metadata", () => {
    expect(platformSource).toContain("redactedTestAccount");
    const getStart = platformSource.indexOf('platform.get("/tenants/:tenantId/test-account"');
    const postStart = platformSource.indexOf('platform.post("/tenants/:tenantId/test-account"');
    expect(getStart).toBeGreaterThanOrEqual(0);
    expect(postStart).toBeGreaterThan(getStart);
    const getRoute = platformSource.slice(getStart, postStart);
    expect(getRoute).toContain("redactedTestAccount");
    expect(getRoute).toContain('requirePlatformRouteScope(c, "platform:tenant-test-account:read")');
    expect(getRoute).not.toContain("publicTestAccount(row?.testAccount)");
  });

  it("does not downgrade shared revocation failures to process-local memory", () => {
    expect(revocationSource).toContain("Shared agent revocation store unavailable");
    expect(revocationSource).toContain("Shared user revocation store unavailable");
    expect(revocationSource).not.toContain("catch {\n      await this.fallback.revokeAgentTokens");
    expect(revocationSource).not.toContain("catch {\n      await this.fallback.revokeUserTokens");
    expect(revocationSource).not.toContain("catch {\n      return this.fallback.getAgentRevokedBefore");
    expect(revocationSource).not.toContain("catch {\n      return this.fallback.getUserRevokedBefore");
  });

  it("revokes user access tokens for tenant membership removal and tenant deletion", () => {
    const memberDeleteStart = platformSource.indexOf(
      'platform.delete("/tenants/:id/members/:userId"',
    );
    expect(memberDeleteStart).toBeGreaterThanOrEqual(0);
    expect(
      platformSource.indexOf("revocationStore.revokeUserTokens(userId)", memberDeleteStart),
    ).toBeLessThan(platformSource.indexOf(".delete(userTenants)", memberDeleteStart));
    expect(
      platformSource.indexOf("revokedUserTokensIssuedBefore", memberDeleteStart),
    ).toBeGreaterThan(memberDeleteStart);

    const tenantDeleteStart = platformSource.indexOf('platform.delete("/tenants/:id"');
    expect(tenantDeleteStart).toBeGreaterThanOrEqual(0);
    expect(platformSource.indexOf("tenantMembers", tenantDeleteStart)).toBeGreaterThan(
      tenantDeleteStart,
    );
    expect(
      platformSource.indexOf("revocationStore.revokeUserTokens(member.userId)", tenantDeleteStart),
    ).toBeLessThan(platformSource.indexOf("tx.delete(refreshTokens)", tenantDeleteStart));
  });

  it("removes non-cascading tenant credential state during tenant deletion", () => {
    const tenantDeleteStart = platformSource.indexOf('platform.delete("/tenants/:id"');
    expect(tenantDeleteStart).toBeGreaterThanOrEqual(0);
    const tenantDeleteRoute = platformSource.slice(
      tenantDeleteStart,
      platformSource.indexOf('platform.put("/tenants/:id/policies"', tenantDeleteStart),
    );
    expect(tenantDeleteRoute).toContain("tx.delete(secretRoutes)");
    expect(tenantDeleteRoute).toContain("tx.delete(secrets)");
    expect(tenantDeleteRoute).toContain("tx.delete(proxyAuditLog)");
    expect(tenantDeleteRoute.indexOf("tx.delete(secretRoutes)")).toBeLessThan(
      tenantDeleteRoute.indexOf("tx.delete(secrets)"),
    );
    expect(tenantDeleteRoute.indexOf("tx.delete(secrets)")).toBeLessThan(
      tenantDeleteRoute.indexOf("tx.delete(tenants)"),
    );
  });

  it("revokes tenant member sessions before platform role changes take effect", () => {
    const memberRoleUpdateStart = platformSource.indexOf(
      'platform.patch("/tenants/:id/members/:userId"',
    );
    expect(memberRoleUpdateStart).toBeGreaterThanOrEqual(0);
    expect(
      platformSource.indexOf("revocationStore.revokeUserTokens(userId", memberRoleUpdateStart),
    ).toBeLessThan(platformSource.indexOf(".set({ role })", memberRoleUpdateStart));
    expect(platformSource.indexOf(".delete(refreshTokens)", memberRoleUpdateStart)).toBeLessThan(
      platformSource.indexOf(".set({ role })", memberRoleUpdateStart),
    );
    expect(
      platformSource.indexOf("revokedUserTokensIssuedBefore", memberRoleUpdateStart),
    ).toBeGreaterThan(memberRoleUpdateStart);
  });

  it("counts only active owners before destructive owner lifecycle changes", () => {
    expect(platformSource).toContain("function activeTenantOwnerCount");
    expect(platformSource).toContain("isNull(users.deactivatedAt)");
    expect(platformSource).toContain("innerJoin(users, eq(users.id, userTenants.userId))");
    expect(platformSource).toContain("function tenantOwnerLifecycleLockKey");
    expect(platformSource).toContain("tenant_owner_lifecycle_${tenantId}");
    expect(platformSource).toContain("function lockUserOwnerLifecycleTenants");
    expect(platformSource).toContain("function assertUserIsNotSoleActiveOwner");
    expect(platformSource).toContain("Cannot deactivate the sole active tenant owner");
    expect(platformSource).toContain("Cannot delete the sole active tenant owner");
    expect(platformSource).not.toContain("platform_member_${tenantId}");

    for (const marker of [
      'platform.patch("/users/:userId/deactivate"',
      'platform.delete("/users/:userId"',
      'platform.delete("/tenants/:id/members/:userId"',
      'platform.patch("/tenants/:id/members/:userId"',
    ]) {
      const routeStart = platformSource.indexOf(marker);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const nextRoute = platformSource.indexOf("\nplatform.", routeStart + marker.length);
      const routeSource = platformSource.slice(
        routeStart,
        nextRoute === -1 ? platformSource.length : nextRoute,
      );
      expect(routeSource).toMatch(/lockTenantOwnerLifecycle|assertUserIsNotSoleActiveOwner/);
    }
  });
});

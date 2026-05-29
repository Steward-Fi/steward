import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const userSource = readFileSync(join(import.meta.dir, "..", "routes", "user.ts"), "utf8");
const platformSource = readFileSync(join(import.meta.dir, "..", "routes", "platform.ts"), "utf8");
const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");
const dbSchemaSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "src", "schema.ts"),
  "utf8",
);
const joinMigrationSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "drizzle", "0034_harden_tenant_join_default.sql"),
  "utf8",
);

describe("user membership hardening", () => {
  it("validates tenant-admin user ids and audits self-service membership before mutation", () => {
    expect(userSource).toContain("function isValidUserId");
    expect(userSource).toContain("if (!isValidUserId(targetUserId))");
    const joinAudit = userSource.indexOf('action: "tenant.member.join"');
    expect(joinAudit).toBeLessThan(userSource.indexOf(".insert(userTenants)", joinAudit));
    const leaveAudit = userSource.indexOf('action: "tenant.member.leave"');
    const leaveDelete = userSource.indexOf(".delete(userTenants)", leaveAudit);
    expect(leaveAudit).toBeLessThan(leaveDelete);
    expect(userSource.lastIndexOf("pg_advisory_xact_lock", leaveDelete)).toBeGreaterThan(0);
    const unlinkRoute = userSource.slice(userSource.indexOf('user.delete("/me/accounts'));
    expect(unlinkRoute.indexOf("hasRecentMfaStepUp(session)")).toBeLessThan(
      unlinkRoute.indexOf(".delete(accounts)"),
    );
    expect(unlinkRoute.indexOf('action: "user.account.unlink.authorized"')).toBeLessThan(
      unlinkRoute.indexOf(".delete(accounts)"),
    );
    const leaveRoute = userSource.slice(
      userSource.indexOf('user.delete("/me/tenants/:tenantId/leave"'),
    );
    expect(leaveRoute.indexOf("hasRecentMfaStepUp(session)")).toBeLessThan(
      leaveRoute.indexOf(".delete(userTenants)"),
    );
    for (const route of [
      'user.get("/me/tenants/:tenantId/users"',
      'user.get("/me/tenants/:tenantId/users/:targetUserId"',
    ]) {
      const routeSource = userSource.slice(userSource.indexOf(route));
      expect(routeSource.indexOf("hasRecentMfaStepUp(session)")).toBeLessThan(
        routeSource.indexOf("tenantAdminUserSelection()"),
      );
    }
    expect(platformSource).toContain("if (!isValidUserId(userId))");
    expect(platformSource).toContain("revocationStore.revokeUserTokens(userId)");
  });

  it("counts only active tenant owners before self-service tenant leave", () => {
    expect(userSource).toContain("function activeTenantOwnerCount");
    expect(userSource).toContain("isNull(users.deactivatedAt)");
    expect(userSource).toContain("innerJoin(users, eq(users.id, userTenants.userId))");
    expect(userSource).toContain("function tenantOwnerLifecycleLockKey");
    expect(userSource).toContain("tenant_owner_lifecycle_${tenantId}");
    expect(userSource).not.toContain("tenant_leave_${tenantId}");
    const leaveRoute = userSource.slice(
      userSource.indexOf('user.delete("/me/tenants/:tenantId/leave"'),
    );
    expect(leaveRoute).toContain("lockTenantOwnerLifecycle(tx, tenantId)");
    expect(leaveRoute).toContain("lockUserSession(tx, userId)");
    expect(leaveRoute).toContain("activeTenantOwnerCount(tx, tenantId, userId)");
    expect(leaveRoute.indexOf("sessionTenantMatches(session, tenantId)")).toBeLessThan(
      leaveRoute.indexOf(".delete(userTenants)"),
    );
    expect(leaveRoute.indexOf("lockUserSession(tx, userId)")).toBeLessThan(
      leaveRoute.indexOf(".delete(refreshTokens)"),
    );
    expect(leaveRoute.indexOf(".delete(refreshTokens)")).toBeLessThan(
      leaveRoute.indexOf("return deleted ?? null"),
    );
  });

  it("does not make tenants publicly self-joinable by default", () => {
    expect(dbSchemaSource).toContain(
      'joinMode: varchar("join_mode", { length: 16 }).notNull().default("invite")',
    );
    expect(joinMigrationSource).toContain(
      "ALTER TABLE tenant_configs ALTER COLUMN join_mode SET DEFAULT 'invite'",
    );
    expect(joinMigrationSource).toContain(
      "UPDATE tenant_configs SET join_mode = 'invite' WHERE join_mode = 'open'",
    );
    expect(userSource).toContain("Personal tenants cannot be self-joined");
    expect(authSource).toContain("Personal tenants cannot be self-joined");
  });

  it("requires personal sessions for cross-tenant membership reads and self-join", () => {
    for (const route of [
      'user.get("/me/tenants/:tenantId"',
      'user.post("/me/tenants/:tenantId/join"',
    ]) {
      const routeSource = userSource.slice(userSource.indexOf(route));
      expect(routeSource.indexOf("requirePersonalUserSession(c)")).toBeGreaterThanOrEqual(0);
      expect(routeSource.indexOf("requirePersonalUserSession(c)")).toBeLessThan(
        routeSource.indexOf('const userId = c.get("userId")'),
      );
    }
  });

  it("reserves internal tenant namespaces from user-created tenants", () => {
    const reservedStart = userSource.indexOf("function isReservedTenantId");
    expect(reservedStart).toBeGreaterThanOrEqual(0);
    const reservedBody = userSource.slice(
      reservedStart,
      userSource.indexOf("function slugifyTenantId", reservedStart),
    );
    expect(reservedBody).toContain('normalized === "platform"');
    expect(reservedBody).toContain('normalized === "system"');
    expect(reservedBody).toContain('normalized === "default"');
    const createTenantRoute = userSource.slice(userSource.indexOf('user.post("/me/tenants"'));
    expect(createTenantRoute.indexOf("isReservedTenantId(tenantId)")).toBeLessThan(
      createTenantRoute.indexOf(".insert(tenants)"),
    );
  });

  it("records specific linked-account identifiers on self-unlink webhooks", () => {
    const route = userSource.slice(
      userSource.indexOf('user.delete("/me/accounts/:provider/:providerAccountId"'),
    );
    expect(route).toContain("hasRecentMfaStepUp(session)");
    expect(route).toContain("user_session_${userId}");
    expect(route).toContain("providerAccountId");
    expect(route).toContain("accountId");
    expect(route).toContain('"user.unlinked_account"');
  });

  it("rechecks linked-account ownership before returning existing link success", () => {
    for (const [marker, error] of [
      ['user.post("/me/accounts/wallet/ethereum"', "Wallet is already linked to another user"],
      ['user.post("/me/accounts/wallet/solana"', "Wallet is already linked to another user"],
      [
        "user.post(`/me/accounts/phone/${channel}/verify`",
        "Phone is already linked to another user",
      ],
    ] as const) {
      const route = userSource.slice(userSource.indexOf(marker));
      expect(route).toContain("userId: accounts.userId");
      expect(route).toContain("existing.userId !== userId");
      expect(route).toContain(error);
    }
  });

  it("audits user wallet transaction signing before handing the request to the vault", () => {
    const authorized = userSource.indexOf('action: "user.wallet.sign.authorized"');
    const sign = userSource.indexOf("vault.signTransaction", authorized);
    expect(authorized).toBeGreaterThanOrEqual(0);
    expect(sign).toBeGreaterThan(authorized);
  });

  it("resolves user wallet chainId before policy evaluation", () => {
    const route = userSource.slice(userSource.indexOf('user.post("/me/wallet/sign"'));
    const chainValidation = route.indexOf("'chainId' must be a positive integer when provided");
    const signRequest = route.indexOf("const signRequest: SignRequest");
    const evaluation = route.indexOf("engine.evaluate");
    expect(chainValidation).toBeGreaterThanOrEqual(0);
    expect(signRequest).toBeGreaterThan(chainValidation);
    expect(route.slice(signRequest, evaluation)).toContain("chainId");
  });
});

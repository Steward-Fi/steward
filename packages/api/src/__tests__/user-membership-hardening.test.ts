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
const dbAuthSchemaSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "src", "schema-auth.ts"),
  "utf8",
);
const joinMigrationSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "drizzle", "0034_harden_tenant_join_default.sql"),
  "utf8",
);
const inviteMigrationSource = readFileSync(
  join(import.meta.dir, "..", "..", "..", "db", "drizzle", "0054_tenant_invitations.sql"),
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
      // Directory reads gate on recent MFA via requireTenantUserDirectoryReaderMfa
      // (which enforces hasRecentMfaStepUp internally) and bail out before
      // selecting any tenant user rows.
      const mfaGate = routeSource.indexOf("requireTenantUserDirectoryReaderMfa(");
      const selection = routeSource.indexOf("tenantAdminUserSelection()");
      expect(mfaGate).toBeGreaterThanOrEqual(0);
      expect(mfaGate).toBeLessThan(selection);
      expect(routeSource.indexOf("if (!reader.ok) return reader.response;")).toBeLessThan(
        selection,
      );
    }
    // Lock in that the directory-reader MFA helper actually enforces tenant match,
    // the directory-reader role, and a recent MFA step-up — so the routes above
    // can't be silently downgraded by gutting the helper.
    const readerHelperStart = userSource.indexOf(
      "async function requireTenantUserDirectoryReaderMfa",
    );
    expect(readerHelperStart).toBeGreaterThanOrEqual(0);
    const readerHelper = userSource.slice(
      readerHelperStart,
      userSource.indexOf("\nuser.get(", readerHelperStart),
    );
    expect(readerHelper).toContain("sessionTenantMatches(session, tenantId)");
    expect(readerHelper).toContain("requireTenantUserDirectoryReader(requesterId, tenantId)");
    expect(readerHelper).toContain("hasRecentMfaStepUp(session)");
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

  it("restores tenant member removal when the completed audit write fails", () => {
    const removeRoute = userSource.slice(
      userSource.indexOf('user.delete("/me/tenants/:tenantId/users/:targetUserId"'),
      userSource.indexOf('user.post("/me/tenants/:tenantId/invitations/accept"', 1),
    );
    const deleteMembership = removeRoute.indexOf(".delete(userTenants)");
    const completedAudit = removeRoute.indexOf('action: "tenant.member.remove"', deleteMembership);
    const rollback = removeRoute.indexOf(".insert(userTenants)", completedAudit);

    expect(deleteMembership).toBeGreaterThanOrEqual(0);
    expect(completedAudit).toBeGreaterThan(deleteMembership);
    expect(rollback).toBeGreaterThan(completedAudit);
    expect(removeRoute).toContain("customMetadata: userTenants.customMetadata");
    expect(removeRoute).toContain("createdAt: userTenants.createdAt");
    expect(removeRoute).toContain(".select({");
    expect(removeRoute).toContain(".from(refreshTokens)");
    expect(removeRoute).toContain(".insert(refreshTokens)");
    expect(removeRoute).toContain(
      "onConflictDoNothing({ target: [userTenants.userId, userTenants.tenantId] })",
    );
    expect(removeRoute).toContain("onConflictDoNothing({ target: refreshTokens.tokenHash })");
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

  it("models tenant invitations as pending single-use records before membership creation", () => {
    expect(dbAuthSchemaSource).toContain("export const tenantInvitations = pgTable");
    expect(dbAuthSchemaSource).toContain('"token_hash"');
    expect(dbAuthSchemaSource).toContain('"accepted_by_user_id"');
    expect(inviteMigrationSource).toContain('"tenant_invitations_pending_email_idx"');
    expect(inviteMigrationSource).toContain("WHERE \"status\" = 'pending'");
    expect(inviteMigrationSource).toContain('CHECK ("role" IN');
    expect(inviteMigrationSource).not.toContain("'owner'");

    const platformInviteRoute = platformSource.slice(
      platformSource.indexOf('platform.post("/tenants/:id/invitations"'),
      platformSource.indexOf('platform.delete("/tenants/:id/invitations', 1),
    );
    expect(platformInviteRoute).toContain('action: "tenant.invitation.create.authorized"');
    expect(platformInviteRoute.indexOf("writeAuditEvent")).toBeLessThan(
      platformInviteRoute.indexOf(".insert(tenantInvitations)"),
    );
    expect(platformInviteRoute.indexOf('action: "tenant.invitation.create"')).toBeGreaterThan(
      platformInviteRoute.indexOf(".insert(tenantInvitations)"),
    );
    expect(platformInviteRoute).toContain("db.transaction");
    expect(platformInviteRoute).toContain("valid email is required");
    expect(platformInviteRoute).toContain("invitedByUserId must belong to the tenant");
    expect(platformInviteRoute).toContain("hashSha256Hex(token)");
    expect(platformInviteRoute).toContain("body.sendEmail === true");
    expect(platformInviteRoute).toContain("sendTenantInvitation(email");

    const platformInviteRevokeRoute = platformSource.slice(
      platformSource.indexOf('platform.delete("/tenants/:id/invitations/:invitationId"'),
      platformSource.indexOf('platform.post("/tenants/:id/members"', 1),
    );
    expect(
      platformInviteRevokeRoute.indexOf('action: "tenant.invitation.revoke.authorized"'),
    ).toBeLessThan(platformInviteRevokeRoute.indexOf(".update(tenantInvitations)"));

    const acceptRoute = userSource.slice(
      userSource.indexOf('user.post("/me/tenants/:tenantId/invitations/accept"'),
      userSource.indexOf('user.post("/me/tenants/:tenantId/join"', 1),
    );
    expect(acceptRoute).toContain("requirePersonalUserSession(c)");
    expect(acceptRoute).toContain("emailVerified");
    expect(acceptRoute).toContain("/^[a-f0-9]{64}$/i.test(body.token)");
    expect(acceptRoute).toContain("hashSha256Hex(body.token)");
    expect(acceptRoute).toContain('eq(tenantInvitations.status, "pending")');
    expect(acceptRoute).toContain("gte(tenantInvitations.expiresAt, new Date())");
    expect(acceptRoute.indexOf('action: "tenant.invitation.accept.authorized"')).toBeLessThan(
      acceptRoute.indexOf(".insert(userTenants)"),
    );
    expect(acceptRoute.indexOf(".update(tenantInvitations)")).toBeLessThan(
      acceptRoute.indexOf(".insert(userTenants)"),
    );

    for (const [routeMarker, auditMarker] of [
      [
        'user.get("/me/tenants/:tenantId/invitations"',
        "Tenant invitations require recent MFA verification",
      ],
      [
        'user.post("/me/tenants/:tenantId/invitations"',
        'action: "tenant.invitation.create.authorized"',
      ],
      [
        'user.delete("/me/tenants/:tenantId/invitations/:invitationId"',
        'action: "tenant.invitation.revoke.authorized"',
      ],
    ] as const) {
      const route = userSource.slice(userSource.indexOf(routeMarker));
      expect(route).toContain("requireTenantAdminMfa(");
      expect(route).toContain("sessionTenantMatches(session, tenantId)");
      expect(route).toContain("hasRecentMfaStepUp(session)");
      expect(route).toContain(auditMarker);
    }
    const userInviteCreateRoute = userSource.slice(
      userSource.indexOf('user.post("/me/tenants/:tenantId/invitations"'),
      userSource.indexOf('user.delete("/me/tenants/:tenantId/invitations/:invitationId"', 1),
    );
    expect(userInviteCreateRoute).toContain("db.transaction");
    expect(userInviteCreateRoute).toContain("body?.sendEmail === true");
    expect(userInviteCreateRoute).toContain("sendTenantInvitation(email");
    const userInviteRevokeRoute = userSource.slice(
      userSource.indexOf('user.delete("/me/tenants/:tenantId/invitations/:invitationId"'),
      userSource.indexOf('user.get("/me/tenants/:tenantId/users"', 1),
    );
    expect(
      userInviteRevokeRoute.indexOf('action: "tenant.invitation.revoke.authorized"'),
    ).toBeLessThan(userInviteRevokeRoute.indexOf(".update(tenantInvitations)"));
    expect(userInviteRevokeRoute.indexOf('action: "tenant.invitation.revoke"')).toBeGreaterThan(
      userInviteRevokeRoute.indexOf(".update(tenantInvitations)"),
    );
    expect(userInviteRevokeRoute).toContain("catch (error)");
    expect(userInviteRevokeRoute).toContain("status: candidate.status");
    expect(userInviteRevokeRoute).toContain("revokedAt: candidate.revokedAt");
  });

  it("requires matching token-backed pending invites through the self-join route for invite-mode tenants", () => {
    const joinRoute = userSource.slice(
      userSource.indexOf('user.post("/me/tenants/:tenantId/join"'),
      userSource.indexOf('user.delete("/me/tenants/:tenantId/leave"', 1),
    );
    expect(joinRoute).toContain('joinMode === "invite"');
    expect(joinRoute).toContain("/^[a-f0-9]{64}$/i.test(body.token)");
    expect(joinRoute).toContain("hashSha256Hex(body.token)");
    expect(joinRoute).toContain("emailVerified");
    expect(joinRoute).toContain("eq(tenantInvitations.email, email)");
    expect(joinRoute).toContain("eq(tenantInvitations.tokenHash, tokenHash)");
    expect(joinRoute).toContain('eq(tenantInvitations.status, "pending")');
    expect(joinRoute.indexOf('action: "tenant.member.accept_invite.authorized"')).toBeLessThan(
      joinRoute.indexOf(".insert(userTenants)"),
    );
    expect(joinRoute.indexOf(".update(tenantInvitations)")).toBeLessThan(
      joinRoute.indexOf(".insert(userTenants)"),
    );
    expect(joinRoute).toContain('action: "tenant.member.join"');
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

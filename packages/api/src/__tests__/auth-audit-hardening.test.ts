import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const authSource = readFileSync(join(apiRoot, "routes", "auth.ts"), "utf8");
const userSource = readFileSync(join(apiRoot, "routes", "user.ts"), "utf8");
const auditRouteSource = readFileSync(join(apiRoot, "routes", "audit.ts"), "utf8");
const auditServiceSource = readFileSync(join(apiRoot, "services", "audit.ts"), "utf8");
const authStoreSource = readFileSync(
  join(apiRoot, "..", "..", "auth", "src", "store-backends.ts"),
  "utf8",
);
const authSchemaSource = readFileSync(
  join(apiRoot, "..", "..", "db", "src", "schema-auth.ts"),
  "utf8",
);
const walletIdentityMigrationSource = readFileSync(
  join(apiRoot, "..", "..", "db", "drizzle", "0032_user_wallet_identity_unique.sql"),
  "utf8",
);

describe("auth and audit hardening", () => {
  it("does not expose test account token minting in production by default", () => {
    const routeStart = authSource.indexOf('auth.post("/test/token"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    expect(
      authSource.indexOf("STEWARD_ENABLE_PROD_TEST_ACCOUNT_TOKEN", routeStart),
    ).toBeGreaterThan(routeStart);
    expect(authSource.indexOf('process.env.NODE_ENV === "production"', routeStart)).toBeGreaterThan(
      routeStart,
    );
  });

  it("revokes access tokens as well as refresh tokens on sign-out everywhere", () => {
    const routeStart = authSource.indexOf('auth.delete("/sessions"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    expect(
      authSource.indexOf("revokeUserRefreshSessions(payload.userId)", routeStart),
    ).toBeGreaterThan(routeStart);
    expect(
      authSource.indexOf("revocationStore.revokeToken(payload.jti, payload.exp)", routeStart),
    ).toBeGreaterThan(routeStart);
  });

  it("revokes already minted access tokens when refresh-token reuse is detected", () => {
    const reusedBranch = authSource.indexOf('rotatedRefresh.status === "reused"');
    expect(reusedBranch).toBeGreaterThanOrEqual(0);
    expect(
      authSource.indexOf("revokeUserRefreshSessions(rotatedRefresh.userId)", reusedBranch),
    ).toBeGreaterThan(reusedBranch);
    expect(authSource.indexOf("auth.refresh.reuse_detected", reusedBranch)).toBeGreaterThan(
      reusedBranch,
    );
  });

  it("fences refresh rotation against concurrent user session revocation", () => {
    const routeStart = authSource.indexOf('auth.post("/refresh"');
    expect(routeStart).toBeGreaterThanOrEqual(0);
    const rotationStart = authSource.indexOf("async function rotateRefreshTokenForUserSession");
    expect(rotationStart).toBeGreaterThanOrEqual(0);
    expect(authSource.indexOf("const [refreshCandidate]", rotationStart)).toBeGreaterThan(
      rotationStart,
    );
    expect(authSource).toContain("lockUserSession(tx, refreshCandidate.userId)");
    expect(
      authSource.indexOf("revocationStore.getUserRevokedBefore(record.userId)", rotationStart),
    ).toBeGreaterThan(rotationStart);
    expect(
      authSource.indexOf("revocationStore.getUserRevokedBefore(record.userId)", rotationStart),
    ).toBeLessThan(authSource.indexOf(".insert(refreshTokens)", rotationStart));
    expect(
      authSource.indexOf("Session was revoked. Please sign in again.", routeStart),
    ).toBeGreaterThan(routeStart);
  });

  it("writes blocking audit events before login/session and MFA state mutations", () => {
    expect(authSource).toContain('action: "auth.login"');
    expect(authSource).toContain("async function writeAuthLoginAudit");
    expect(authSource).toContain('action: "auth.oidc.login.authorized"');
    const oidcProvisionStart = authSource.indexOf("async function provisionOidcUser");
    expect(oidcProvisionStart).toBeGreaterThanOrEqual(0);
    const oidcProvision = authSource.slice(
      oidcProvisionStart,
      authSource.indexOf("async function completeEmailAuth", oidcProvisionStart),
    );
    expect(oidcProvision.indexOf('action: "auth.oidc.login"')).toBeLessThan(
      oidcProvision.indexOf("buildAuthOrMfaResponse("),
    );
    for (const action of [
      'action: "mfa.enable.authorized"',
      'action: "mfa.disable.authorized"',
      'action: "mfa.recovery_codes.regenerate.authorized"',
      'action: "auth.logout.authorized"',
      'action: "auth.refresh_token.revoke.authorized"',
      'action: "auth.sessions.revoke_all.authorized"',
    ]) {
      expect(authSource).toContain(action);
    }
    const revokeAllRouteStart = authSource.indexOf('auth.delete("/sessions"');
    expect(
      authSource.indexOf('action: "auth.sessions.revoke_all.authorized"', revokeAllRouteStart),
    ).toBeLessThan(
      authSource.indexOf("revokeUserRefreshSessions(payload.userId)", revokeAllRouteStart),
    );
  });

  it("audits completed MFA logins before minting session tokens", () => {
    for (const marker of ['auth.post("/mfa/totp/complete"', 'auth.post("/mfa/sms/complete"']) {
      const routeStart = authSource.indexOf(marker);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const nextRoute = authSource.indexOf("\nauth.", routeStart + marker.length);
      const route = authSource.slice(routeStart, nextRoute === -1 ? undefined : nextRoute);
      expect(route).toContain("writeAuthLoginAudit(");
      expect(route.indexOf("writeAuthLoginAudit(")).toBeLessThan(
        route.indexOf("createSessionToken("),
      );
      expect(route.indexOf("writeAuthLoginAudit(")).toBeLessThan(
        route.indexOf("createRefreshToken("),
      );
      expect(route.indexOf("writeAuthLoginAudit(")).toBeLessThan(
        route.indexOf("dispatchUserAuthenticated("),
      );
    }
  });

  it("requires owner/admin session for audit routes and verifies bounded ranges", () => {
    expect(auditRouteSource).toContain('c.get("authType") !== "session-jwt"');
    expect(auditRouteSource).toContain('role !== "owner" && role !== "admin"');
    expect(auditRouteSource).toContain("sessionMfaVerifiedAt");
    expect(auditRouteSource).toContain("Audit routes require recent MFA verification");
    expect(auditServiceSource).toContain("seq = ${effectiveFromSeq - 1}");
    expect(auditServiceSource).toContain("seq BETWEEN ${effectiveFromSeq} AND ${toSeq}");
    expect(auditServiceSource).not.toContain("const fromSeq = 1");
  });

  it("binds phone login OTPs to tenant-specific purposes", () => {
    expect(authSource).toContain("function smsLoginPurpose");
    expect(authSource).toContain("function whatsappLoginPurpose");
    expect(authSource).toContain("sendOtp(body.phone, smsLoginPurpose(resolvedTenantId))");
    expect(authSource).toContain("const otpPurpose = smsLoginPurpose(otpTenantId)");
    expect(authSource).toContain("verifyOtp(body.phone, body.code, otpPurpose)");
    expect(authSource).toContain("whatsappLoginPurpose(resolvedTenantId)");
    expect(authSource).toContain("whatsappLoginPurpose(otpTenantId)");
  });

  it("enforces tenant login-method policy on direct auth routes", () => {
    for (const [routeMarker, methodMarker] of [
      ['auth.post("/sms/send"', 'requireTenantLoginMethodAllowed(c, resolvedTenantId, "sms")'],
      ['auth.post("/sms/verify"', 'requireTenantLoginMethodAllowed(c, otpTenantId, "sms")'],
      [
        'auth.post("/whatsapp/send"',
        'requireTenantLoginMethodAllowed(c, resolvedTenantId, "whatsapp")',
      ],
      [
        'auth.post("/whatsapp/verify"',
        'requireTenantLoginMethodAllowed(c, otpTenantId, "whatsapp")',
      ],
      ['auth.get("/nonce"', 'requireTenantLoginMethodAllowed(c, tenantId, "siwe")'],
      ['auth.post("/verify"', 'requireTenantLoginMethodAllowed(c, requestedTenantId, "siwe")'],
      [
        'auth.post("/verify/solana"',
        'requireTenantLoginMethodAllowed(c, requestedTenantId, "siws")',
      ],
      [
        'auth.post("/passkey/register/options"',
        'requireTenantLoginMethodAllowed(\n    c,\n    session.payload.tenantId,\n    "passkey"',
      ],
      [
        'auth.post("/passkey/register/verify"',
        'requireTenantLoginMethodAllowed(c, tenantId, "passkey")',
      ],
      [
        'auth.post("/passkey/login/options"',
        'requireTenantLoginMethodAllowed(c, optionTenantId, "passkey")',
      ],
      [
        'auth.post("/passkey/login/verify"',
        'requireTenantLoginMethodAllowed(c, tenantId, "passkey")',
      ],
      ['auth.post("/email/send"', 'requireTenantLoginMethodAllowed(c, resolvedTenantId, "email")'],
      [
        'auth.get("/callback/email"',
        'requireTenantLoginMethodAllowed(c, resolvedTenantId, "email")',
      ],
      [
        'auth.post("/email/verify"',
        'requireTenantLoginMethodAllowed(c, resolvedTenantId, "email")',
      ],
    ] as const) {
      const routeStart = authSource.indexOf(routeMarker);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const routeEnd = authSource.indexOf("\nauth.", routeStart + routeMarker.length);
      const routeSource = authSource.slice(routeStart, routeEnd > 0 ? routeEnd : undefined);
      expect(routeSource).toContain("requireTenantLoginMethodAllowed(");
      expect(routeSource).toContain(
        methodMarker.match(/"(email|sms|passkey)"/)?.[0] ?? methodMarker,
      );
    }
  });

  it("rejects non-loopback HTTP OAuth redirect URIs and non-atomic Redis consume", () => {
    expect(authSource).toContain(
      "redirect_uri must use https except for loopback development origins",
    );
    expect(authStoreSource).toContain("does not support atomic GETDEL token consumption");
    expect(authStoreSource).not.toContain("await this.client.get(this.prefix + key)");
  });

  it("requires stronger recent re-authentication before adding factors after one exists", () => {
    expect(authSource).toContain("async function hasAnyDurableFactor");
    expect(authSource).toContain("async function requireRecentFactorEnrollmentStepUp");
    expect(authSource).toContain("const existingDurableFactor = await hasAnyDurableFactor");
    expect(authSource).toContain("factorEnrollmentVerifiedAt");

    const factorStepUpStart = authSource.indexOf("function sessionHasRecentFactorEnrollmentStepUp");
    const factorStepUpSource = authSource.slice(
      factorStepUpStart,
      authSource.indexOf("async function requireRecentFactorEnrollmentStepUp", factorStepUpStart),
    );
    expect(factorStepUpSource).toContain("existingDurableFactor");
    expect(factorStepUpSource).toContain("session.payload.factorEnrollmentVerifiedAt");
    expect(factorStepUpSource).toContain("session.payload.mfaVerifiedAt");
    expect(factorStepUpSource).toContain('session.payload.authMethod !== "passkey"');
    expect(factorStepUpSource).not.toContain("session.payload.iat");

    for (const route of [
      'auth.post("/mfa/totp/enroll"',
      'auth.post("/mfa/sms/enroll"',
      'auth.post("/passkey/register/options"',
      'auth.post("/passkey/register/verify"',
    ]) {
      const routeStart = authSource.indexOf(route);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const routeSource = authSource.slice(routeStart, authSource.indexOf("\n});", routeStart));
      expect(routeSource).toContain("await requireRecentFactorEnrollmentStepUp(c, session)");
    }

    for (const route of ['auth.post("/mfa/totp/verify"', 'auth.post("/mfa/sms/verify"']) {
      const routeStart = authSource.indexOf(route);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const nextRoute = authSource.indexOf("\nauth.", routeStart + route.length);
      const routeSource = authSource.slice(routeStart, nextRoute === -1 ? undefined : nextRoute);
      expect(
        routeSource.indexOf("await requireRecentFactorEnrollmentStepUp(c, session)"),
      ).toBeLessThan(routeSource.indexOf("revokeUserRefreshSessions(session.payload.userId)"));
      expect(routeSource).toContain("revokeUserRefreshSessions(session.payload.userId)");
      expect(routeSource).toContain("revokedAccessTokensIssuedBefore");
    }
  });

  it("validates tenant access before storing OAuth tokens or passkey authenticators", () => {
    const passkeyVerifyStart = authSource.indexOf('auth.post("/passkey/register/verify"');
    expect(passkeyVerifyStart).toBeGreaterThanOrEqual(0);
    const passkeyVerifySource = authSource.slice(
      passkeyVerifyStart,
      authSource.indexOf("return authExchangeJson(", passkeyVerifyStart),
    );
    expect(
      passkeyVerifySource.indexOf("resolveAndValidateTenant(c, user.id, body.tenantId)"),
    ).toBeLessThan(passkeyVerifySource.indexOf(".insert(authenticators)"));

    const oauthProvisionStart = authSource.indexOf("async function provisionOAuthUser");
    expect(oauthProvisionStart).toBeGreaterThanOrEqual(0);
    const oauthProvisionSource = authSource.slice(
      oauthProvisionStart,
      authSource.indexOf("const payload = await buildAuthOrMfaResponse", oauthProvisionStart),
    );
    const accountUpsert = oauthProvisionSource.indexOf(".insert(accounts)");
    expect(oauthProvisionSource.indexOf("validateOidcJitTenant(requestedTenantId)")).toBeLessThan(
      accountUpsert,
    );
    expect(
      oauthProvisionSource.indexOf("resolveAndValidateTenant(c, existingUser.id, tenantId)"),
    ).toBeLessThan(accountUpsert);
    expect(
      oauthProvisionSource.indexOf("validateEmailAbusePolicy(email, authAbuseConfig)"),
    ).toBeLessThan(accountUpsert);
  });

  it("does not reassign OAuth provider accounts on insert conflicts", () => {
    const oauthProvisionStart = authSource.indexOf("async function provisionOAuthUser");
    expect(oauthProvisionStart).toBeGreaterThanOrEqual(0);
    const oauthProvisionSource = authSource.slice(
      oauthProvisionStart,
      authSource.indexOf("const payload = await buildAuthOrMfaResponse", oauthProvisionStart),
    );
    expect(oauthProvisionSource).toContain(".onConflictDoNothing");
    expect(oauthProvisionSource).toContain("currentAccount.userId !== user.id");
    expect(oauthProvisionSource).toContain("OAuth account is already linked to another user");
    expect(oauthProvisionSource).toContain(
      ".where(and(eq(accounts.id, currentAccount.id), eq(accounts.userId, user.id)))",
    );
    expect(oauthProvisionSource).not.toContain("set: {\n          userId: user.id");

    const userLinkStart = userSource.indexOf('user.post("/me/accounts/oauth/:provider/token"');
    expect(userLinkStart).toBeGreaterThanOrEqual(0);
    const userLinkSource = userSource.slice(
      userLinkStart,
      userSource.indexOf('user.delete("/me/accounts/:provider/:providerAccountId"', userLinkStart),
    );
    expect(userLinkSource).toContain(".onConflictDoNothing");
    expect(userLinkSource).toContain("current.userId !== userId");
    expect(userLinkSource).toContain("OAuth account is already linked to another user");
    expect(userLinkSource).toContain(
      ".where(and(eq(accounts.id, current.id), eq(accounts.userId, userId)))",
    );
    expect(userLinkSource).not.toContain("set: {\n        userId,");
  });

  it("hardens test accounts, OIDC email policy, passkey enumeration, and SMS MFA enrollment OTPs", () => {
    const testAccountStart = authSource.indexOf('auth.post("/test/token"');
    expect(testAccountStart).toBeGreaterThanOrEqual(0);
    const testAccountRoute = authSource.slice(
      testAccountStart,
      authSource.indexOf('auth.post("/sms/send"', testAccountStart),
    );
    expect(testAccountRoute.indexOf("testCredentialMatches(body?.email")).toBeLessThan(
      testAccountRoute.indexOf("testAccountOtpMatches(body?.otp"),
    );
    expect(testAccountRoute).toContain(
      "emailMatches ? `email:${testAccount.email.trim().toLowerCase()}`",
    );
    expect(testAccountRoute).toContain("phoneMatches ? `phone:${testAccount.phone.trim()}`");

    const oidcProvisionStart = authSource.indexOf("async function provisionOidcUser");
    expect(oidcProvisionStart).toBeGreaterThanOrEqual(0);
    const oidcProvision = authSource.slice(
      oidcProvisionStart,
      authSource.indexOf("const [existingAccount]", oidcProvisionStart),
    );
    expect(oidcProvision).toContain("validateEmailAbusePolicy(email, authAbuseConfig)");

    const passkeyVerifyStart = authSource.indexOf('auth.post("/passkey/register/verify"');
    const passkeyVerify = authSource.slice(
      passkeyVerifyStart,
      authSource.indexOf("const stepUpResponse", passkeyVerifyStart),
    );
    expect(passkeyVerify).toContain("where(eq(users.id, session.payload.userId))");
    expect(passkeyVerify).toContain("sessionUser.email?.toLowerCase().trim() !== email");
    expect(passkeyVerify).not.toContain("User not found");

    const smsVerifyStart = authSource.indexOf('auth.post("/mfa/sms/verify"');
    const smsVerify = authSource.slice(
      smsVerifyStart,
      authSource.indexOf('auth.post("/mfa/sms/send"', smsVerifyStart),
    );
    expect(smsVerify).toContain("getSmsVerifyFailedAttempts(pending.phone, pendingPurpose)");
    expect(smsVerify).toContain("recordSmsVerifyFailure(pending.phone, pendingPurpose)");
    expect(smsVerify).toContain("clearSmsVerifyFailures(pending.phone, pendingPurpose)");
  });

  it("enforces one user row per wallet identity", () => {
    expect(authSchemaSource).toContain("users_wallet_identity_unique_idx");
    expect(authSchemaSource).toContain("walletAddress} is not null");
    expect(walletIdentityMigrationSource).toContain("CREATE UNIQUE INDEX IF NOT EXISTS");
    expect(walletIdentityMigrationSource).toContain("ON users (wallet_chain, wallet_address)");
    const helper = authSource.slice(
      authSource.indexOf("async function findOrCreateWalletUserWithStatus"),
    );
    expect(helper).toContain("eq(users.walletChain, walletChain)");
    expect(helper).toContain("catch (error)");
    expect(helper).toContain("if (concurrent) return { user: concurrent, isNew: false }");
  });

  it("enforces tenant-disabled login methods on direct auth routes", () => {
    expect(authSource).toContain("async function requireTenantLoginMethodAllowed");
    for (const [route, method] of [
      ['auth.post("/telegram/challenge"', '"telegram"'],
      ['auth.post("/telegram/verify"', '"telegram"'],
      ['auth.post("/farcaster/verify"', '"farcaster"'],
      ['auth.post("/jwt/login"', '"oidc"'],
      ['auth.get("/oauth/:provider/authorize"', '"oauth"'],
      ['auth.get("/oauth/:provider/callback"', '"oauth"'],
      ['auth.post("/oauth/exchange"', '"oauth"'],
      ['auth.post("/oauth/:provider/token"', '"oauth"'],
    ] as const) {
      const routeStart = authSource.indexOf(route);
      expect(routeStart).toBeGreaterThanOrEqual(0);
      const routeBody = authSource.slice(routeStart, authSource.indexOf("\n});", routeStart));
      expect(routeBody).toContain("requireTenantLoginMethodAllowed");
      expect(routeBody).toContain(method);
    }
  });
});

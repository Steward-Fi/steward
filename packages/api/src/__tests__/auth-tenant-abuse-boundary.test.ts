import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("tenant auth abuse boundaries", () => {
  it("rejects blocked or not-allowed resolved user ids before MFA or session issuance", () => {
    const start = authSource.indexOf("async function buildAuthOrMfaResponse");
    const end = authSource.indexOf("function authExchangeJson", start);
    const source = authSource.slice(start, end);

    const configLoad = source.indexOf("const authAbuseConfig = await getTenantAuthAbuseConfig");
    const policyCheck = source.indexOf("validateUserAbusePolicy(userId, authAbuseConfig)");
    const policyDeny = source.indexOf(
      "return { ok: false, status: 403, error: userPolicyError };",
      policyCheck,
    );
    const totpMfaGate = source.indexOf("if (await hasTotpEnabled(userId))");
    const smsMfaGate = source.indexOf("const smsMfa = await getSmsMfa(userId)");
    const accessTokenMint = source.indexOf("const token = await createSessionToken");
    const refreshTokenMint = source.indexOf("const refreshToken = await createRefreshToken");
    const dispatchAuthenticated = source.indexOf("dispatchUserAuthenticated(");

    expect(start).toBeGreaterThanOrEqual(0);
    expect(configLoad).toBeGreaterThanOrEqual(0);
    expect(policyCheck).toBeGreaterThan(configLoad);
    expect(policyDeny).toBeGreaterThan(policyCheck);
    expect(policyDeny).toBeLessThan(totpMfaGate);
    expect(policyDeny).toBeLessThan(smsMfaGate);
    expect(policyDeny).toBeLessThan(accessTokenMint);
    expect(policyDeny).toBeLessThan(refreshTokenMint);
    expect(policyDeny).toBeLessThan(dispatchAuthenticated);
  });

  it("propagates user-id allowlist/blocklist denials from email auth completion", () => {
    const start = authSource.indexOf("async function completeEmailAuth");
    const end = authSource.indexOf("function resolveSamlMappedRole", start);
    const source = authSource.slice(start, end);

    const userResolved = source.indexOf("const { user, isNew } = await findOrCreateUserWithStatus");
    const tenantResolved = source.indexOf("resolvedTenantId = tenantResult.tenantId", userResolved);
    const sessionOrMfaResponse = source.indexOf("const response = await buildAuthOrMfaResponse");
    const policyFailureBranch = source.indexOf("if (response.ok === false)", sessionOrMfaResponse);
    const policyFailureReturn = source.indexOf("return {", policyFailureBranch);
    const successReturn = source.indexOf("ok: true", policyFailureBranch);

    expect(start).toBeGreaterThanOrEqual(0);
    expect(userResolved).toBeGreaterThanOrEqual(0);
    expect(tenantResolved).toBeGreaterThan(userResolved);
    expect(sessionOrMfaResponse).toBeGreaterThan(tenantResolved);
    expect(policyFailureBranch).toBeGreaterThan(sessionOrMfaResponse);
    expect(policyFailureReturn).toBeGreaterThan(policyFailureBranch);
    expect(policyFailureReturn).toBeLessThan(successReturn);
  });

  it("re-checks SMS phone policy against the resolved tenant before linking or issuing a session", () => {
    const start = authSource.indexOf('auth.post("/sms/verify"');
    const end = authSource.indexOf('auth.post("/whatsapp/send"', start);
    const source = authSource.slice(start, end);

    const tenantResolved = source.indexOf("const tenantResult = await resolveAndValidateTenant");
    const policyCheck = source.indexOf("validatePhoneAbusePolicy", tenantResolved);
    const tenantLink = source.indexOf("await ensureUserTenantLink", tenantResolved);
    const sessionResponse = source.indexOf("await buildAuthOrMfaResponse", tenantResolved);

    expect(tenantResolved).toBeGreaterThanOrEqual(0);
    expect(policyCheck).toBeGreaterThan(tenantResolved);
    expect(policyCheck).toBeLessThan(tenantLink);
    expect(policyCheck).toBeLessThan(sessionResponse);
  });

  it("checks OAuth email policy against the resolved tenant before tenant linking or session minting", () => {
    const start = authSource.indexOf("async function completeEmailAuth");
    const end = authSource.indexOf("function resolveSamlMappedRole", start);
    const source = authSource.slice(start, end);

    const tenantResolved = source.indexOf("resolvedTenantId = tenantResult.tenantId");
    const policyCheck = source.indexOf("validateEmailAbusePolicy", tenantResolved);
    const tenantLink = source.indexOf("await ensureUserTenantLink", tenantResolved);
    const sessionResponse = source.indexOf("buildAuthOrMfaResponse", tenantResolved);

    expect(tenantResolved).toBeGreaterThanOrEqual(0);
    expect(policyCheck).toBeGreaterThan(tenantResolved);
    expect(policyCheck).toBeLessThan(tenantLink);
    expect(policyCheck).toBeLessThan(sessionResponse);
  });

  it("re-checks WhatsApp phone policy against the resolved tenant before linking or issuing a session", () => {
    const start = authSource.indexOf('auth.post("/whatsapp/verify"');
    const end = authSource.indexOf('auth.get("/nonce"', start);
    const source = authSource.slice(start, end);

    const tenantResolved = source.indexOf("const tenantResult = await resolveAndValidateTenant");
    const policyCheck = source.indexOf("validatePhoneAbusePolicy", tenantResolved);
    const tenantLink = source.indexOf("await ensureUserTenantLink", tenantResolved);
    const sessionResponse = source.indexOf("await buildAuthOrMfaResponse", tenantResolved);

    expect(tenantResolved).toBeGreaterThanOrEqual(0);
    expect(policyCheck).toBeGreaterThan(tenantResolved);
    expect(policyCheck).toBeLessThan(tenantLink);
    expect(policyCheck).toBeLessThan(sessionResponse);
  });

  it("uses one canonical tenant for Telegram and Farcaster login checks and session minting", () => {
    for (const [route, method] of [
      ['auth.post("/telegram/verify"', '"telegram"'],
      ['auth.post("/farcaster/verify"', '"farcaster"'],
    ] as const) {
      const start = authSource.indexOf(route);
      const end = authSource.indexOf("\n});", start);
      const source = authSource.slice(start, end);
      const mismatchCheck = source.indexOf("tenantId and X-Steward-Tenant must match");
      const initialMethodCheck = source.indexOf("requireTenantLoginMethodAllowed", mismatchCheck);
      const tenantResolved = source.indexOf("const tenantResult = await resolveAndValidateTenant");
      const resolvedMethodCheck = source.indexOf("requireTenantLoginMethodAllowed", tenantResolved);
      const tenantLink = source.indexOf("await ensureUserTenantLink", tenantResolved);
      const sessionResponse = source.indexOf("await buildAuthOrMfaResponse", tenantResolved);

      expect(start).toBeGreaterThanOrEqual(0);
      expect(mismatchCheck).toBeGreaterThanOrEqual(0);
      expect(initialMethodCheck).toBeGreaterThan(mismatchCheck);
      expect(source).toContain(method);
      expect(tenantResolved).toBeGreaterThan(initialMethodCheck);
      expect(resolvedMethodCheck).toBeGreaterThan(tenantResolved);
      expect(resolvedMethodCheck).toBeLessThan(tenantLink);
      expect(resolvedMethodCheck).toBeLessThan(sessionResponse);
    }
  });
});

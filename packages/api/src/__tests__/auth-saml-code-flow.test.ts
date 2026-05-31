import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("enterprise SAML authorization-code SSO hardening", () => {
  it("adds SP-initiated login with RelayState, InResponseTo, app PKCE, and redirect allowlist", () => {
    const source = read("packages/api/src/routes/auth.ts");
    const loginStart = source.indexOf('auth.get("/saml/:tenantId/login"');
    const metadataStart = source.indexOf('auth.get("/saml/:tenantId/metadata"');
    expect(loginStart).toBeGreaterThanOrEqual(0);
    expect(metadataStart).toBeGreaterThan(loginStart);
    const loginRoute = source.slice(loginStart, metadataStart);

    expect(loginRoute).toContain("response_type must be 'code'");
    expect(loginRoute).toContain("code_challenge is required for response_type=code");
    expect(loginRoute).toContain("code_challenge_method must be 'S256'");
    expect(loginRoute).toContain("assertAllowedOAuthRedirectUri(redirectUri, tenantId, clientId)");
    expect(loginRoute).toContain("const relayState = randomBase64Url(32)");
    expect(loginRoute).toContain("const requestId = `_${randomBase64Url(32)}`");
    expect(loginRoute).toContain("buildSamlAuthorizeUrl");
    expect(loginRoute).toContain("tenantSamlAuthnRequests");
    expect(loginRoute).toContain("saml-app-state:${relayState}");
  });

  it("validates ACS through signed SAML verifier, verified domains, replay storage, and one-time code exchange", () => {
    const source = read("packages/api/src/routes/auth.ts");
    const acsStart = source.indexOf('auth.post("/saml/:tenantId/acs"');
    const providersStart = source.indexOf('auth.get("/providers"', acsStart);
    expect(acsStart).toBeGreaterThanOrEqual(0);
    expect(providersStart).toBeGreaterThan(acsStart);
    const acsRoute = source.slice(acsStart, providersStart);

    expect(acsRoute).toContain("loadSamlAuthnRequest");
    expect(acsRoute).toContain("consumeSamlAuthnRequest");
    expect(acsRoute).toContain("verifySamlAcsResponse");
    expect(acsRoute.indexOf("loadSamlAuthnRequest")).toBeLessThan(
      acsRoute.indexOf("verifySamlAcsResponse"),
    );
    expect(acsRoute.indexOf("verifySamlAcsResponse")).toBeLessThan(
      acsRoute.indexOf("consumeSamlAuthnRequest", acsRoute.indexOf("verifySamlAcsResponse")),
    );
    expect(acsRoute).toContain("expectedRequestId: request.requestId");
    expect(acsRoute).toContain("isVerifiedSsoEmailDomainForTenant");
    expect(acsRoute).toContain("recordSamlAssertionReplay");
    expect(acsRoute).toContain("saml_assertion_replay");
    expect(acsRoute).toContain("provisionSamlUser");
    expect(acsRoute).toContain("groups: verified.groups");
    expect(acsRoute).toContain("oauth-code:${exchangeCode}");
    expect(acsRoute).toContain("setRedirectFragment(redirectUrl, { code: exchangeCode");
    expect(acsRoute).not.toContain('searchParams.set("token"');
    expect(acsRoute).not.toContain('searchParams.set("refreshToken"');
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../../../..");

function read(path: string): string {
  return readFileSync(join(ROOT, path), "utf-8");
}

describe("enterprise OIDC authorization-code SSO hardening", () => {
  it("adds SP-initiated OIDC authorize and callback routes with two PKCE layers", () => {
    const source = read("packages/api/src/routes/auth.ts");
    const authorizeStart = source.indexOf('auth.get("/oidc/:provider/authorize"');
    const callbackStart = source.indexOf('auth.get("/oidc/:provider/callback"');
    expect(authorizeStart).toBeGreaterThanOrEqual(0);
    expect(callbackStart).toBeGreaterThan(authorizeStart);
    const authorizeRoute = source.slice(authorizeStart, callbackStart);
    const callbackEnd = source.indexOf("\n/**", callbackStart + 1);
    const callbackRoute = source.slice(callbackStart, callbackEnd === -1 ? undefined : callbackEnd);

    expect(authorizeRoute).toContain("response_type must be 'code'");
    expect(authorizeRoute).toContain("code_challenge is required for response_type=code");
    expect(authorizeRoute).toContain("code_challenge_method must be 'S256'");
    expect(authorizeRoute).toContain(
      "await assertAllowedOAuthRedirectUri(redirectUri, tenantId, clientId)",
    );
    expect(authorizeRoute).toContain("const nonce = randomBase64Url(24)");
    expect(authorizeRoute).toContain("const codeVerifier = randomBase64Url(48)");
    expect(authorizeRoute).toContain("pkceChallengeForVerifier(codeVerifier, \"S256\")");
    expect(authorizeRoute).toContain('authUrl.searchParams.set("nonce", nonce)');
    expect(authorizeRoute).toContain(
      'authUrl.searchParams.set("code_challenge", providerCodeChallenge)',
    );
    expect(authorizeRoute).toContain('`oidc:${state}`');

    expect(callbackRoute).toContain('await getChallengeStore().consume(`oidc:${state}`)');
    expect(callbackRoute).toContain("stateData.providerId !== providerId");
    expect(callbackRoute).toContain("exchangeOidcAuthorizationCode");
    expect(callbackRoute).toContain("verifyOidcJwt(stateData.tenantId, provider, idToken)");
    expect(callbackRoute).toContain("verified.claims.nonce !== stateData.nonce");
    expect(callbackRoute).toContain("Enterprise OIDC SSO requires a verified email claim");
    expect(callbackRoute).toContain("isVerifiedSsoEmailDomainForTenant");
    expect(callbackRoute).toContain("Enterprise OIDC SSO email domain is not verified");
    expect(callbackRoute).toContain("provisionOidcUser");
    expect(callbackRoute).toContain('tenantRole: "viewer"');
    expect(callbackRoute).toContain("oauth-code:${exchangeCode}");
    expect(callbackRoute).toContain("setRedirectFragment(redirectUrl, { code: exchangeCode");
  });

  it("does not expose Steward access or refresh tokens through OIDC redirects", () => {
    const source = read("packages/api/src/routes/auth.ts");
    const callbackStart = source.indexOf('auth.get("/oidc/:provider/callback"');
    const callbackEnd = source.indexOf("\n/**", callbackStart + 1);
    const callbackRoute = source.slice(callbackStart, callbackEnd === -1 ? undefined : callbackEnd);

    expect(callbackRoute).not.toContain('searchParams.set("token"');
    expect(callbackRoute).not.toContain('searchParams.set("refreshToken"');
    expect(callbackRoute).toContain("OAUTH_CODE_TTL_MS");
    expect(source).toContain("async function exchangeOidcAuthorizationCode");
    expect(source).toContain('if (!provider.clientId || !provider.tokenUrl)');
    expect(source).toContain('body.set("client_secret", secret)');
    expect(source).toContain("postPublicOidcTokenEndpoint(provider.tokenUrl, body)");
    expect(source).toContain("OIDC token endpoint redirects are not allowed");
    expect(source).toContain("assertPublicOidcAddress");
    expect(source).toContain("OIDC token endpoint did not return an id_token");
  });
});

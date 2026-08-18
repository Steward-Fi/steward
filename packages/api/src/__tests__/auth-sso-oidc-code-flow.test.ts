import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { assertPublicHttpsEndpoint } from "../../../auth/src/public-endpoint";

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
    expect(authorizeRoute).toContain(
      'assertPublicHttpsEndpoint(provider.authorizationUrl, "OIDC authorization endpoint")',
    );
    expect(authorizeRoute).toContain("const nonce = randomBase64Url(24)");
    expect(authorizeRoute).toContain("const codeVerifier = randomBase64Url(48)");
    expect(authorizeRoute).toContain('pkceChallengeForVerifier(codeVerifier, "S256")');
    expect(authorizeRoute).toContain('authUrl.searchParams.set("nonce", nonce)');
    expect(authorizeRoute).toContain(
      'authUrl.searchParams.set("code_challenge", providerCodeChallenge)',
    );
    expect(authorizeRoute).toContain("`oidc:${state}`");

    expect(callbackRoute).toContain("await getChallengeStore().get(stateKey)");
    expect(callbackRoute).toContain("stateData.providerId !== providerId");
    expect(callbackRoute).toContain("exchangeOidcAuthorizationCode");
    expect(callbackRoute).toContain("verifyOidcJwt(stateData.tenantId, provider, idToken)");
    expect(callbackRoute).toContain("verified.claims.nonce !== stateData.nonce");
    expect(callbackRoute).toContain("Enterprise OIDC SSO requires a verified email claim");
    expect(callbackRoute).toContain("isVerifiedSsoEmailDomainForTenant");
    expect(callbackRoute).toContain("Enterprise OIDC SSO email domain is not verified");
    expect(callbackRoute.indexOf("await getChallengeStore().get(stateKey)")).toBeLessThan(
      callbackRoute.indexOf("exchangeOidcAuthorizationCode"),
    );
    expect(callbackRoute.indexOf("await getChallengeStore().consume(stateKey)")).toBeGreaterThan(
      callbackRoute.indexOf("isVerifiedSsoEmailDomainForTenant"),
    );
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
    expect(source).toContain("if (!provider.clientId || !provider.tokenUrl)");
    expect(source).toContain('body.set("client_secret", secret)');
    expect(source).toContain("postPublicOidcTokenEndpoint(provider.tokenUrl, body)");
    expect(source).toContain("OIDC token endpoint redirects are not allowed");
    expect(source).toContain("assertPublicInternetAddress");
    expect(source).toContain("OIDC token endpoint did not return an id_token");
    expect(source).toContain("Direct JWT login is disabled for authorization-code OIDC providers");
  });

  it("uses the shared public-destination classifier for token URL and DNS answers", () => {
    const source = read("packages/api/src/routes/auth.ts");
    expect(source).toContain('assertPublicHttpsEndpoint(tokenUrl, "OIDC token endpoint")');
    expect(source).toContain('assertPublicInternetAddress(address, family, "OIDC token endpoint")');
    expect(source).not.toContain("function isPrivateOidcIpv4");
    expect(source).not.toContain("function isPrivateOidcIpv6");
  });

  it("rejects IPv4-compatible and special-use token endpoint literals", () => {
    for (const tokenUrl of [
      "https://[::127.0.0.1]/token",
      "https://[::ffff:0:127.0.0.1]/token",
      "https://192.0.2.1/token",
      "https://198.51.100.1/token",
      "https://203.0.113.1/token",
      "https://[100::1]/token",
      "https://[3fff::1]/token",
    ]) {
      expect(() => assertPublicHttpsEndpoint(tokenUrl, "OIDC token endpoint"), tokenUrl).toThrow(
        "OIDC token endpoint must be a public https URL",
      );
    }
  });

  it("rejects local and special-use browser authorization destinations", () => {
    for (const authorizationUrl of [
      "https://[::127.0.0.1]/authorize",
      "https://[::ffff:0:127.0.0.1]/authorize",
      "https://192.0.2.1/authorize",
      "https://[100::1]/authorize",
      "https://[3fff::1]/authorize",
      "https://user:secret@idp.example.com/authorize",
    ]) {
      expect(
        () => assertPublicHttpsEndpoint(authorizationUrl, "OIDC authorization endpoint"),
        authorizationUrl,
      ).toThrow("OIDC authorization endpoint must be a public https URL");
    }
  });

  it("never echoes the IdP-supplied error string into the token-exchange 502", () => {
    const source = read("packages/api/src/routes/auth.ts");
    const exchangeStart = source.indexOf("async function exchangeOidcAuthorizationCode");
    expect(exchangeStart).toBeGreaterThanOrEqual(0);
    const exchangeEnd = source.indexOf("\nasync function ", exchangeStart + 1);
    const exchange = source.slice(exchangeStart, exchangeEnd === -1 ? undefined : exchangeEnd);

    // The IdP-controlled payload.error must be logged server-side, not thrown
    // (the route surfaces err.message in its 502 response).
    const rejectStart = exchange.indexOf("if (!response.ok)");
    expect(rejectStart).toBeGreaterThanOrEqual(0);
    const rejectBlock = exchange.slice(rejectStart, exchange.indexOf("}", rejectStart) + 1);
    expect(exchange).toContain("console.warn(");
    expect(exchange).not.toContain("throw new Error(error)");
    expect(exchange).toContain(
      'throw new Error("OIDC token endpoint rejected authorization code")',
    );
    expect(rejectBlock).not.toContain("throw new Error(error)");
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("wallet nonce binding hardening", () => {
  it("rate limits public auth routes that allocate backend challenge state", () => {
    const nonceRouteStart = authSource.indexOf('auth.get("/nonce"');
    expect(nonceRouteStart).toBeGreaterThanOrEqual(0);
    expect(
      authSource.indexOf('checkAuthRateLimit(c, "siwe-nonce"', nonceRouteStart),
    ).toBeGreaterThan(nonceRouteStart);

    const oauthAuthorizeStart = authSource.indexOf('auth.get("/oauth/:provider/authorize"');
    expect(oauthAuthorizeStart).toBeGreaterThanOrEqual(0);
    expect(
      authSource.indexOf(
        "checkAuthRateLimit(c, `oauth-authorize:${providerName}`",
        oauthAuthorizeStart,
      ),
    ).toBeGreaterThan(oauthAuthorizeStart);
    expect(
      authSource.indexOf("getChallengeStore().set(`oauth:${state}`", oauthAuthorizeStart),
    ).toBeGreaterThan(oauthAuthorizeStart);
  });

  it("does not burn OAuth callback state before provider verification succeeds", () => {
    const callbackStart = authSource.indexOf('auth.get("/oauth/:provider/callback"');
    expect(callbackStart).toBeGreaterThanOrEqual(0);
    const callbackEnd = authSource.indexOf("\n/**", callbackStart + 1);
    const callbackRoute = authSource.slice(
      callbackStart,
      callbackEnd === -1 ? undefined : callbackEnd,
    );

    const stateLoad = callbackRoute.indexOf("await getChallengeStore().get(stateKey)");
    const exchange = callbackRoute.indexOf("oauthClient.exchangeCode");
    const userInfo = callbackRoute.indexOf("oauthClient.getUserInfo");
    const consume = callbackRoute.indexOf("await getChallengeStore().consume(stateKey)");

    expect(stateLoad).toBeGreaterThanOrEqual(0);
    expect(exchange).toBeGreaterThan(stateLoad);
    expect(userInfo).toBeGreaterThan(exchange);
    expect(consume).toBeGreaterThan(userInfo);
    expect(callbackRoute).toContain("Invalid or already-used OAuth state");
  });

  it("binds Sign in with Apple id_tokens to an authorize-request nonce", () => {
    const authorizeStart = authSource.indexOf('auth.get("/oauth/:provider/authorize"');
    const callbackStart = authSource.indexOf('auth.get("/oauth/:provider/callback"');
    expect(authorizeStart).toBeGreaterThanOrEqual(0);
    expect(callbackStart).toBeGreaterThan(authorizeStart);
    const authorizeRoute = authSource.slice(authorizeStart, callbackStart);
    const callbackEnd = authSource.indexOf("\n/**", callbackStart + 1);
    const callbackRoute = authSource.slice(
      callbackStart,
      callbackEnd === -1 ? undefined : callbackEnd,
    );

    expect(authorizeRoute).toContain('providerName === "apple" ? randomBase64Url(24)');
    expect(authorizeRoute).toContain('url.searchParams.set("nonce", oidcNonce)');
    expect(authorizeRoute).toContain("...(oidcNonce ? { oidcNonce } : {})");
    expect(callbackRoute).toContain('if (providerName === "apple")');
    expect(callbackRoute).toContain("oauthClient.setExpectedNonce(stateData.oidcNonce)");
    expect(callbackRoute.indexOf("oauthClient.setExpectedNonce")).toBeLessThan(
      callbackRoute.indexOf("oauthClient.getUserInfo"),
    );
  });

  it("does not trust request Host for OAuth callback URLs in production", () => {
    const helperStart = authSource.indexOf("function authCallbackBaseUrl");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const helperEnd = authSource.indexOf("function buildOAuthCallbackUrl", helperStart);
    const helper = authSource.slice(helperStart, helperEnd);
    expect(helper).toContain("process.env.APP_URL");
    expect(helper).toContain('process.env.NODE_ENV === "production"');
    expect(helper).toContain("APP_URL is required for OAuth/OIDC callback URLs in production");
    expect(helper.indexOf('c.req.header("host")')).toBeGreaterThan(
      helper.indexOf('process.env.NODE_ENV === "production"'),
    );
  });

  it("binds issued wallet nonces to domain, origin, and tenant context", () => {
    const nonceRouteStart = authSource.indexOf('auth.get("/nonce"');
    expect(nonceRouteStart).toBeGreaterThanOrEqual(0);
    expect(authSource.indexOf("requiredOriginHostFromRequest(c)", nonceRouteStart)).toBeGreaterThan(
      nonceRouteStart,
    );
    expect(
      authSource.indexOf(
        "SIWE nonce requests require an allowed Origin or Referer",
        nonceRouteStart,
      ),
    ).toBeGreaterThan(nonceRouteStart);
    expect(authSource.indexOf("setSiweNonce(nonce, {", nonceRouteStart)).toBeGreaterThan(
      nonceRouteStart,
    );
    expect(
      authSource.indexOf("allowedDomains: getAllowedSiweDomains(c)", nonceRouteStart),
    ).toBeGreaterThan(nonceRouteStart);
    expect(authSource.indexOf("originHost,", nonceRouteStart)).toBeGreaterThan(nonceRouteStart);
    expect(authSource.indexOf("tenantId: tenantId || undefined", nonceRouteStart)).toBeGreaterThan(
      nonceRouteStart,
    );
  });

  it("validates consumed nonce bindings before wallet sessions are minted", () => {
    const siweStart = authSource.indexOf('auth.post("/verify"');
    expect(siweStart).toBeGreaterThanOrEqual(0);
    const siweNonceCheck = authSource.indexOf(
      "validateConsumedSiweNonce(await consumeSiweNonce(siweMessage.nonce)",
      siweStart,
    );
    expect(siweNonceCheck).toBeGreaterThan(siweStart);
    expect(siweNonceCheck).toBeLessThan(authSource.indexOf("viemVerifyMessage", siweStart));
    expect(authSource).toContain('return "Nonce was not bound to an origin"');
    expect(authSource).toContain("evaluateSiwePolicy(");

    const siwsStart = authSource.indexOf('auth.post("/verify/solana"');
    expect(siwsStart).toBeGreaterThanOrEqual(0);
    const siwsNonceCheck = authSource.indexOf(
      "validateConsumedSiweNonce(await consumeSiweNonce(parsed.nonce)",
      siwsStart,
    );
    expect(siwsNonceCheck).toBeGreaterThan(siwsStart);
    expect(siwsNonceCheck).toBeLessThan(
      authSource.indexOf("verifySolanaMessageSignature", siwsStart),
    );

    const farcasterStart = authSource.indexOf('auth.post("/farcaster/verify"');
    expect(farcasterStart).toBeGreaterThanOrEqual(0);
    const farcasterNonceCheck = authSource.indexOf("validateConsumedSiweNonce(", farcasterStart);
    expect(farcasterNonceCheck).toBeGreaterThan(farcasterStart);
    expect(farcasterNonceCheck).toBeLessThan(
      authSource.indexOf("buildAuthOrMfaResponse", farcasterStart),
    );
  });
});

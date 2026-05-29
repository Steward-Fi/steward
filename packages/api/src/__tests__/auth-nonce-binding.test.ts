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

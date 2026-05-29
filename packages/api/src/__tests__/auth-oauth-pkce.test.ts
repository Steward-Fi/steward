import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("OAuth broker PKCE policy", () => {
  it("requires S256 and does not allow plain code challenges", () => {
    expect(authSource).toContain('codeChallengeMethod !== "S256"');
    expect(authSource).toContain("code_challenge_method must be 'S256'");
    expect(authSource).not.toContain(
      'codeChallengeMethod !== "S256" && codeChallengeMethod !== "plain"',
    );
  });

  it("does not exchange raw provider codes unless explicitly unsafe-enabled", () => {
    const tokenStart = authSource.indexOf('auth.post("/oauth/:provider/token"');
    expect(tokenStart).toBeGreaterThanOrEqual(0);
    expect(authSource.indexOf("getOAuthCodeStore().consume", tokenStart)).toBeLessThan(
      authSource.indexOf("oauthClient.exchangeCode", tokenStart),
    );
    expect(
      authSource.indexOf("isUnsafeUnboundOAuthProviderCodeExchangeAllowed", tokenStart),
    ).toBeLessThan(authSource.indexOf("oauthClient.exchangeCode", tokenStart));
    expect(authSource).toContain("STEWARD_ALLOW_UNBOUND_OAUTH_PROVIDER_CODE_EXCHANGE");
  });

  it("validates exchange-code PKCE before consuming the one-time code", () => {
    const exchangeStart = authSource.indexOf('auth.post("/oauth/exchange"');
    expect(exchangeStart).toBeGreaterThanOrEqual(0);
    const mismatchCheck = authSource.indexOf("code_verifier_mismatch", exchangeStart);
    const lock = authSource.indexOf("lockOAuthCodeRedemption(code)", exchangeStart);
    const consume = authSource.indexOf("getOAuthCodeStore().consume(codeKey)", exchangeStart);
    expect(mismatchCheck).toBeGreaterThan(exchangeStart);
    expect(lock).toBeGreaterThan(mismatchCheck);
    expect(consume).toBeGreaterThan(lock);
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("passkey MFA hardening", () => {
  it("exposes session-bound passkey MFA options and verification routes", () => {
    const optionsStart = authSource.indexOf('auth.post("/mfa/passkey/options"');
    const completeStart = authSource.indexOf('auth.post("/mfa/passkey/complete"');
    const verifyStart = authSource.indexOf('auth.post("/mfa/passkey/verify"');

    expect(optionsStart).toBeGreaterThanOrEqual(0);
    expect(completeStart).toBeGreaterThan(optionsStart);
    expect(verifyStart).toBeGreaterThan(completeStart);
    expect(authSource.indexOf("requireSession(c)", optionsStart)).toBeGreaterThan(optionsStart);
    expect(authSource.indexOf("authenticators.userId", optionsStart)).toBeGreaterThan(optionsStart);
    expect(authSource.indexOf("allowCredentials", optionsStart)).toBeGreaterThan(optionsStart);
    expect(authSource.indexOf("passkeyMfaChallengeKey", optionsStart)).toBeGreaterThan(
      optionsStart,
    );
    expect(authSource.indexOf("requireSession(c)", verifyStart)).toBeGreaterThan(verifyStart);
  });

  it("verifies WebAuthn before consuming the MFA challenge and stamps passkey MFA claims", () => {
    const handlerStart = authSource.indexOf("const completePasskeyMfaHandler");
    expect(handlerStart).toBeGreaterThanOrEqual(0);

    const readChallenge = authSource.indexOf("getChallengeStore().get(challengeKey)", handlerStart);
    const webauthnVerify = authSource.indexOf(".verifyAuthentication(", handlerStart);
    const consumeChallenge = authSource.indexOf(
      "getChallengeStore().consume(challengeKey)",
      handlerStart,
    );
    const counterUpdate = authSource.indexOf(".set({ counter:", handlerStart);
    const mfaMethod = authSource.indexOf('mfaMethod: "passkey"', handlerStart);

    expect(readChallenge).toBeGreaterThan(handlerStart);
    expect(webauthnVerify).toBeGreaterThan(readChallenge);
    expect(consumeChallenge).toBeGreaterThan(webauthnVerify);
    expect(counterUpdate).toBeGreaterThan(consumeChallenge);
    expect(mfaMethod).toBeGreaterThan(counterUpdate);
  });
});

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
    const counterUpdate = authSource.indexOf(".update(authenticators)", handlerStart);
    const mfaMethod = authSource.indexOf('mfaMethod: "passkey"', handlerStart);

    expect(readChallenge).toBeGreaterThan(handlerStart);
    expect(webauthnVerify).toBeGreaterThan(readChallenge);
    expect(consumeChallenge).toBeGreaterThan(webauthnVerify);
    expect(counterUpdate).toBeGreaterThan(consumeChallenge);
    expect(mfaMethod).toBeGreaterThan(counterUpdate);
  });

  it("rejects passkey counter regression before persisting the counter (SEC-141)", () => {
    // Both the login route and the MFA complete/verify handler must reject a
    // non-increasing counter from an authenticator that previously reported
    // one — and must do so before updating the stored counter.
    const guard = "verification.authenticationInfo.newCounter <= cred.counter";

    const mfaStart = authSource.indexOf("const completePasskeyMfaHandler");
    expect(mfaStart).toBeGreaterThanOrEqual(0);
    const mfaGuard = authSource.indexOf(guard, mfaStart);
    const mfaCounterUpdate = authSource.indexOf(".update(authenticators)", mfaStart);
    const mfaCompareAndSwap = authSource.indexOf(
      "eq(authenticators.counter, cred.counter)",
      mfaCounterUpdate,
    );
    expect(mfaGuard).toBeGreaterThan(mfaStart);
    expect(mfaGuard).toBeLessThan(mfaCounterUpdate);
    expect(mfaCompareAndSwap).toBeGreaterThan(mfaCounterUpdate);

    const loginStart = authSource.indexOf('auth.post("/passkey/login/verify"');
    expect(loginStart).toBeGreaterThanOrEqual(0);
    const loginGuard = authSource.indexOf(guard, loginStart);
    const loginCounterUpdate = authSource.indexOf(".update(authenticators)", loginStart);
    const loginCompareAndSwap = authSource.indexOf(
      "eq(authenticators.counter, cred.counter)",
      loginCounterUpdate,
    );
    expect(loginGuard).toBeGreaterThan(loginStart);
    expect(loginGuard).toBeLessThan(loginCounterUpdate);
    expect(loginCompareAndSwap).toBeGreaterThan(loginCounterUpdate);
  });

  it("atomically claims passkey counters to reject concurrent clones", () => {
    const compareAndSwap = "eq(authenticators.counter, cred.counter)";

    const mfaStart = authSource.indexOf("const completePasskeyMfaHandler");
    const mfaCas = authSource.indexOf(compareAndSwap, mfaStart);
    const mfaFailure = authSource.indexOf("updatedMfaCounters.length !== 1", mfaCas);
    expect(mfaCas).toBeGreaterThan(mfaStart);
    expect(mfaFailure).toBeGreaterThan(mfaCas);

    const loginStart = authSource.indexOf('auth.post("/passkey/login/verify"');
    const loginCas = authSource.indexOf(compareAndSwap, loginStart);
    const loginFailure = authSource.indexOf("updatedCounters.length !== 1", loginCas);
    expect(loginCas).toBeGreaterThan(loginStart);
    expect(loginFailure).toBeGreaterThan(loginCas);
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

describe("MFA challenge completion", () => {
  it("does not consume pending login challenges before validating MFA codes", () => {
    const totpStart = authSource.indexOf('auth.post("/mfa/totp/complete"');
    const smsStart = authSource.indexOf('auth.post("/mfa/sms/complete"');
    expect(authSource.indexOf("get(challengeKey)", totpStart)).toBeLessThan(
      authSource.indexOf("verifyStoredTotp", totpStart),
    );
    // TOTP branch: the code is verified before the challenge is consumed
    // (the consume between verifyStoredTotp and the lastAcceptedStep write).
    const verifyTotp = authSource.indexOf("verifyStoredTotp", totpStart);
    const stamp = authSource.indexOf("lastAcceptedStep", verifyTotp);
    const totpConsume = authSource.indexOf("consume(challengeKey)", verifyTotp);
    expect(totpConsume).toBeGreaterThan(verifyTotp);
    expect(totpConsume).toBeLessThan(stamp);
    expect(authSource.indexOf("get(challengeKey)", smsStart)).toBeLessThan(
      authSource.indexOf("verifyOtp", smsStart),
    );
    expect(authSource.indexOf("consume(challengeKey)", smsStart)).toBeGreaterThan(
      authSource.indexOf("verifyOtp", smsStart),
    );
  });

  it("consumes the challenge before burning a recovery code (SEC-146)", () => {
    // The burn is irreversible: a concurrent completion must lose on the
    // challenge consume, not forfeit a valid recovery code to a 401.
    const totpStart = authSource.indexOf('auth.post("/mfa/totp/complete"');
    const totpEnd = authSource.indexOf("\nauth.", totpStart + 1);
    const route = authSource.slice(totpStart, totpEnd === -1 ? undefined : totpEnd);

    const recoveryBranch = route.indexOf("if (hasRecoveryCode) {");
    expect(recoveryBranch).toBeGreaterThanOrEqual(0);
    const consume = route.indexOf("consume(challengeKey)", recoveryBranch);
    const burn = route.indexOf("verifyRecoveryCode(", recoveryBranch);
    expect(consume).toBeGreaterThan(recoveryBranch);
    expect(burn).toBeGreaterThan(consume);
    // The old trailing "consume after burn" block must not come back.
    expect(route).not.toContain("hasRecoveryCode && (await getMfaBackend().consume(challengeKey))");
  });
});

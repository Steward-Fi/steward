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
    expect(authSource.indexOf("consume(challengeKey)", totpStart)).toBeGreaterThan(
      authSource.indexOf("verifyStoredTotp", totpStart),
    );
    expect(authSource.indexOf("get(challengeKey)", smsStart)).toBeLessThan(
      authSource.indexOf("verifyOtp", smsStart),
    );
    expect(authSource.indexOf("consume(challengeKey)", smsStart)).toBeGreaterThan(
      authSource.indexOf("verifyOtp", smsStart),
    );
  });
});

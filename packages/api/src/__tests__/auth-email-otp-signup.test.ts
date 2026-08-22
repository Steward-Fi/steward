/**
 * Email-OTP verified passkey signup (Privy-style).
 *
 * Canonical flow: POST /email/otp/send → user receives 6-digit code →
 * POST /email/otp/verify → short-lived single-use verified-email grant →
 * passkey register/options (peek) + register/verify (consume) WITHOUT a
 * session. Closes the pre-hijack vector (registration requires proof of
 * email ownership) while restoring one-tap signup UX.
 */
import { afterAll, beforeAll, describe, expect, it } from "bun:test";

process.env.STEWARD_JWT_SECRET ??= "test-secret-key-that-is-long-enough-for-hs256";
process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
process.env.STEWARD_KDF_SALT ??= "dGVzdC1zYWx0LXRlc3Qtc2FsdA==";

import { EmailAuth } from "@stwd/auth";

describe("EmailAuth OTP primitives", () => {
  let emailAuth: EmailAuth;
  let lastEmailBody = "";

  beforeAll(() => {
    emailAuth = new EmailAuth({
      from: "login@test.steward.fi",
      baseUrl: "https://test.steward.fi",
      provider: {
        async send(_to: string, _subject: string, body: string) {
          lastEmailBody = body;
          return { provider: "test" };
        },
      },
    });
  });

  afterAll(() => {
    emailAuth.destroy();
  });

  function extractCode(): string {
    const m = lastEmailBody.match(/\b(\d{6})\b/);
    if (!m) throw new Error(`no 6-digit code in email body: ${lastEmailBody}`);
    return m[1];
  }

  it("sends a 6-digit code and verifies it once", async () => {
    await emailAuth.sendOtp("otp-user@example.com", { tenantId: "waifu" });
    const code = extractCode();
    expect(code).toMatch(/^\d{6}$/);

    const ok = await emailAuth.verifyOtp("otp-user@example.com", code, "waifu");
    expect(ok).toBe(true);

    // single use — second verify fails
    const again = await emailAuth.verifyOtp("otp-user@example.com", code, "waifu");
    expect(again).toBe(false);
  });

  it("binds the code to the email", async () => {
    await emailAuth.sendOtp("alice@example.com", { tenantId: "waifu" });
    const code = extractCode();
    const wrongEmail = await emailAuth.verifyOtp("bob@example.com", code, "waifu");
    expect(wrongEmail).toBe(false);
    // and the right email still works (wrong-email attempt must not burn it —
    // the store key includes the email so bob's consume missed alice's entry)
    const ok = await emailAuth.verifyOtp("alice@example.com", code, "waifu");
    expect(ok).toBe(true);
  });

  it("binds the code to the tenant", async () => {
    await emailAuth.sendOtp("carol@example.com", { tenantId: "waifu" });
    const code = extractCode();
    const wrongTenant = await emailAuth.verifyOtp("carol@example.com", code, "elizacloud");
    expect(wrongTenant).toBe(false);
    const ok = await emailAuth.verifyOtp("carol@example.com", code, "waifu");
    expect(ok).toBe(true);
  });

  it("rejects malformed codes without store lookups", async () => {
    expect(await emailAuth.verifyOtp("x@example.com", "12345", "waifu")).toBe(false);
    expect(await emailAuth.verifyOtp("x@example.com", "abcdef", "waifu")).toBe(false);
    expect(await emailAuth.verifyOtp("x@example.com", "1234567", "waifu")).toBe(false);
    expect(await emailAuth.verifyOtp("x@example.com", "", "waifu")).toBe(false);
  });

  it("expires codes after the TTL", async () => {
    const shortAuth = new EmailAuth({
      from: "login@test.steward.fi",
      baseUrl: "https://test.steward.fi",
      tokenTtlMs: 10, // 10ms
      provider: {
        async send(_to: string, _subject: string, body: string) {
          lastEmailBody = body;
          return { provider: "test" };
        },
      },
    });
    await shortAuth.sendOtp("expired@example.com", { tenantId: "waifu" });
    const code = extractCode();
    await new Promise((r) => setTimeout(r, 30));
    expect(await shortAuth.verifyOtp("expired@example.com", code, "waifu")).toBe(false);
    shortAuth.destroy();
  });

  it("subject contains the code (glanceable in notifications)", async () => {
    let subject = "";
    const subjAuth = new EmailAuth({
      from: "login@test.steward.fi",
      baseUrl: "https://test.steward.fi",
      provider: {
        async send(_to: string, subj: string, body: string) {
          subject = subj;
          lastEmailBody = body;
          return { provider: "test" };
        },
      },
    });
    await subjAuth.sendOtp("subject@example.com", { tenantId: "waifu" });
    const code = extractCode();
    expect(subject).toContain(code);
    subjAuth.destroy();
  });
});

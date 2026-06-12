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
        },
      },
    });
    await subjAuth.sendOtp("subject@example.com", { tenantId: "waifu" });
    const code = extractCode();
    expect(subject).toContain(code);
    subjAuth.destroy();
  });
});

// ── Route-level invariants (source inspection, mirrors auth-passkey-enumeration) ──

import { readFileSync } from "node:fs";
import { join } from "node:path";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

function routeBody(start: string, end: string): string {
  const s = authSource.indexOf(start);
  expect(s).toBeGreaterThan(-1);
  const e = authSource.indexOf(end, s);
  expect(e).toBeGreaterThan(s);
  return authSource.slice(s, e);
}

describe("OTP route security invariants", () => {
  it("otp/verify enforces a per-{email,tenant} brute-force limiter", () => {
    const body = routeBody('auth.post("/email/otp/verify"', '// ── Guest');
    expect(body).toContain("email-otp-verify-target");
    expect(body).toContain("${resolvedTenantId}:${email}");
  });

  it("otp/send keeps the same abuse gates as magic-link send", () => {
    const body = routeBody('auth.post("/email/otp/send"', 'auth.post("/email/otp/verify"');
    expect(body).toContain("verifyCaptchaToken");
    expect(body).toContain("validateEmailAbusePolicy");
    expect(body).toContain("requireTenantLoginMethodAllowed");
    expect(body).toContain("requireNonSsoEmailLoginAllowed");
    expect(body).toContain("email-otp-send-destination");
  });

  it("register/options PEEKS the grant (non-consuming) so cancelled prompts don't burn it", () => {
    const body = routeBody('auth.post("/passkey/register/options"', 'auth.post("/passkey/register/verify"');
    expect(body).toContain("peekEmailGrant");
    expect(body).not.toContain("consumeEmailGrant");
    // session path must remain for logged-in add-passkey
    expect(body).toContain("requireSession");
  });

  it("register/verify peeks pre-ceremony and CONSUMES only after WebAuthn succeeds", () => {
    const start = authSource.indexOf('auth.post("/passkey/register/verify"');
    const end = authSource.indexOf('auth.post("/passkey/login/options"', start);
    const body = authSource.slice(start, end);
    // peek happens before the ceremony (cheap reject), consume after success
    const peekIdx = body.indexOf("peekEmailGrant");
    const ceremonyIdx = body.indexOf("verifyRegistration");
    const consumeIdx = body.indexOf("consumeEmailGrant");
    expect(peekIdx).toBeGreaterThan(-1);
    expect(consumeIdx).toBeGreaterThan(ceremonyIdx);
    expect(ceremonyIdx).toBeGreaterThan(peekIdx);
    expect(body).toContain("emailVerified: true");
    // grant-less path still requires a session
    expect(body).toContain("requireSession");
    // tenant joining stays join_mode-gated (no invite bypass via grant)
    expect(body).toContain("resolveAndValidateTenant");
    // resolved tenant must equal the grant-bound tenant (no tenant pivot)
    expect(body).toContain("tenantId !== grantTenantId");
  });

  it("register/options is rate limited (pre-auth reachable)", () => {
    const body = routeBody('auth.post("/passkey/register/options"', 'auth.post("/passkey/register/verify"');
    expect(body).toContain("passkey-register-options");
  });

  it("grants are single-purpose: issued only by otp/verify", () => {
    const matches = authSource.match(/issueEmailGrant\(/g) ?? [];
    // one definition + exactly one call site (otp/verify)
    expect(matches.length).toBe(2);
  });
});

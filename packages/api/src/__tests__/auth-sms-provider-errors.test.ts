import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import {
  SmsChallengeInProgressError,
  SmsDeliveryError,
  SmsVerificationError,
  SmsVerificationNotAttemptedError,
} from "@stwd/auth";

process.env.NODE_ENV = "test";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.STEWARD_MASTER_PASSWORD = "sms-provider-errors-master-password";
process.env.STEWARD_JWT_SECRET = "sms-provider-errors-jwt-secret-with-enough-entropy";
process.env.STEWARD_AUDIT_HMAC_KEY = "sms-provider-errors-audit-key-with-enough-entropy";
delete process.env.SMS_PROVIDER;
process.env.TWILIO_ACCOUNT_SID = `AC${"a".repeat(32)}`;
process.env.TWILIO_AUTH_TOKEN = "twilio-test-auth-token";
process.env.TWILIO_VERIFY_SERVICE_SID = `VA${"b".repeat(32)}`;
process.env.TWILIO_VERIFY_TOKEN_TTL_SECONDS = "600";
process.env.TWILIO_FROM = "+14155550000";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";

const { app, createApp } = await import("../app");
const {
  claimSmsVerifyAttempt,
  clearSmsVerifyFailures,
  getPhoneAuth,
  getSmsVerifyFailedAttempts,
  initAuthStores,
  releaseSmsVerifyAttempt,
  releaseUnattemptedSmsVerifyClaim,
} = await import("../routes/auth");

const ORIGINAL_CONSOLE_ERROR = console.error;
const ORIGINAL_FETCH = globalThis.fetch;

beforeEach(async () => {
  process.env.TWILIO_VERIFY_TOKEN_TTL_SECONDS = "600";
  await initAuthStores(false);
});

afterEach(() => {
  console.error = ORIGINAL_CONSOLE_ERROR;
  globalThis.fetch = ORIGINAL_FETCH;
});

describe("SMS provider HTTP errors", () => {
  it("selects Twilio Verify ahead of the legacy Messaging sender", async () => {
    let requestUrl = "";
    const createdAt = new Date(Date.now() - 1000);
    globalThis.fetch = (async (input: string | URL | Request) => {
      requestUrl = String(input);
      return new Response(
        JSON.stringify({ status: "pending", date_created: createdAt.toISOString() }),
        { status: 201 },
      );
    }) as typeof fetch;
    const phoneAuth = getPhoneAuth();
    const { expiresAt } = await phoneAuth.sendOtp("+14155550123", "login:tenant-a");

    expect(requestUrl).toBe(
      `https://verify.twilio.com/v2/Services/${process.env.TWILIO_VERIFY_SERVICE_SID}/Verifications`,
    );
    expect(expiresAt.getTime()).toBe(createdAt.getTime() + 10 * 60 * 1000);
  });

  it("fails closed when the Verify service TTL is not explicitly configured", () => {
    delete process.env.TWILIO_VERIFY_TOKEN_TTL_SECONDS;
    expect(() => getPhoneAuth()).toThrow("tokenTtlSeconds must be between 120 and 86400");
  });

  it.each([
    {
      path: "/auth/test-sms-delivery-error",
      error: new SmsDeliveryError("provider rejected +14155550123 with account metadata"),
      status: 503,
      message: "SMS could not be sent. Please try again later.",
    },
    {
      path: "/auth/test-sms-verification-error",
      error: new SmsVerificationError("provider timed out for code 123456"),
      status: 503,
      message: "SMS verification is temporarily unavailable. Please try again.",
    },
    {
      path: "/auth/test-sms-purpose-conflict",
      error: new SmsChallengeInProgressError(),
      status: 409,
      message: "Another SMS verification is already in progress. Complete it or try later.",
    },
  ])("maps $path to a generic actionable response", async ({ path, error, status, message }) => {
    const app = createApp();
    app.post(path, () => {
      throw error;
    });
    const logged: string[] = [];
    console.error = (...args: unknown[]) => {
      logged.push(args.map(String).join(" "));
    };

    const response = await app.request(path, { method: "POST" });
    const responseText = await response.text();

    expect(response.status).toBe(status);
    expect(JSON.parse(responseText)).toEqual({ ok: false, error: message });
    expect(logged).toEqual([]);
    expect(responseText).not.toContain("+14155550123");
    expect(responseText).not.toContain("123456");
  });

  it("cannot use a stale rollback to delete a newer attempt-slot generation", async () => {
    const phone = "+14155550124";
    const purpose = "login:default";
    const stale = await claimSmsVerifyAttempt(phone, purpose);
    expect(stale).not.toBeNull();

    await clearSmsVerifyFailures(phone, purpose);
    const current = await claimSmsVerifyAttempt(phone, purpose);
    expect(current).not.toBeNull();

    expect(await releaseSmsVerifyAttempt(stale!)).toBe(false);
    expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(1);
    expect(await releaseSmsVerifyAttempt(current!)).toBe(true);
    expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(0);
    expect(await releaseSmsVerifyAttempt(current!)).toBe(false);
  });

  it("rolls back only errors that prove no provider check was attempted", async () => {
    const phone = "+14155550125";
    const purpose = "login:default";
    const ambiguous = await claimSmsVerifyAttempt(phone, purpose);
    expect(ambiguous).not.toBeNull();
    expect(await releaseUnattemptedSmsVerifyClaim(ambiguous!, new SmsVerificationError())).toBe(
      false,
    );
    expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(1);

    await clearSmsVerifyFailures(phone, purpose);
    const notAttempted = await claimSmsVerifyAttempt(phone, purpose);
    expect(notAttempted).not.toBeNull();
    expect(
      await releaseUnattemptedSmsVerifyClaim(notAttempted!, new SmsVerificationNotAttemptedError()),
    ).toBe(true);
    expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(0);
  });

  it("retains the real-route attempt slot when a provider-check outcome is ambiguous", async () => {
    const phone = "+14155550126";
    const purpose = "login:default";
    const createdAt = new Date(Date.now() - 1000);
    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input).endsWith("/VerificationCheck")) {
        throw new Error("provider transport failed with sensitive metadata");
      }
      return new Response(
        JSON.stringify({ status: "pending", date_created: createdAt.toISOString() }),
        { status: 201 },
      );
    }) as typeof fetch;
    await getPhoneAuth().sendOtp(phone, purpose);

    const response = await app.request("/auth/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: "123456" }),
    });

    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({
      ok: false,
      error: "SMS verification is temporarily unavailable. Please try again.",
    });
    expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(1);
  });

  it("rolls back the exact real-route slot when another check holds the phone lock", async () => {
    const phone = "+14155550127";
    const purpose = "login:default";
    const createdAt = new Date(Date.now() - 1000);
    let markCheckStarted!: () => void;
    let releaseCheck!: () => void;
    const checkStarted = new Promise<void>((resolve) => {
      markCheckStarted = resolve;
    });
    const checkGate = new Promise<void>((resolve) => {
      releaseCheck = resolve;
    });
    globalThis.fetch = (async (input: string | URL | Request) => {
      if (String(input).endsWith("/VerificationCheck")) {
        markCheckStarted();
        await checkGate;
        return new Response(JSON.stringify({ status: "pending" }), { status: 200 });
      }
      return new Response(
        JSON.stringify({ status: "pending", date_created: createdAt.toISOString() }),
        { status: 201 },
      );
    }) as typeof fetch;
    const phoneAuth = getPhoneAuth();
    await phoneAuth.sendOtp(phone, purpose);
    const activeCheck = phoneAuth.verifyOtp(phone, "000000", purpose);
    await checkStarted;

    try {
      const response = await app.request("/auth/sms/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, code: "123456" }),
      });
      expect(response.status).toBe(409);
      expect(await getSmsVerifyFailedAttempts(phone, purpose)).toBe(0);
    } finally {
      releaseCheck();
    }
    await expect(activeCheck).resolves.toEqual({ valid: false });
  });

  it("applies disposition-aware rollback to every SMS verify route pattern", async () => {
    const authSource = await Bun.file(new URL("../routes/auth.ts", import.meta.url)).text();
    const userSource = await Bun.file(new URL("../routes/user.ts", import.meta.url)).text();
    expect(
      authSource.match(/releaseUnattemptedSmsVerifyClaim\(attemptClaim, error\)/g),
    ).toHaveLength(6);
    expect(
      userSource.match(/releaseUnattemptedSmsVerifyClaim\(attemptClaim, error\)/g),
    ).toHaveLength(1);
  });
});

/**
 * SMS pumping guard (ported from elizaOS/eliza 12e9bb4c657 + c8035651ab7):
 * the deployment-wide destination policy and hourly send ceiling run inside
 * PhoneAuth.sendOtp, before any provider call, on every send route.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { MockSmsInbox } from "@stwd/auth";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

process.env.NODE_ENV = "test";
process.env.SMS_PROVIDER = "mock";
process.env.WHATSAPP_OTP_ENABLED = "true";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgres://test:test@localhost:5432/test";
process.env.STEWARD_MASTER_PASSWORD = "sms-pumping-guard-master-password";
process.env.STEWARD_JWT_SECRET = "sms-pumping-guard-jwt-secret-with-enough-entropy";
process.env.STEWARD_AUDIT_HMAC_KEY = "sms-pumping-guard-audit-key-with-enough-entropy";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
delete process.env.STEWARD_SMS_ALLOWED_COUNTRY_CODES;
process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR = "3";

const { app } = await import("../app");
const { _setSmsSendBudgetCheckForTests, getPhoneAuth } = await import("../routes/auth");

const counters = new Map<string, number>();
const budgetCalls: Array<{ endpoint: string; windowMs: number; max: number }> = [];

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
  _setSmsSendBudgetCheckForTests(async (endpoint, windowMs, max) => {
    budgetCalls.push({ endpoint, windowMs, max });
    const next = (counters.get(endpoint) ?? 0) + 1;
    counters.set(endpoint, next);
    return { allowed: next <= max, retryAfterSecs: 42 };
  });
});

afterAll(async () => {
  _setSmsSendBudgetCheckForTests(undefined);
  delete process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR;
  await closeDb();
});

beforeEach(() => {
  counters.clear();
  budgetCalls.length = 0;
  MockSmsInbox.clear();
  delete process.env.STEWARD_SMS_ALLOWED_COUNTRY_CODES;
  process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR = "3";
});

function send(path: string, phone: string) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ phone }),
  });
}

describe("SMS pumping guard", () => {
  it("refuses a pumping destination on SMS and WhatsApp login without reaching the provider", async () => {
    for (const path of ["/auth/sms/send", "/auth/whatsapp/send"]) {
      for (const phone of ["+998995073528", "+18765550123"]) {
        const response = await send(path, phone);
        expect(response.status).toBe(400);
        expect(await response.json()).toMatchObject({
          ok: false,
          error: "SMS is not available for this phone number",
        });
        expect(MockSmsInbox.all(phone)).toHaveLength(0);
      }
    }
    // The destination check runs before the budget is charged.
    expect(budgetCalls).toHaveLength(0);
  });

  it("honors a configured allowlist", async () => {
    process.env.STEWARD_SMS_ALLOWED_COUNTRY_CODES = "1,44";
    const phone = "+447700900123";
    const response = await send("/auth/sms/send", phone);
    expect(response.status).toBe(200);
    expect(MockSmsInbox.all(phone)).toHaveLength(1);
  });

  it("caps deployment-wide sends per hour across rotating destinations", async () => {
    const sent: string[] = [];
    for (let i = 0; i < 3; i++) {
      const phone = `+1415555020${i}`;
      const response = await send("/auth/sms/send", phone);
      expect(response.status).toBe(200);
      sent.push(phone);
    }
    for (const phone of sent) expect(MockSmsInbox.all(phone)).toHaveLength(1);

    const fourth = "+14155550209";
    const refused = await send("/auth/sms/send", fourth);
    expect(refused.status).toBe(503);
    expect(refused.headers.get("Retry-After")).toBe("42");
    expect(await refused.json()).toMatchObject({
      ok: false,
      error: "SMS verification is temporarily unavailable",
    });
    expect(MockSmsInbox.all(fourth)).toHaveLength(0);
    expect(budgetCalls.every((call) => call.endpoint === "sms-send-global")).toBe(true);
    expect(budgetCalls.every((call) => call.windowMs === 3_600_000 && call.max === 3)).toBe(true);
  });

  it("covers non-route senders such as MFA challenges through PhoneAuth itself", async () => {
    const { SmsDestinationNotAllowedError } = await import("@stwd/auth");
    const phone = "+25765517171";
    await expect(getPhoneAuth().sendOtp(phone, "mfa:test", "sms")).rejects.toBeInstanceOf(
      SmsDestinationNotAllowedError,
    );
    expect(MockSmsInbox.all(phone)).toHaveLength(0);
  });

  it("a ceiling of 0 disables the budget without disabling the destination policy", async () => {
    process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR = "0";
    for (let i = 0; i < 5; i++) {
      expect((await send("/auth/sms/send", `+1415555030${i}`)).status).toBe(200);
    }
    expect(budgetCalls).toHaveLength(0);
    expect((await send("/auth/sms/send", "+998995073528")).status).toBe(400);
  });
});

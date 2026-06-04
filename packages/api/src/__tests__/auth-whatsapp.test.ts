import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

process.env.NODE_ENV = "test";
process.env.SMS_PROVIDER = "mock";
process.env.WHATSAPP_OTP_ENABLED = "true";
process.env.STEWARD_MASTER_PASSWORD = "whatsapp-auth-master-password";
process.env.STEWARD_JWT_SECRET = "whatsapp-auth-jwt-secret-with-enough-entropy";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgres://test:test@localhost:5432/test";

const { authRoutes, verifySessionToken } = await import("../routes/auth");

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  delete process.env.WHATSAPP_OTP_ENABLED;
  await closeDb();
});

beforeEach(() => {
  process.env.WHATSAPP_OTP_ENABLED = "true";
});

describe("WhatsApp OTP auth routes", () => {
  it("advertises WhatsApp only when enabled", async () => {
    let response = await authRoutes.request("/providers");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ whatsapp: true });

    process.env.WHATSAPP_OTP_ENABLED = "false";
    response = await authRoutes.request("/providers");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ whatsapp: false });
  });

  it("signs in with a WhatsApp OTP without accepting the code on the SMS route", async () => {
    const phone = "+14155559000";

    const sendRes = await authRoutes.request("/whatsapp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(sendRes.status).toBe(200);

    const inboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    expect(inboxRes.status).toBe(200);
    const inbox = (await inboxRes.json()) as { code: string };
    expect(inbox.code).toMatch(/^\d{6}$/);

    const smsVerifyRes = await authRoutes.request("/sms/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(smsVerifyRes.status).toBe(401);

    const verifyRes = await authRoutes.request("/whatsapp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(verifyRes.status).toBe(200);
    const body = (await verifyRes.json()) as {
      token: string;
      refreshToken: string;
      user: { id: string; walletAddress: string };
    };
    expect(body.refreshToken).toBeTruthy();
    expect(body.user.walletAddress).toMatch(/^phone:/);
    expect(await verifySessionToken(body.token)).toMatchObject({
      userId: body.user.id,
      authMethod: "whatsapp",
    });
  });

  it("does not let SMS verify failures lock out WhatsApp verification for the same phone", async () => {
    const phone = "+14155559002";

    for (let i = 0; i < 5; i++) {
      const failRes = await authRoutes.request("/sms/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ phone, code: "000000" }),
      });
      expect(failRes.status).toBe(401);
    }

    const sendRes = await authRoutes.request("/whatsapp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone }),
    });
    expect(sendRes.status).toBe(200);

    const inboxRes = await authRoutes.request(`/test/sms-inbox/${encodeURIComponent(phone)}`);
    expect(inboxRes.status).toBe(200);
    const inbox = (await inboxRes.json()) as { code: string };

    const verifyRes = await authRoutes.request("/whatsapp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone, code: inbox.code }),
    });
    expect(verifyRes.status).toBe(200);
  });

  it("rejects WhatsApp OTP routes when disabled", async () => {
    process.env.WHATSAPP_OTP_ENABLED = "false";

    const sendRes = await authRoutes.request("/whatsapp/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: "+14155559001" }),
    });
    expect(sendRes.status).toBe(503);

    const verifyRes = await authRoutes.request("/whatsapp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ phone: "+14155559001", code: "123456" }),
    });
    expect(verifyRes.status).toBe(503);
  });
});

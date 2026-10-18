/**
 * Phone login resolves SMS/WhatsApp linked accounts (ported from elizaOS/eliza
 * f3b2358e267, 18ba2c685b6, f03edd03e81). SMS and WhatsApp share one phone
 * subject; a linked number signs in to its linked account, never creates a
 * second account, and fails closed when its owners disagree.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { MockSmsInbox } from "@stwd/auth";
import { accounts, closeDb, getDb, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

process.env.NODE_ENV = "test";
process.env.SMS_PROVIDER = "mock";
process.env.WHATSAPP_OTP_ENABLED = "true";
process.env.STEWARD_PGLITE_MEMORY = "true";
process.env.DATABASE_URL = process.env.DATABASE_URL || "postgres://test:test@localhost:5432/test";
process.env.STEWARD_MASTER_PASSWORD = "linked-phone-login-master-password";
process.env.STEWARD_JWT_SECRET = "linked-phone-login-jwt-secret-with-enough-entropy";
process.env.STEWARD_AUDIT_HMAC_KEY = "linked-phone-login-audit-key-with-enough-entropy";
process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL = "true";
process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR = "0";

const { app } = await import("../app");
const { verifySessionToken } = await import("../routes/auth");

beforeAll(async () => {
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  delete process.env.STEWARD_SMS_SEND_GLOBAL_MAX_PER_HOUR;
  await closeDb();
});

beforeEach(() => {
  MockSmsInbox.clear();
});

function phoneSubject(phone: string): string {
  return `phone:${createHash("sha256").update(phone).digest("hex")}`;
}

function post(path: string, body: object) {
  return app.request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function verifyPhone(phone: string, channel: "sms" | "whatsapp" = "sms") {
  const sent = await post(`/auth/${channel}/send`, { phone });
  expect(sent.status).toBe(200);
  const code = MockSmsInbox.last(phone)?.code;
  expect(code).toMatch(/^\d{6}$/);
  return { response: await post(`/auth/${channel}/verify`, { phone, code }), code };
}

async function emailUser(email: string) {
  const [user] = await getDb().insert(users).values({ email, emailVerified: true }).returning();
  return user;
}

async function linkPhone(userId: string, phone: string, provider: "phone" | "whatsapp") {
  await getDb()
    .insert(accounts)
    .values({ userId, provider, providerAccountId: phoneSubject(phone) });
}

async function phoneAccountsFor(phone: string) {
  return getDb()
    .select()
    .from(users)
    .where(eq(users.walletAddress, phoneSubject(phone)));
}

describe("phone login with linked accounts", () => {
  it("a verified SMS-linked phone signs into its existing email account", async () => {
    const phone = "+14155550123";
    const owner = await emailUser("phone-owner@example.test");
    await linkPhone(owner.id, phone, "phone");

    const { response, code } = await verifyPhone(phone);
    expect(response.status).toBe(200);
    const body = (await response.json()) as { token: string; user: { id: string } };
    expect(body.user.id).toBe(owner.id);
    expect(await verifySessionToken(body.token)).toMatchObject({ userId: owner.id });
    expect(await phoneAccountsFor(phone)).toEqual([]);

    const replay = await post("/auth/sms/verify", { phone, code });
    expect(replay.status).toBe(401);
  });

  it("a WhatsApp-linked phone signs into its linked account through WhatsApp", async () => {
    const phone = "+14155550128";
    const owner = await emailUser("whatsapp-owner@example.test");
    await linkPhone(owner.id, phone, "whatsapp");

    const { response } = await verifyPhone(phone, "whatsapp");
    expect(response.status).toBe(200);
    expect(((await response.json()) as { user: { id: string } }).user.id).toBe(owner.id);
  });

  it("original phone accounts retain their identity", async () => {
    const phone = "+14155550124";
    const [owner] = await getDb()
      .insert(users)
      .values({ walletAddress: phoneSubject(phone), walletChain: "ethereum" })
      .returning();
    const { response } = await verifyPhone(phone);
    expect(response.status).toBe(200);
    expect(((await response.json()) as { user: { id: string } }).user.id).toBe(owner.id);
  });

  it("conflicting original and linked phone owners receive no session", async () => {
    const phone = "+14155550125";
    await getDb()
      .insert(users)
      .values({ walletAddress: phoneSubject(phone), walletChain: "ethereum" });
    const other = await emailUser("conflict@example.test");
    await linkPhone(other.id, phone, "phone");

    const { response } = await verifyPhone(phone);
    expect(response.status).toBe(409);
    const body = (await response.json()) as { token?: string; code?: string };
    expect(body.token).toBeUndefined();
    expect(body.code).toBe("PHONE_IDENTITY_CONFLICT");
  });

  it("a phone linked through SMS gets no second account from WhatsApp login", async () => {
    const phone = "+14155550126";
    const owner = await emailUser("sms-linked@example.test");
    await linkPhone(owner.id, phone, "phone");

    const whatsapp = await verifyPhone(phone, "whatsapp");
    expect(whatsapp.response.status).toBe(409);
    expect(((await whatsapp.response.json()) as { token?: string }).token).toBeUndefined();
    expect(await phoneAccountsFor(phone)).toEqual([]);

    const sms = await verifyPhone(phone);
    expect(sms.response.status).toBe(200);
    expect(((await sms.response.json()) as { user: { id: string } }).user.id).toBe(owner.id);
  });

  it("a phone linked to two users through SMS and WhatsApp signs in to neither", async () => {
    const phone = "+14155550127";
    const smsOwner = await emailUser("split-sms@example.test");
    const whatsappOwner = await emailUser("split-whatsapp@example.test");
    await linkPhone(smsOwner.id, phone, "phone");
    await linkPhone(whatsappOwner.id, phone, "whatsapp");

    for (const channel of ["sms", "whatsapp"] as const) {
      const { response } = await verifyPhone(phone, channel);
      expect(response.status).toBe(409);
      expect(((await response.json()) as { token?: string }).token).toBeUndefined();
    }
  });
});

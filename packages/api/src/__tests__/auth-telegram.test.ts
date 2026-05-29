import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { signTelegramLoginPayload } from "@stwd/auth";
import { accounts, closeDb, getDb, tenantConfigs, tenants, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const TENANT_ID = "telegram-auth-tenant";
const BOT_TOKEN = "123456:telegram-auth-test-token";

describe("Telegram auth", () => {
  let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
  let verifySessionToken: Awaited<typeof import("../routes/auth")>["verifySessionToken"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "telegram-auth-master-password";
    process.env.STEWARD_JWT_SECRET = "telegram-auth-jwt-secret-with-enough-entropy";
    process.env.TELEGRAM_BOT_TOKEN = BOT_TOKEN;

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Telegram Auth Tenant",
      apiKeyHash: "hash",
    });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        joinMode: "open",
        allowedOrigins: ["https://app.example.test"],
      });

    ({ authRoutes, verifySessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.TELEGRAM_BOT_TOKEN;
  });

  function signedPayload(overrides: Record<string, unknown> = {}) {
    const payload = {
      id: "424242",
      first_name: "Ada",
      last_name: "Lovelace",
      username: "ada",
      photo_url: "https://t.me/i/userpic/320/ada.jpg",
      auth_date: Math.floor(Date.now() / 1000),
      ...overrides,
    };
    return { ...payload, hash: signTelegramLoginPayload(payload, BOT_TOKEN) };
  }

  async function telegramChallenge(tenantId = TENANT_ID, origin = "https://app.example.test") {
    const response = await authRoutes.request("/telegram/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: origin },
      body: JSON.stringify({ tenantId }),
    });
    expect(response.status).toBe(200);
    return (await response.json()) as { challengeId: string };
  }

  it("verifies Telegram login payloads and reuses the linked account on re-login", async () => {
    const telegramPayload = signedPayload();
    const firstChallenge = await telegramChallenge();
    const first = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({
        ...telegramPayload,
        challengeId: firstChallenge.challengeId,
        tenantId: TENANT_ID,
      }),
    });
    expect(first.status).toBe(200);
    const firstBody = (await first.json()) as {
      token: string;
      refreshToken: string;
      user: { id: string; telegramId: string; telegramUsername: string };
    };
    expect(firstBody.refreshToken).toBeTruthy();
    expect(firstBody.user.telegramId).toBe("424242");
    expect(firstBody.user.telegramUsername).toBe("ada");
    expect(await verifySessionToken(firstBody.token)).toMatchObject({
      userId: firstBody.user.id,
      tenantId: TENANT_ID,
      authMethod: "telegram",
      telegramId: "424242",
    });

    const [account] = await getDb()
      .select()
      .from(accounts)
      .where(and(eq(accounts.provider, "telegram"), eq(accounts.providerAccountId, "424242")));
    expect(account?.userId).toBe(firstBody.user.id);

    const [membership] = await getDb()
      .select()
      .from(userTenants)
      .where(and(eq(userTenants.userId, firstBody.user.id), eq(userTenants.tenantId, TENANT_ID)));
    expect(membership?.tenantId).toBe(TENANT_ID);

    const replay = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({
        ...telegramPayload,
        challengeId: firstChallenge.challengeId,
        tenantId: TENANT_ID,
      }),
    });
    expect(replay.status).toBe(401);

    const secondChallenge = await telegramChallenge();
    const second = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({
        ...signedPayload({ first_name: "Ada2" }),
        challengeId: secondChallenge.challengeId,
        tenantId: TENANT_ID,
      }),
    });
    expect(second.status).toBe(200);
    const secondBody = (await second.json()) as { user: { id: string } };
    expect(secondBody.user.id).toBe(firstBody.user.id);
  });

  it("rejects tampered Telegram payloads before creating accounts", async () => {
    const before = await getDb().select().from(accounts);
    const tampered = signedPayload();
    const challenge = await telegramChallenge();
    const response = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({
        ...tampered,
        username: "mallory",
        challengeId: challenge.challengeId,
      }),
    });

    expect(response.status).toBe(401);
    const after = await getDb().select().from(accounts);
    expect(after).toHaveLength(before.length);
  });

  it("requires a tenant- and origin-bound server challenge before accepting Telegram payloads", async () => {
    const missingOriginChallenge = await authRoutes.request("/telegram/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tenantId: TENANT_ID }),
    });
    expect(missingOriginChallenge.status).toBe(400);
    expect(await missingOriginChallenge.text()).toContain("allowed Origin");

    const evilOriginChallenge = await authRoutes.request("/telegram/challenge", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example.test" },
      body: JSON.stringify({ tenantId: TENANT_ID }),
    });
    expect(evilOriginChallenge.status).toBe(400);
    expect(await evilOriginChallenge.text()).toContain("allowed Origin");

    const noChallenge = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({ ...signedPayload(), tenantId: TENANT_ID }),
    });
    expect(noChallenge.status).toBe(400);

    const wrongOriginChallenge = await telegramChallenge(TENANT_ID, "https://app.example.test");
    const wrongOrigin = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example.test" },
      body: JSON.stringify({
        ...signedPayload({ id: "424243", username: "grace" }),
        challengeId: wrongOriginChallenge.challengeId,
        tenantId: TENANT_ID,
      }),
    });
    expect(wrongOrigin.status).toBe(401);
    expect(await wrongOrigin.text()).toContain("origin");

    const wrongTenantChallenge = await telegramChallenge(TENANT_ID, "https://app.example.test");
    const wrongTenant = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://app.example.test" },
      body: JSON.stringify({
        ...signedPayload({ id: "424244", username: "katherine" }),
        challengeId: wrongTenantChallenge.challengeId,
        tenantId: "other-tenant",
      }),
    });
    expect(wrongTenant.status).toBe(401);
    expect(await wrongTenant.text()).toContain("tenant");
  });

  it("rejects split body and header tenants before verifying Telegram login", async () => {
    const challenge = await telegramChallenge(TENANT_ID, "https://app.example.test");
    const response = await authRoutes.request("/telegram/verify", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://app.example.test",
        "X-Steward-Tenant": "other-tenant",
      },
      body: JSON.stringify({
        ...signedPayload({ id: "424245", username: "hypatia" }),
        challengeId: challenge.challengeId,
        tenantId: TENANT_ID,
      }),
    });
    expect(response.status).toBe(400);
    expect(await response.text()).toContain("tenantId and X-Steward-Tenant must match");
  });
});

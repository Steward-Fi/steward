import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenants, userPushSubscriptions, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const USER_ADDRESS = "0x0000000000000000000000000000000000000001";

describe("user push subscriptions", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let userId = "";
  let personalTenantId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-push-subscriptions-master-password";
    process.env.STEWARD_JWT_SECRET = "user-push-subscriptions-jwt-secret";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const [userRow] = await getDb()
      .insert(users)
      .values({ email: "push@example.test", emailVerified: true })
      .returning({ id: users.id });
    userId = userRow.id;
    personalTenantId = `personal-${userId}`;

    await getDb()
      .insert(tenants)
      .values({
        id: personalTenantId,
        name: "Push Personal",
        apiKeyHash: `${personalTenantId}-hash`,
      });
    await getDb().insert(tenants).values({
      id: "push-tenant",
      name: "Push Tenant",
      apiKeyHash: "push-tenant-hash",
    });
    await getDb()
      .insert(userTenants)
      .values([
        { userId, tenantId: personalTenantId, role: "owner" },
        { userId, tenantId: "push-tenant", role: "member" },
      ]);

    ({ createSessionToken } = await import("../routes/auth"));
    ({ userRoutes } = await import("../routes/user"));
  }, 30_000);

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
  }, 30_000);

  async function personalToken(): Promise<string> {
    return createSessionToken(USER_ADDRESS, personalTenantId, {
      userId,
      tenantId: personalTenantId,
    });
  }

  it("registers, lists, refreshes, and revokes push subscriptions", async () => {
    const token = await personalToken();
    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    const createResponse = await userRoutes.request("/me/push-subscriptions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        provider: "expo",
        token: "ExpoPushToken[abc123abc123abc123]",
        platform: "ios",
        tenantId: "push-tenant",
        deviceId: "device-1",
        metadata: { appVersion: "1.0.0" },
      }),
    });
    const createBody = (await createResponse.json()) as {
      ok: boolean;
      data: { subscription: { id: string; provider: string; token: string; deviceId: string } };
    };
    expect(createResponse.status).toBe(200);
    expect(createBody.data.subscription).toMatchObject({
      provider: "expo",
      token: "ExpoPushToken[abc123abc123abc123]",
      deviceId: "device-1",
    });

    const refreshResponse = await userRoutes.request("/me/push-subscriptions", {
      method: "POST",
      headers,
      body: JSON.stringify({
        provider: "expo",
        token: "ExpoPushToken[abc123abc123abc123]",
        platform: "ios",
        tenantId: "push-tenant",
        deviceId: "device-2",
      }),
    });
    expect(refreshResponse.status).toBe(200);
    const rowsAfterRefresh = await getDb()
      .select()
      .from(userPushSubscriptions)
      .where(eq(userPushSubscriptions.userId, userId));
    expect(rowsAfterRefresh).toHaveLength(1);
    expect(rowsAfterRefresh[0].deviceId).toBe("device-2");

    const listResponse = await userRoutes.request("/me/push-subscriptions", { headers });
    const listBody = (await listResponse.json()) as {
      ok: boolean;
      data: { subscriptions: Array<{ id: string; status: string }> };
    };
    expect(listBody.data.subscriptions).toHaveLength(1);
    expect(listBody.data.subscriptions[0].status).toBe("active");

    const revokeResponse = await userRoutes.request(
      `/me/push-subscriptions/${createBody.data.subscription.id}`,
      { method: "DELETE", headers },
    );
    expect(revokeResponse.status).toBe(200);

    const listAfterRevoke = await userRoutes.request("/me/push-subscriptions", { headers });
    const listAfterRevokeBody = (await listAfterRevoke.json()) as {
      data: { subscriptions: unknown[] };
    };
    expect(listAfterRevokeBody.data.subscriptions).toEqual([]);
  });

  it("rejects invalid push provider and token combinations", async () => {
    const token = await personalToken();
    const response = await userRoutes.request("/me/push-subscriptions", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ provider: "apns", token: "ExpoPushToken[abc123abc123abc123]" }),
    });
    const body = (await response.json()) as { ok: boolean; error: string };
    expect(response.status).toBe(400);
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Invalid push token");
  });
});

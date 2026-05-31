import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";

import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ADDRESS = "0x0000000000000000000000000000000000000042";

describe("user wallet creation webhooks", () => {
  let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
  let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];
  let userId = "";
  let personalTenantId = "";
  let userAgentId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-wallet-created-webhook-master-password";
    process.env.STEWARD_JWT_SECRET = "user-wallet-created-webhook-jwt-secret-with-enough-entropy";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    const [userRow] = await getDb()
      .insert(users)
      .values({ email: "wallet-created@example.test", emailVerified: true })
      .returning({ id: users.id });
    userId = userRow.id;
    personalTenantId = `personal-${userId}`;
    userAgentId = `user-wallet-${userId}`;

    // verifySessionToken requires a userTenants row matching the token tenantId.
    await getDb()
      .insert(tenants)
      .values({
        id: personalTenantId,
        name: "Wallet Created Personal",
        apiKeyHash: `${personalTenantId}-hash`,
      })
      .onConflictDoNothing();
    await getDb().insert(userTenants).values({ userId, tenantId: personalTenantId, role: "owner" });

    ({ createSessionToken } = await import("../routes/auth"));
    ({ userRoutes } = await import("../routes/user"));
  });

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
  });

  it("dispatches user.wallet_created only for first successful wallet provisioning", async () => {
    const token = await createSessionToken(USER_ADDRESS, personalTenantId, {
      userId,
      tenantId: personalTenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });

    const created = await userRoutes.request("/me/wallet", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const createdBody = (await created.json()) as {
      ok: boolean;
      data: { agentId: string; walletAddress: string };
    };

    expect(created.status).toBe(201);
    expect(createdBody.ok).toBe(true);
    expect(createdBody.data.agentId).toBe(userAgentId);

    const [personalTenant] = await getDb()
      .select({ id: tenants.id })
      .from(tenants)
      .where(eq(tenants.id, personalTenantId));
    expect(personalTenant?.id).toBe(personalTenantId);

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      personalTenantId,
      userAgentId,
      "user.wallet_created",
      {
        userId,
        walletId: userAgentId,
        walletAddress: createdBody.data.walletAddress,
        walletAddresses: expect.objectContaining({ evm: createdBody.data.walletAddress }),
      },
    );

    dispatchWebhookMock.mockClear();
    const existing = await userRoutes.request("/me/wallet", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const existingBody = (await existing.json()) as {
      ok: boolean;
      data: { agentId: string; walletAddress: string };
    };

    expect(existing.status).toBe(201);
    expect(existingBody.ok).toBe(true);
    expect(existingBody.data).toEqual(createdBody.data);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });
});

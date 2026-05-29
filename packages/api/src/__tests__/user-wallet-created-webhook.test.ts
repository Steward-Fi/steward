import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";

import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ADDRESS = "0x0000000000000000000000000000000000000042";
const PERSONAL_TENANT_ID = `personal-${USER_ADDRESS}`;
const USER_AGENT_ID = `user-wallet-${USER_ADDRESS}`;

describe("user wallet creation webhooks", () => {
  let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
  let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-wallet-created-webhook-master-password";
    process.env.STEWARD_JWT_SECRET = "user-wallet-created-webhook-jwt-secret-with-enough-entropy";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

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
    const token = await createSessionToken(USER_ADDRESS, "tenant");

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
    expect(createdBody.data.agentId).toBe(USER_AGENT_ID);

    const [personalTenant] = await getDb()
      .select({ id: tenants.id })
      .from(tenants)
      .where(eq(tenants.id, PERSONAL_TENANT_ID));
    expect(personalTenant?.id).toBe(PERSONAL_TENANT_ID);

    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      PERSONAL_TENANT_ID,
      USER_AGENT_ID,
      "user.wallet_created",
      {
        userId: USER_ADDRESS,
        walletId: USER_AGENT_ID,
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

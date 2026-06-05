import { afterAll, beforeAll, describe, expect, it, mock } from "bun:test";
import {
  agents,
  closeDb,
  getDb,
  tenantAppClients,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const APP_TENANT_ID = "embedded-wallet-create-on-login-app";
const OFF_TENANT_ID = "embedded-wallet-create-on-login-off";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

describe("user embedded wallet create-on-login config", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "embedded-wallet-create-on-login-master-password";
    process.env.STEWARD_JWT_SECRET = "embedded-wallet-create-on-login-jwt-secret-32chars";
    process.env.STEWARD_AUDIT_HMAC_KEY = "embedded-wallet-create-on-login-audit-hmac-key-32chars";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values([
        { id: APP_TENANT_ID, name: "Create On Login App", apiKeyHash: "hash-create" },
        { id: OFF_TENANT_ID, name: "Create On Login Off", apiKeyHash: "hash-off" },
      ]);
    await getDb()
      .insert(tenantConfigs)
      .values([
        {
          tenantId: APP_TENANT_ID,
          featureFlags: { embeddedWallets: { createOnLogin: "users-without-wallets" } },
        },
        {
          tenantId: OFF_TENANT_ID,
          featureFlags: { embeddedWallets: { createOnLogin: "off" } },
        },
      ]);
    await getDb()
      .insert(tenantAppClients)
      .values([
        {
          id: "web-default",
          tenantId: APP_TENANT_ID,
          name: "Web Default",
          environment: "production",
          enabled: true,
          isDefault: true,
        },
        {
          id: "web-off",
          tenantId: APP_TENANT_ID,
          name: "Web Off",
          environment: "production",
          enabled: true,
          embeddedWallets: { createOnLogin: "off" },
        },
        {
          id: "web-all",
          tenantId: OFF_TENANT_ID,
          name: "Web All",
          environment: "production",
          enabled: true,
          isDefault: true,
          embeddedWallets: { createOnLogin: "all-users" },
        },
      ]);

    ({ userRoutes } = await import("../routes/user"));
    ({ createSessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  async function seedUser(email: string, appTenantId: string) {
    const [user] = await getDb()
      .insert(users)
      .values({ email, emailVerified: true, walletAddress: null })
      .returning({ id: users.id });
    const personalTenantId = `personal-${user.id}`;
    await getDb()
      .insert(tenants)
      .values({ id: personalTenantId, name: email, apiKeyHash: `hash-${user.id}` });
    await getDb()
      .insert(userTenants)
      .values([
        { userId: user.id, tenantId: personalTenantId, role: "owner" },
        { userId: user.id, tenantId: appTenantId, role: "member" },
      ]);
    const token = await createSessionToken(
      "0x0000000000000000000000000000000000000000",
      personalTenantId,
      {
        userId: user.id,
        tenantId: personalTenantId,
      },
    );
    return { userId: user.id, token };
  }

  it("provisions an embedded wallet during the authenticated user bootstrap when tenant config opts in", async () => {
    const { userId, token } = await seedUser("create-on-login@example.test", APP_TENANT_ID);

    const response = await userRoutes.request(`/me?tenantId=${APP_TENANT_ID}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        wallet: { agentId: string; address: string } | null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { tenantId: string; createOnLogin: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.data.embeddedWalletConfig).toEqual({
      tenantId: APP_TENANT_ID,
      createOnLogin: "users-without-wallets",
    });
    expect(body.data.walletAutoCreated).toBe(true);
    expect(body.data.wallet?.agentId).toBe(`user-wallet-${userId}`);
    expect(body.data.wallet?.address).toMatch(/^0x[0-9a-fA-F]{40}$/);

    const [walletAgent] = await getDb()
      .select({ id: agents.id, tenantId: agents.tenantId, walletAddress: agents.walletAddress })
      .from(agents)
      .where(
        and(eq(agents.id, `user-wallet-${userId}`), eq(agents.tenantId, `personal-${userId}`)),
      );
    expect(walletAgent?.walletAddress).toBe(body.data.wallet?.address);
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
  });

  it("does not provision when createOnLogin is off and does not recreate an existing wallet", async () => {
    const offUser = await seedUser("create-on-login-off@example.test", OFF_TENANT_ID);
    const offResponse = await userRoutes.request(`/me?tenantId=${OFF_TENANT_ID}`, {
      headers: { Authorization: `Bearer ${offUser.token}` },
    });
    const offBody = (await offResponse.json()) as {
      data: {
        wallet: null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { createOnLogin: string };
      };
    };

    expect(offResponse.status).toBe(200);
    expect(offBody.data.embeddedWalletConfig.createOnLogin).toBe("off");
    expect(offBody.data.wallet).toBeNull();
    expect(offBody.data.walletAutoCreated).toBe(false);

    const existingUser = await seedUser("create-on-login-existing@example.test", APP_TENANT_ID);
    const first = await userRoutes.request(`/me?tenantId=${APP_TENANT_ID}`, {
      headers: { Authorization: `Bearer ${existingUser.token}` },
    });
    expect(
      ((await first.json()) as { data: { walletAutoCreated: boolean } }).data.walletAutoCreated,
    ).toBe(true);
    dispatchWebhookMock.mockClear();

    const second = await userRoutes.request(`/me?tenantId=${APP_TENANT_ID}`, {
      headers: { Authorization: `Bearer ${existingUser.token}` },
    });
    const secondBody = (await second.json()) as {
      data: { wallet: { agentId: string } | null; walletAutoCreated: boolean };
    };

    expect(second.status).toBe(200);
    expect(secondBody.data.wallet?.agentId).toBe(`user-wallet-${existingUser.userId}`);
    expect(secondBody.data.walletAutoCreated).toBe(false);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("falls back to tenant createOnLogin when the app client has no embedded wallet override", async () => {
    const { userId, token } = await seedUser(
      "create-on-login-client-fallback@example.test",
      APP_TENANT_ID,
    );
    dispatchWebhookMock.mockClear();

    const response = await userRoutes.request(
      `/me?tenantId=${APP_TENANT_ID}&client_id=web-default`,
      {
        headers: { Authorization: `Bearer ${token}` },
      },
    );
    const body = (await response.json()) as {
      data: {
        wallet: { agentId: string } | null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { tenantId: string; clientId?: string; createOnLogin: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.embeddedWalletConfig).toEqual({
      tenantId: APP_TENANT_ID,
      clientId: "web-default",
      createOnLogin: "users-without-wallets",
    });
    expect(body.data.wallet?.agentId).toBe(`user-wallet-${userId}`);
    expect(body.data.walletAutoCreated).toBe(true);
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
  });

  it("lets an app client override tenant createOnLogin to off", async () => {
    const { userId, token } = await seedUser(
      "create-on-login-client-off@example.test",
      APP_TENANT_ID,
    );
    dispatchWebhookMock.mockClear();

    const response = await userRoutes.request(`/me?tenantId=${APP_TENANT_ID}&clientId=web-off`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await response.json()) as {
      data: {
        wallet: { agentId: string } | null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { tenantId: string; clientId?: string; createOnLogin: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.embeddedWalletConfig).toEqual({
      tenantId: APP_TENANT_ID,
      clientId: "web-off",
      createOnLogin: "off",
    });
    expect(body.data.wallet).toBeNull();
    expect(body.data.walletAutoCreated).toBe(false);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const [walletAgent] = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(
        and(eq(agents.id, `user-wallet-${userId}`), eq(agents.tenantId, `personal-${userId}`)),
      );
    expect(walletAgent).toBeUndefined();
  });

  it("lets an app client override tenant createOnLogin to all-users via X-Steward-App-Id", async () => {
    const { userId, token } = await seedUser(
      "create-on-login-client-all@example.test",
      OFF_TENANT_ID,
    );
    dispatchWebhookMock.mockClear();

    const response = await userRoutes.request(`/me?tenantId=${OFF_TENANT_ID}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Steward-App-Id": `${OFF_TENANT_ID}/web-all`,
      },
    });
    const body = (await response.json()) as {
      data: {
        wallet: { agentId: string } | null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { tenantId: string; clientId?: string; createOnLogin: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.embeddedWalletConfig).toEqual({
      tenantId: OFF_TENANT_ID,
      clientId: "web-all",
      createOnLogin: "all-users",
    });
    expect(body.data.wallet?.agentId).toBe(`user-wallet-${userId}`);
    expect(body.data.walletAutoCreated).toBe(true);
    expect(dispatchWebhookMock).toHaveBeenCalledTimes(1);
  });

  it("ignores another tenant's createOnLogin flag when the user is not a member", async () => {
    const { userId, token } = await seedUser(
      "create-on-login-nonmember@example.test",
      OFF_TENANT_ID,
    );
    dispatchWebhookMock.mockClear();

    const response = await userRoutes.request(`/me?tenantId=${APP_TENANT_ID}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await response.json()) as {
      data: {
        wallet: { agentId: string } | null;
        walletAutoCreated: boolean;
        embeddedWalletConfig: { tenantId: string; createOnLogin: string };
      };
    };

    expect(response.status).toBe(200);
    expect(body.data.embeddedWalletConfig).toEqual({
      tenantId: APP_TENANT_ID,
      createOnLogin: "off",
    });
    expect(body.data.wallet).toBeNull();
    expect(body.data.walletAutoCreated).toBe(false);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const [walletAgent] = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(
        and(eq(agents.id, `user-wallet-${userId}`), eq(agents.tenantId, `personal-${userId}`)),
      );
    expect(walletAgent).toBeUndefined();
  });
});

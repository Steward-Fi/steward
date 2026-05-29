import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";

setDefaultTimeout(30000);

import { closeDb, getDb, tenantConfigs, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const PLATFORM_KEY = "user-lifecycle-webhooks-platform-key";
const TENANT_ID = "user-lifecycle-webhooks-tenant";

describe("user lifecycle webhook dispatch", () => {
  let authRoutes: Awaited<typeof import("../routes/auth")>["authRoutes"];
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-lifecycle-webhooks-master-password";
    process.env.STEWARD_JWT_SECRET = "user-lifecycle-webhooks-jwt-secret-with-enough-entropy";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: ["platform:*"],
    });
    process.env.STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "User Lifecycle Webhooks Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });

    ({ authRoutes } = await import("../routes/auth"));
    ({ platformRoutes } = await import("../routes/platform"));
  });

  beforeEach(() => {
    dispatchWebhookMock.mockClear();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
    delete process.env.STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION;
  });

  function platformHeaders() {
    return {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
    };
  }

  it("dispatches user.created only after platform user provisioning succeeds", async () => {
    const invalid = await platformRoutes.request("/users", {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ email: "not-an-email" }),
    });
    expect(invalid.status).toBe(400);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const email = "lifecycle-created@example.test";
    const created = await platformRoutes.request("/users", {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ email, emailVerified: true }),
    });
    expect(created.status).toBe(201);
    const body = (await created.json()) as { data: { userId: string; isNew: boolean } };
    expect(body.data.isNew).toBe(true);
    expect(dispatchWebhookMock).toHaveBeenCalledWith("platform", body.data.userId, "user.created", {
      userId: body.data.userId,
      source: "platform.provision",
      hasEmail: true,
    });

    dispatchWebhookMock.mockClear();
    const duplicate = await platformRoutes.request("/users", {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ email }),
    });
    expect(duplicate.status).toBe(200);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("dispatches metadata and linked-account events only after platform mutations succeed", async () => {
    const [sourceUser] = await getDb()
      .insert(users)
      .values({
        email: "lifecycle-source@example.test",
        emailVerified: true,
      })
      .returning({ id: users.id });
    const [targetUser] = await getDb()
      .insert(users)
      .values({
        email: "lifecycle-target@example.test",
        emailVerified: true,
      })
      .returning({ id: users.id });

    const badMetadata = await platformRoutes.request(`/users/${sourceUser.id}/metadata`, {
      method: "PATCH",
      headers: platformHeaders(),
      body: JSON.stringify({ customMetadata: "invalid" }),
    });
    expect(badMetadata.status).toBe(400);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const metadata = await platformRoutes.request(`/users/${sourceUser.id}/metadata`, {
      method: "PATCH",
      headers: platformHeaders(),
      body: JSON.stringify({ customMetadata: { tier: "gold" } }),
    });
    expect(metadata.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      "platform",
      sourceUser.id,
      "user.updated_account",
      {
        userId: sourceUser.id,
        scope: "global",
        field: "customMetadata",
      },
    );

    dispatchWebhookMock.mockClear();
    const link = await platformRoutes.request(`/users/${sourceUser.id}/accounts`, {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ provider: "google", providerAccountId: "lifecycle-google" }),
    });
    expect(link.status).toBe(201);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      "platform",
      sourceUser.id,
      "user.linked_account",
      {
        userId: sourceUser.id,
        provider: "google",
      },
    );

    dispatchWebhookMock.mockClear();
    const transfer = await platformRoutes.request(
      `/users/${sourceUser.id}/accounts/google/lifecycle-google/transfer`,
      {
        method: "POST",
        headers: platformHeaders(),
        body: JSON.stringify({ toUserId: targetUser.id }),
      },
    );
    expect(transfer.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      "platform",
      sourceUser.id,
      "user.transferred_account",
      {
        fromUserId: sourceUser.id,
        toUserId: targetUser.id,
        provider: "google",
        forced: false,
      },
    );

    dispatchWebhookMock.mockClear();
    const unlink = await platformRoutes.request(
      `/users/${targetUser.id}/accounts/google/lifecycle-google`,
      {
        method: "DELETE",
        headers: platformHeaders(),
      },
    );
    expect(unlink.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      "platform",
      targetUser.id,
      "user.unlinked_account",
      {
        userId: targetUser.id,
        provider: "google",
        forced: false,
      },
    );

    dispatchWebhookMock.mockClear();
    const missingUnlink = await platformRoutes.request(
      `/users/${targetUser.id}/accounts/google/lifecycle-google`,
      {
        method: "DELETE",
        headers: platformHeaders(),
      },
    );
    expect(missingUnlink.status).toBe(404);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });

  it("dispatches tenant user lifecycle events for tenant-scoped provisioning and metadata", async () => {
    const memberEmail = "lifecycle-member@example.test";
    const member = await platformRoutes.request(`/tenants/${TENANT_ID}/members`, {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ email: memberEmail }),
    });
    expect(member.status).toBe(201);
    const memberBody = (await member.json()) as { data: { userId: string } };
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      memberBody.data.userId,
      "user.created",
      {
        userId: memberBody.data.userId,
        source: "platform.tenant_member",
        hasEmail: true,
      },
    );

    dispatchWebhookMock.mockClear();
    const badTenantMetadata = await platformRoutes.request(
      `/tenants/${TENANT_ID}/users/${memberBody.data.userId}/metadata`,
      {
        method: "PATCH",
        headers: platformHeaders(),
        body: JSON.stringify({ tenantCustomMetadata: "invalid" }),
      },
    );
    expect(badTenantMetadata.status).toBe(400);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const tenantMetadata = await platformRoutes.request(
      `/tenants/${TENANT_ID}/users/${memberBody.data.userId}/metadata`,
      {
        method: "PATCH",
        headers: platformHeaders(),
        body: JSON.stringify({ tenantCustomMetadata: { externalId: "crm-123" } }),
      },
    );
    expect(tenantMetadata.status).toBe(200);
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      memberBody.data.userId,
      "user.updated_account",
      {
        userId: memberBody.data.userId,
        scope: "tenant",
        field: "tenantCustomMetadata",
      },
    );
  });

  it("dispatches user.created and user.authenticated for successful test-account login only", async () => {
    const testAccount = {
      enabled: true,
      email: "lifecycle-test-account@steward.test",
      phone: "+15555550123",
      otp: "123456",
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId: TENANT_ID, testAccount })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { testAccount },
      });

    const rejected = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: testAccount.email,
        otp: "000000",
      }),
    });
    expect(rejected.status).toBe(401);
    expect(dispatchWebhookMock).not.toHaveBeenCalled();

    const accepted = await authRoutes.request("/test/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenantId: TENANT_ID,
        email: testAccount.email,
        otp: testAccount.otp,
      }),
    });
    expect(accepted.status).toBe(200);
    const acceptedBody = (await accepted.json()) as { user: { id: string } };
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      acceptedBody.user.id,
      "user.created",
      {
        userId: acceptedBody.user.id,
        source: "auth.email",
        hasEmail: true,
      },
    );
    expect(dispatchWebhookMock).toHaveBeenCalledWith(
      TENANT_ID,
      acceptedBody.user.id,
      "user.authenticated",
      {
        userId: acceptedBody.user.id,
        authMethod: "email",
      },
    );
  });
});

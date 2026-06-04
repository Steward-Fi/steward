import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { hashSha256Hex } from "@stwd/auth";
import { accounts, closeDb, getDb, refreshTokens, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const PLATFORM_KEY = "platform-identity-graph-key";
const TENANT_ID = "platform-identity-graph-tenant";
const OTHER_TENANT_ID = "platform-identity-graph-other";

describe("platform global identity graph routes", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];
  let userId = "";
  let otherUserId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "platform-identity-graph-master-password";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: [
        "platform:read",
        "platform:write",
        "platform:user:read",
        "platform:user:write",
        "platform:user-lifecycle:write",
        "platform:user:delete",
        "platform:tenant-user:read",
        "platform:tenant-user:write",
        "platform:identity-migration",
        "platform:identity-migration:force",
      ],
    });
    process.env.STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Identity Graph Tenant", apiKeyHash: "hash" },
        { id: OTHER_TENANT_ID, name: "Identity Graph Other", apiKeyHash: "hash-other" },
      ]);
    const [user] = await getDb()
      .insert(users)
      .values({
        email: "identity-graph@example.test",
        emailVerified: true,
        name: "Identity Graph User",
        walletAddress: "0x1111111111111111111111111111111111111111",
        customMetadata: { source: "seed" },
      })
      .returning({ id: users.id });
    const [otherUser] = await getDb()
      .insert(users)
      .values({ email: null, emailVerified: false, name: "Account Only User" })
      .returning({ id: users.id });
    userId = user.id;
    otherUserId = otherUser.id;
    await getDb()
      .insert(userTenants)
      .values([
        { userId, tenantId: TENANT_ID, role: "member" },
        { userId, tenantId: OTHER_TENANT_ID, role: "member" },
      ]);
    await getDb().insert(accounts).values({
      userId,
      provider: "google",
      providerAccountId: "google-identity-graph",
    });

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
    delete process.env.STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION;
  });

  function headers() {
    return {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
    };
  }

  it("gets a global user identity with tenant ids and linked accounts", async () => {
    const response = await platformRoutes.request(`/users/${userId}`, { headers: headers() });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        userId: string;
        email: string;
        customMetadata: Record<string, unknown>;
        tenantIds: string[];
        linkedAccounts: Array<{ provider: string; providerAccountId: string }>;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.userId).toBe(userId);
    expect(body.data.tenantIds.sort()).toEqual([OTHER_TENANT_ID, TENANT_ID].sort());
    expect(body.data.customMetadata).toEqual({ source: "seed" });
    expect(body.data.linkedAccounts).toEqual([
      expect.objectContaining({
        provider: "google",
        providerAccountId: "google-identity-graph",
      }),
    ]);
  });

  it("updates global custom metadata without touching tenant metadata", async () => {
    await getDb()
      .update(userTenants)
      .set({ customMetadata: { tenantOnly: true } })
      .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, TENANT_ID)));

    const response = await platformRoutes.request(`/users/${userId}/metadata`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ customMetadata: { plan: "enterprise", seats: 12 } }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: { userId: string; customMetadata: Record<string, unknown> };
    };
    expect(body.ok).toBe(true);
    expect(body.data.userId).toBe(userId);
    expect(body.data.customMetadata).toEqual({ plan: "enterprise", seats: 12 });

    const [tenantLink] = await getDb()
      .select({ customMetadata: userTenants.customMetadata })
      .from(userTenants)
      .where(and(eq(userTenants.userId, userId), eq(userTenants.tenantId, TENANT_ID)));
    expect(tenantLink?.customMetadata).toEqual({ tenantOnly: true });

    const invalid = await platformRoutes.request(`/users/${userId}/metadata`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ customMetadata: "not-object" }),
    });
    expect(invalid.status).toBe(400);

    const oversized = await platformRoutes.request(`/users/${userId}/metadata`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ customMetadata: { blob: "x".repeat(17_000) } }),
    });
    expect(oversized.status).toBe(400);
    const oversizedBody = (await oversized.json()) as { error: string };
    expect(oversizedBody.error).toContain("customMetadata");
  });

  it("rejects oversized metadata during user provisioning and tenant metadata updates", async () => {
    const create = await platformRoutes.request("/users", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        email: "oversized-metadata@example.test",
        customMetadata: { blob: "x".repeat(17_000) },
      }),
    });
    expect(create.status).toBe(400);

    const tenantUpdate = await platformRoutes.request(
      `/tenants/${TENANT_ID}/users/${userId}/metadata`,
      {
        method: "PATCH",
        headers: headers(),
        body: JSON.stringify({ tenantCustomMetadata: { blob: "x".repeat(17_000) } }),
      },
    );
    expect(tenantUpdate.status).toBe(400);
    const tenantBody = (await tenantUpdate.json()) as { error: string };
    expect(tenantBody.error).toContain("tenantCustomMetadata");
  });

  it("looks up users by provider account and respects tenant filters", async () => {
    const found = await platformRoutes.request(
      "/users/lookup?provider=google&providerAccountId=google-identity-graph",
      { headers: headers() },
    );
    expect(found.status).toBe(200);
    const foundBody = (await found.json()) as { data: { user: { userId: string } | null } };
    expect(foundBody.data.user?.userId).toBe(userId);

    const filteredOut = await platformRoutes.request(
      "/users/lookup?provider=google&providerAccountId=google-identity-graph&tenantId=missing-tenant",
      { headers: headers() },
    );
    expect(filteredOut.status).toBe(200);
    const filteredOutBody = (await filteredOut.json()) as { data: { user: null } };
    expect(filteredOutBody.data.user).toBeNull();
  });

  it("looks up users by phone, smart wallet id, and custom auth id aliases", async () => {
    const phone = "+14155550101";
    const [aliasUser] = await getDb()
      .insert(users)
      .values({
        email: "alias-lookup@example.test",
        walletAddress: `phone:${hashSha256Hex(phone)}`,
        stewardWalletId: "smart-wallet-alias-1",
      })
      .returning({ id: users.id });
    await getDb().insert(userTenants).values({
      userId: aliasUser.id,
      tenantId: TENANT_ID,
      role: "member",
    });
    await getDb().insert(accounts).values({
      userId: aliasUser.id,
      provider: "custom",
      providerAccountId: "custom-auth-alias-1",
    });

    const byPhone = await platformRoutes.request(
      `/users/lookup?phone=${encodeURIComponent(phone)}`,
      { headers: headers() },
    );
    expect(byPhone.status).toBe(200);
    const phoneBody = (await byPhone.json()) as { data: { user: { userId: string } | null } };
    expect(phoneBody.data.user?.userId).toBe(aliasUser.id);

    const bySmartWallet = await platformRoutes.request(
      "/users/lookup?smartWalletId=smart-wallet-alias-1",
      { headers: headers() },
    );
    expect(bySmartWallet.status).toBe(200);
    const smartWalletBody = (await bySmartWallet.json()) as {
      data: { user: { userId: string } | null };
    };
    expect(smartWalletBody.data.user?.userId).toBe(aliasUser.id);

    const byCustomAuth = await platformRoutes.request(
      "/users/lookup?customAuthId=custom-auth-alias-1",
      { headers: headers() },
    );
    expect(byCustomAuth.status).toBe(200);
    const customAuthBody = (await byCustomAuth.json()) as {
      data: { user: { userId: string } | null };
    };
    expect(customAuthBody.data.user?.userId).toBe(aliasUser.id);
  });

  it("links, rejects duplicate ownership, and unlinks global accounts", async () => {
    const link = await platformRoutes.request(`/users/${userId}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ provider: "github", providerAccountId: "github-identity-graph" }),
    });
    expect(link.status).toBe(201);
    const linkBody = (await link.json()) as { data: { isNew: boolean } };
    expect(linkBody.data.isNew).toBe(true);

    const duplicate = await platformRoutes.request(`/users/${otherUserId}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ provider: "github", providerAccountId: "github-identity-graph" }),
    });
    expect(duplicate.status).toBe(409);

    const unlink = await platformRoutes.request(
      `/users/${userId}/accounts/github/github-identity-graph`,
      { method: "DELETE", headers: headers() },
    );
    expect(unlink.status).toBe(200);
    const remaining = await getDb()
      .select()
      .from(accounts)
      .where(
        and(
          eq(accounts.provider, "github"),
          eq(accounts.providerAccountId, "github-identity-graph"),
        ),
      );
    expect(remaining).toHaveLength(0);
  });

  it("refuses to unlink the last login method without force", async () => {
    await getDb().insert(accounts).values({
      userId: otherUserId,
      provider: "oidc",
      providerAccountId: "only-login-method",
    });

    const response = await platformRoutes.request(
      `/users/${otherUserId}/accounts/oidc/only-login-method`,
      { method: "DELETE", headers: headers() },
    );

    expect(response.status).toBe(409);
  });

  it("transfers linked accounts between users and invalidates both refresh token sets", async () => {
    const [sourceUser] = await getDb()
      .insert(users)
      .values({ email: "transfer-source@example.test", emailVerified: true })
      .returning({ id: users.id });
    const [targetUser] = await getDb()
      .insert(users)
      .values({ email: "transfer-target@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(accounts).values({
      userId: sourceUser.id,
      provider: "spotify",
      providerAccountId: "spotify-transfer",
    });
    await getDb()
      .insert(refreshTokens)
      .values([
        {
          id: "transfer-source-refresh-token",
          userId: sourceUser.id,
          tenantId: TENANT_ID,
          tokenHash: "transfer-source-refresh-hash",
          expiresAt: new Date(Date.now() + 60_000),
        },
        {
          id: "transfer-target-refresh-token",
          userId: targetUser.id,
          tenantId: TENANT_ID,
          tokenHash: "transfer-target-refresh-hash",
          expiresAt: new Date(Date.now() + 60_000),
        },
      ]);

    const response = await platformRoutes.request(
      `/users/${sourceUser.id}/accounts/spotify/spotify-transfer/transfer`,
      {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ toUserId: targetUser.id }),
      },
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: { fromUserId: string; toUserId: string; provider: string };
    };
    expect(body.data).toMatchObject({
      fromUserId: sourceUser.id,
      toUserId: targetUser.id,
      provider: "spotify",
    });
    const [transferred] = await getDb()
      .select({ userId: accounts.userId })
      .from(accounts)
      .where(
        and(eq(accounts.provider, "spotify"), eq(accounts.providerAccountId, "spotify-transfer")),
      );
    expect(transferred?.userId).toBe(targetUser.id);
    const remainingRefresh = await getDb()
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tenantId, TENANT_ID));
    expect(
      remainingRefresh.some((row) => row.userId === sourceUser.id || row.userId === targetUser.id),
    ).toBe(false);
  });

  it("refuses to transfer the source user's last login method without force", async () => {
    const [sourceUser] = await getDb()
      .insert(users)
      .values({ email: null, emailVerified: false })
      .returning({ id: users.id });
    const [targetUser] = await getDb()
      .insert(users)
      .values({ email: "last-login-target@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(accounts).values({
      userId: sourceUser.id,
      provider: "telegram",
      providerAccountId: "only-transfer-login",
    });

    const response = await platformRoutes.request(
      `/users/${sourceUser.id}/accounts/telegram/only-transfer-login/transfer`,
      {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ toUserId: targetUser.id }),
      },
    );

    expect(response.status).toBe(409);
  });

  it("deactivates users, clears refresh tokens, and blocks identity reads as inactive", async () => {
    await getDb()
      .insert(refreshTokens)
      .values({
        id: "deactivate-refresh-token",
        userId,
        tenantId: TENANT_ID,
        tokenHash: "deactivate-refresh-hash",
        expiresAt: new Date(Date.now() + 60_000),
      });

    const response = await platformRoutes.request(`/users/${userId}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: true }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: { userId: string; deactivatedAt: string | null };
    };
    expect(body.data.userId).toBe(userId);
    expect(typeof body.data.deactivatedAt).toBe("string");

    const [stored] = await getDb()
      .select({ deactivatedAt: users.deactivatedAt })
      .from(users)
      .where(eq(users.id, userId));
    expect(stored?.deactivatedAt).toBeInstanceOf(Date);
    const remainingRefresh = await getDb()
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, userId));
    expect(remainingRefresh).toHaveLength(0);

    const reactivate = await platformRoutes.request(`/users/${userId}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: false }),
    });
    expect(reactivate.status).toBe(200);
    const reactivateBody = (await reactivate.json()) as { data: { deactivatedAt: string | null } };
    expect(reactivateBody.data.deactivatedAt).toBeNull();
  });

  it("hard-deletes users and cascades linked identity rows", async () => {
    const [deleteUser] = await getDb()
      .insert(users)
      .values({ email: "delete-me@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(userTenants).values({
      userId: deleteUser.id,
      tenantId: TENANT_ID,
      role: "member",
    });
    await getDb().insert(accounts).values({
      userId: deleteUser.id,
      provider: "github",
      providerAccountId: "delete-me-github",
    });
    await getDb()
      .insert(refreshTokens)
      .values({
        id: "delete-refresh-token",
        userId: deleteUser.id,
        tenantId: TENANT_ID,
        tokenHash: "delete-refresh-hash",
        expiresAt: new Date(Date.now() + 60_000),
      });

    const response = await platformRoutes.request(`/users/${deleteUser.id}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { userId: string; deleted: boolean } };
    expect(body.data).toEqual({ userId: deleteUser.id, deleted: true });

    const deletedUsers = await getDb().select().from(users).where(eq(users.id, deleteUser.id));
    expect(deletedUsers).toHaveLength(0);
    const deletedAccounts = await getDb()
      .select()
      .from(accounts)
      .where(eq(accounts.providerAccountId, "delete-me-github"));
    expect(deletedAccounts).toHaveLength(0);
    const deletedRefresh = await getDb()
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, deleteUser.id));
    expect(deletedRefresh).toHaveLength(0);
  });
});

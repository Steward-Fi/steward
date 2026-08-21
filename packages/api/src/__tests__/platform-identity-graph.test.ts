import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";

import { hashSha256Hex, revocationStore } from "@stwd/auth";
import {
  accounts,
  agents,
  auditEvents,
  closeDb,
  getDb,
  refreshTokens,
  retainedUserProviderEvidence,
  sponsoredGasEvents,
  tenantConfigs,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq, sql } from "drizzle-orm";

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
        "platform:tenant:delete",
        "platform:tenant-member:write",
        "platform:tenant-user:read",
        "platform:tenant-user:write",
        "platform:gas-spend:read",
        "platform:identity-migration",
        "platform:identity-migration:force",
      ],
    });
    process.env.STEWARD_ALLOW_PLATFORM_IDENTITY_MIGRATION = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "platform-identity-graph-audit-hmac-key-with-enough-entropy";

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
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  function headers() {
    return {
      "Content-Type": "application/json",
      "X-Steward-Platform-Key": PLATFORM_KEY,
    };
  }

  async function assertMalformedPersonalTenantRejected(extraRole: "member" | "owner") {
    const [owner, extraUser] = await getDb()
      .insert(users)
      .values([
        {
          email: `personal-${extraRole}-owner@example.test`,
          emailVerified: true,
        },
        {
          email: `personal-${extraRole}-extra@example.test`,
          emailVerified: true,
        },
      ])
      .returning({ id: users.id });
    const tenantId = `personal-${owner.id}`;
    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: `Malformed personal ${extraRole}`,
        apiKeyHash: `malformed-personal-${extraRole}-hash`,
      });
    // Reproduce a row shape that could predate 0114. New writes are covered by
    // a separate invariant test and cannot create this state.
    await getDb().execute(
      sql.raw("ALTER TABLE user_tenants DISABLE TRIGGER user_tenants_personal_authority_guard"),
    );
    try {
      await getDb()
        .insert(userTenants)
        .values([
          { userId: owner.id, tenantId, role: "owner" },
          { userId: extraUser.id, tenantId, role: extraRole },
        ]);
    } finally {
      await getDb().execute(
        sql.raw("ALTER TABLE user_tenants ENABLE TRIGGER user_tenants_personal_authority_guard"),
      );
    }
    await getDb()
      .insert(refreshTokens)
      .values({
        id: `malformed-personal-${extraRole}-refresh`,
        userId: owner.id,
        tenantId,
        tokenHash: `malformed-personal-${extraRole}-refresh-hash`,
        expiresAt: new Date(Date.now() + 60_000),
      });
    const revokedBefore = await revocationStore.getUserRevokedBefore(owner.id);

    const deactivate = await platformRoutes.request(`/users/${owner.id}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: true }),
    });
    expect(deactivate.status).toBe(409);
    expect(((await deactivate.json()) as { error: string }).error).toBe(
      "Personal tenant membership invariant violated",
    );

    const removeTenant = await platformRoutes.request(`/tenants/${tenantId}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(removeTenant.status).toBe(409);
    expect(((await removeTenant.json()) as { error: string }).error).toBe(
      "Personal tenant membership invariant violated",
    );

    const [storedOwner] = await getDb()
      .select({ deactivatedAt: users.deactivatedAt })
      .from(users)
      .where(eq(users.id, owner.id));
    expect(storedOwner?.deactivatedAt).toBeNull();
    expect(await revocationStore.getUserRevokedBefore(owner.id)).toBe(revokedBefore);
    expect(await getDb().select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(1);
    expect(
      await getDb().select().from(userTenants).where(eq(userTenants.tenantId, tenantId)),
    ).toHaveLength(2);
    expect(
      await getDb().select().from(refreshTokens).where(eq(refreshTokens.userId, owner.id)),
    ).toHaveLength(1);
  }

  async function createLifecycleFaultUser(label: string) {
    const [user] = await getDb()
      .insert(users)
      .values({ email: `${label}@example.test`, emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(userTenants).values({
      userId: user.id,
      tenantId: TENANT_ID,
      role: "member",
    });
    await getDb()
      .insert(refreshTokens)
      .values({
        id: `${label}-refresh-token`,
        userId: user.id,
        tenantId: TENANT_ID,
        tokenHash: `${label}-refresh-hash`,
        expiresAt: new Date(Date.now() + 60_000),
      });
    return user.id;
  }

  async function lifecycleDatabaseState(faultUserId: string) {
    const [user] = await getDb()
      .select({ deactivatedAt: users.deactivatedAt })
      .from(users)
      .where(eq(users.id, faultUserId));
    const tokens = await getDb()
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.userId, faultUserId));
    const audits = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(eq(auditEvents.resourceId, faultUserId))
      .orderBy(asc(auditEvents.seq));
    return { audits: audits.map((row) => row.action), tokens, user };
  }

  async function deactivateUser(faultUserId: string) {
    return platformRoutes.request(`/users/${faultUserId}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: true }),
    });
  }

  async function installOneShotCompletionAuditFailure(name: string, deferred: boolean) {
    await getDb().execute(sql.raw(`CREATE SEQUENCE ${name}_seq`));
    await getDb().execute(
      sql.raw(`
      CREATE FUNCTION ${name}_fn() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF NEW.action = 'user.deactivate' AND nextval('${name}_seq') = 1 THEN
          RAISE EXCEPTION '${name}';
        END IF;
        RETURN NEW;
      END
      $$
    `),
    );
    await getDb().execute(
      sql.raw(
        deferred
          ? `CREATE CONSTRAINT TRIGGER ${name}_trigger AFTER INSERT ON audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ${name}_fn()`
          : `CREATE TRIGGER ${name}_trigger AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION ${name}_fn()`,
      ),
    );
  }

  async function removeCompletionAuditFailure(name: string) {
    await getDb().execute(sql.raw(`DROP TRIGGER IF EXISTS ${name}_trigger ON audit_events`));
    await getDb().execute(sql.raw(`DROP FUNCTION IF EXISTS ${name}_fn()`));
    await getDb().execute(sql.raw(`DROP SEQUENCE IF EXISTS ${name}_seq`));
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

  it("assigns wallet external ids at user creation and resolves them by lookup aliases", async () => {
    const create = await platformRoutes.request("/users", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        email: "wallet-external-create@example.test",
        tenantId: TENANT_ID,
        walletExternalId: "wallet-ext-create-1",
      }),
    });

    expect(create.status).toBe(201);
    const createBody = (await create.json()) as {
      data: { userId: string; isNew: boolean; tenantId: string; walletExternalId: string };
    };
    expect(createBody.data.isNew).toBe(true);
    expect(createBody.data.tenantId).toBe(TENANT_ID);
    expect(createBody.data.walletExternalId).toBe("wallet-ext-create-1");

    const byQuery = await platformRoutes.request(
      "/users/lookup?tenantId=platform-identity-graph-tenant&walletExternalId=wallet-ext-create-1",
      { headers: headers() },
    );
    expect(byQuery.status).toBe(200);
    const queryBody = (await byQuery.json()) as {
      data: {
        user: {
          userId: string;
          tenantIds: string[];
          linkedAccounts: Array<{ provider: string }>;
          walletExternalIds: Array<{ tenantId: string; externalId: string }>;
        } | null;
      };
    };
    expect(queryBody.data.user?.userId).toBe(createBody.data.userId);
    expect(queryBody.data.user?.tenantIds).toEqual([TENANT_ID]);
    expect(queryBody.data.user?.linkedAccounts).toEqual([]);
    expect(queryBody.data.user?.walletExternalIds).toEqual([
      { tenantId: TENANT_ID, externalId: "wallet-ext-create-1" },
    ]);

    const byAlias = await platformRoutes.request("/users/wallet/external-id", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ tenantId: TENANT_ID, externalId: "wallet-ext-create-1" }),
    });
    expect(byAlias.status).toBe(200);
    const aliasBody = (await byAlias.json()) as {
      data: { user: { userId: string } | null };
    };
    expect(aliasBody.data.user?.userId).toBe(createBody.data.userId);

    const list = await platformRoutes.request(
      `/tenants/${TENANT_ID}/users?walletExternalId=wallet-ext-create-1`,
      { headers: headers() },
    );
    expect(list.status).toBe(200);
    const listBody = (await list.json()) as { data: { users: Array<{ userId: string }> } };
    expect(listBody.data.users.map((row) => row.userId)).toEqual([createBody.data.userId]);
  });

  it("connects or creates users by wallet external id idempotently", async () => {
    const create = await platformRoutes.request("/users/wallet/external-id/connect-or-create", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        tenantId: OTHER_TENANT_ID,
        walletExternalId: "wallet-ext-connect-1",
        name: "External Wallet User",
      }),
    });

    expect(create.status).toBe(201);
    const createBody = (await create.json()) as {
      data: {
        userId: string;
        isNew: boolean;
        createdExternalId: boolean;
        user: { walletExternalIds: Array<{ tenantId: string; externalId: string }> };
      };
    };
    expect(createBody.data.isNew).toBe(true);
    expect(createBody.data.createdExternalId).toBe(true);
    expect(createBody.data.user.walletExternalIds).toEqual([
      { tenantId: OTHER_TENANT_ID, externalId: "wallet-ext-connect-1" },
    ]);

    const again = await platformRoutes.request("/users/wallet/external-id/connect-or-create", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        tenantId: OTHER_TENANT_ID,
        walletExternalId: "wallet-ext-connect-1",
      }),
    });
    expect(again.status).toBe(200);
    const againBody = (await again.json()) as {
      data: { userId: string; isNew: boolean; createdExternalId: boolean };
    };
    expect(againBody.data).toMatchObject({
      userId: createBody.data.userId,
      isNew: false,
      createdExternalId: false,
    });
  });

  it("enforces wallet external id tenant uniqueness and immutability", async () => {
    await getDb().insert(userTenants).values({
      userId: otherUserId,
      tenantId: TENANT_ID,
      role: "member",
    });

    const link = await platformRoutes.request(`/users/${userId}/wallet/external-id`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ tenantId: TENANT_ID, walletExternalId: "wallet-ext-immutable-1" }),
    });
    expect(link.status).toBe(201);

    const idempotent = await platformRoutes.request(`/users/${userId}/wallet/external-id`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ tenantId: TENANT_ID, walletExternalId: "wallet-ext-immutable-1" }),
    });
    expect(idempotent.status).toBe(200);

    const mutate = await platformRoutes.request(`/users/${userId}/wallet/external-id`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ tenantId: TENANT_ID, walletExternalId: "wallet-ext-immutable-2" }),
    });
    expect(mutate.status).toBe(409);

    const collision = await platformRoutes.request(`/users/${otherUserId}/wallet/external-id`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({ tenantId: TENANT_ID, walletExternalId: "wallet-ext-immutable-1" }),
    });
    expect(collision.status).toBe(409);
  });

  it("does not leave tenant membership behind when wallet external id assignment fails", async () => {
    await getDb()
      .insert(accounts)
      .values({
        userId,
        provider: "wallet_external_id",
        providerAccountId: `${TENANT_ID}:wallet-ext-membership-collision`,
      });
    const [victim] = await getDb()
      .insert(users)
      .values({ email: "wallet-external-rollback@example.test", emailVerified: true })
      .returning({ id: users.id });

    const createCollision = await platformRoutes.request("/users", {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        email: "wallet-external-rollback@example.test",
        tenantId: TENANT_ID,
        walletExternalId: "wallet-ext-membership-collision",
      }),
    });
    expect(createCollision.status).toBe(409);

    const leakedMembership = await getDb()
      .select({ id: userTenants.id })
      .from(userTenants)
      .where(and(eq(userTenants.userId, victim.id), eq(userTenants.tenantId, TENANT_ID)));
    expect(leakedMembership).toHaveLength(0);

    await getDb()
      .insert(accounts)
      .values({
        userId: victim.id,
        provider: "wallet_external_id",
        providerAccountId: `${TENANT_ID}:wallet-ext-victim-existing`,
      });
    const immutableCollision = await platformRoutes.request(
      "/users/wallet/external-id/connect-or-create",
      {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({
          email: "wallet-external-rollback@example.test",
          tenantId: TENANT_ID,
          walletExternalId: "wallet-ext-victim-new",
        }),
      },
    );
    expect(immutableCollision.status).toBe(409);

    const leakedImmutableMembership = await getDb()
      .select({ id: userTenants.id })
      .from(userTenants)
      .where(and(eq(userTenants.userId, victim.id), eq(userTenants.tenantId, TENANT_ID)));
    expect(leakedImmutableMembership).toHaveLength(0);
  });

  it("filters platform gas spend history by wallet external ids", async () => {
    const walletA = "gas-spend-wallet-a";
    const walletB = "gas-spend-wallet-b";
    await getDb()
      .insert(agents)
      .values([
        {
          id: walletA,
          tenantId: TENANT_ID,
          name: "Gas Spend Wallet A",
          walletAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          platformId: "external-gas-wallet-a",
        },
        {
          id: walletB,
          tenantId: TENANT_ID,
          name: "Gas Spend Wallet B",
          walletAddress: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          platformId: "external-gas-wallet-b",
        },
      ]);
    await getDb()
      .insert(sponsoredGasEvents)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: walletA,
          provider: "mock",
          mode: "erc4337",
          status: "settled",
          reservedUsd: "1.25",
          actualUsd: "1.00",
        },
        {
          tenantId: TENANT_ID,
          agentId: walletB,
          provider: "mock",
          mode: "erc4337",
          status: "settled",
          reservedUsd: "2.25",
          actualUsd: "2.00",
        },
      ]);

    const response = await platformRoutes.request(
      `/apps/gas_spend?tenant_id=${TENANT_ID}&wallet_external_ids=external-gas-wallet-a`,
      { headers: headers() },
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        count: number;
        actualUsd: string;
        entries: Array<{ agentId: string }>;
      };
    };
    expect(body.data.count).toBe(1);
    expect(body.data.actualUsd).toBe("1.000000");
    expect(body.data.entries.map((entry) => entry.agentId)).toEqual([walletA]);

    const missing = await platformRoutes.request(
      `/apps/gas_spend?tenant_id=${TENANT_ID}&wallet_external_ids=missing-external-wallet`,
      { headers: headers() },
    );
    expect(missing.status).toBe(404);

    await getDb().insert(agents).values({
      id: "gas-spend-wallet-duplicate",
      tenantId: TENANT_ID,
      name: "Gas Spend Wallet Duplicate",
      walletAddress: "0xcccccccccccccccccccccccccccccccccccccccc",
      platformId: "external-gas-wallet-a",
    });
    const ambiguous = await platformRoutes.request(
      `/apps/gas_spend?tenant_id=${TENANT_ID}&wallet_external_ids=external-gas-wallet-a`,
      { headers: headers() },
    );
    expect(ambiguous.status).toBe(409);
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

  it("enforces tenant one-wallet policy for platform wallet links", async () => {
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { wallet: { restrictToOneThirdPartyWallet: true } },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: { wallet: { restrictToOneThirdPartyWallet: true } } },
      });

    const firstWallet = await platformRoutes.request(`/users/${userId}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        provider: "wallet:ethereum",
        providerAccountId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        tenantId: TENANT_ID,
      }),
    });
    expect(firstWallet.status).toBe(201);

    const secondWallet = await platformRoutes.request(`/users/${userId}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        provider: "wallet:solana",
        providerAccountId: "So11111111111111111111111111111111111111112",
        tenantId: TENANT_ID,
      }),
    });
    expect(secondWallet.status).toBe(409);
    expect(((await secondWallet.json()) as { error: string }).error).toContain(
      "already has a linked wallet",
    );
  });

  it("enforces one-wallet policy from user memberships when platform link omits tenantId", async () => {
    const [policyUser] = await getDb()
      .insert(users)
      .values({ email: "wallet-policy-membership@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb()
      .insert(userTenants)
      .values({ userId: policyUser.id, tenantId: TENANT_ID, role: "member" });
    await getDb()
      .insert(tenantConfigs)
      .values({
        tenantId: TENANT_ID,
        authAbuseConfig: { wallet: { restrictToOneThirdPartyWallet: true } },
      })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { authAbuseConfig: { wallet: { restrictToOneThirdPartyWallet: true } } },
      });

    const firstWallet = await platformRoutes.request(`/users/${policyUser.id}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        provider: "wallet:ethereum",
        providerAccountId: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      }),
    });
    expect(firstWallet.status).toBe(201);

    const secondWallet = await platformRoutes.request(`/users/${policyUser.id}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        provider: "wallet:solana",
        providerAccountId: "So22222222222222222222222222222222222222222",
      }),
    });
    expect(secondWallet.status).toBe(409);
    expect(((await secondWallet.json()) as { error: string }).error).toContain(
      "already has a linked wallet",
    );
  });

  it("rejects platform wallet links scoped to a tenant the user is not a member of", async () => {
    const [nonMember] = await getDb()
      .insert(users)
      .values({ email: "wallet-policy-nonmember@example.test", emailVerified: true })
      .returning({ id: users.id });

    const response = await platformRoutes.request(`/users/${nonMember.id}/accounts`, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify({
        provider: "wallet:ethereum",
        providerAccountId: "0xcccccccccccccccccccccccccccccccccccccccc",
        tenantId: TENANT_ID,
      }),
    });

    expect(response.status).toBe(403);
    expect(((await response.json()) as { error: string }).error).toContain(
      "not a member of tenant",
    );
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

  it("rolls back authorization and mutation when the mounted revoker fails, then retries", async () => {
    const faultUserId = await createLifecycleFaultUser("platform-revoker-fault");
    const originalRevoke = revocationStore.revokeUserTokens.bind(revocationStore);
    let attempts = 0;
    revocationStore.revokeUserTokens = async (id, issuedBefore, expiresAt) => {
      attempts += 1;
      if (attempts === 1) throw new Error("simulated platform revoker failure");
      return originalRevoke(id, issuedBefore, expiresAt);
    };

    try {
      const failed = await deactivateUser(faultUserId);
      expect(failed.status).toBe(500);
      expect(await lifecycleDatabaseState(faultUserId)).toEqual({
        audits: [],
        tokens: [{ id: "platform-revoker-fault-refresh-token" }],
        user: { deactivatedAt: null },
      });
      expect(await revocationStore.getUserRevokedBefore(faultUserId)).toBeNull();

      const retried = await deactivateUser(faultUserId);
      expect(retried.status).toBe(200);
      expect(await lifecycleDatabaseState(faultUserId)).toEqual({
        audits: ["user.deactivate.authorized", "user.deactivate"],
        tokens: [],
        user: { deactivatedAt: expect.any(Date) },
      });
      expect(await revocationStore.getUserRevokedBefore(faultUserId)).not.toBeNull();
    } finally {
      revocationStore.revokeUserTokens = originalRevoke;
    }
  });

  for (const fault of [
    { deferred: false, label: "completion audit", name: "platform_completion_audit_fault" },
    { deferred: true, label: "commit", name: "platform_commit_fault" },
  ]) {
    it(`rolls back database state on ${fault.label} failure, preserves safe revocation, and retries`, async () => {
      const faultUserId = await createLifecycleFaultUser(fault.name);
      await installOneShotCompletionAuditFailure(fault.name, fault.deferred);
      try {
        const failed = await deactivateUser(faultUserId);
        expect(failed.status).toBe(500);
        expect(await lifecycleDatabaseState(faultUserId)).toEqual({
          audits: [],
          tokens: [{ id: `${fault.name}-refresh-token` }],
          user: { deactivatedAt: null },
        });
        const firstCutoff = await revocationStore.getUserRevokedBefore(faultUserId);
        expect(firstCutoff).not.toBeNull();

        const retried = await deactivateUser(faultUserId);
        expect(retried.status).toBe(200);
        expect(await lifecycleDatabaseState(faultUserId)).toEqual({
          audits: ["user.deactivate.authorized", "user.deactivate"],
          tokens: [],
          user: { deactivatedAt: expect.any(Date) },
        });
        const retryCutoff = await revocationStore.getUserRevokedBefore(faultUserId);
        expect(retryCutoff).not.toBeNull();
        expect(retryCutoff as number).toBeGreaterThanOrEqual(firstCutoff as number);
      } finally {
        await removeCompletionAuditFailure(fault.name);
      }
    });
  }

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

  it("keeps a committed deletion successful when token-cache refresh fails", async () => {
    const [deleteUser] = await getDb()
      .insert(users)
      .values({ email: "delete-revocation-retry@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(accounts).values({
      userId: deleteUser.id,
      provider: "github",
      providerAccountId: "delete-revocation-retry-github",
    });

    const revoke = spyOn(revocationStore, "revokeUserTokens").mockRejectedValueOnce(
      new Error("redis provider unavailable"),
    );
    try {
      const response = await platformRoutes.request(`/users/${deleteUser.id}`, {
        method: "DELETE",
        headers: headers(),
      });
      expect(response.status).toBe(200);
      expect(await getDb().select().from(users).where(eq(users.id, deleteUser.id))).toHaveLength(0);
      expect(
        await getDb()
          .select()
          .from(retainedUserProviderEvidence)
          .where(eq(retainedUserProviderEvidence.deletedUserId, deleteUser.id)),
      ).toHaveLength(1);
    } finally {
      revoke.mockRestore();
    }
  });

  it("keeps committed deactivation successful when token-cache refresh fails", async () => {
    const [target] = await getDb()
      .insert(users)
      .values({ email: "deactivate-revocation-retry@example.test", emailVerified: true })
      .returning({ id: users.id });
    const revoke = spyOn(revocationStore, "revokeUserTokens").mockRejectedValueOnce(
      new Error("redis provider unavailable"),
    );
    try {
      const first = await platformRoutes.request(`/users/${target.id}/deactivate`, {
        method: "PATCH",
        headers: headers(),
        body: JSON.stringify({ deactivated: true }),
      });
      expect(first.status).toBe(200);
      const [stored] = await getDb()
        .select({ deactivatedAt: users.deactivatedAt })
        .from(users)
        .where(eq(users.id, target.id));
      expect(stored?.deactivatedAt).toBeInstanceOf(Date);
      const completed = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(eq(auditEvents.resourceId, target.id), eq(auditEvents.action, "user.deactivate")),
        );
      expect(completed).toHaveLength(1);

      expect(revoke).toHaveBeenCalledTimes(1);
    } finally {
      revoke.mockRestore();
    }
  });

  it("keeps committed reactivation successful behind the durable token line", async () => {
    const [target] = await getDb()
      .insert(users)
      .values({
        email: "reactivate-revocation-retry@example.test",
        emailVerified: true,
        deactivatedAt: new Date(),
      })
      .returning({ id: users.id });
    const revoke = spyOn(revocationStore, "revokeUserTokens").mockRejectedValueOnce(
      new Error("redis provider unavailable"),
    );
    try {
      const first = await platformRoutes.request(`/users/${target.id}/deactivate`, {
        method: "PATCH",
        headers: headers(),
        body: JSON.stringify({ deactivated: false }),
      });
      expect(first.status).toBe(200);
      const [stored] = await getDb()
        .select({
          deactivatedAt: users.deactivatedAt,
          tokensRevokedBefore: users.tokensRevokedBefore,
        })
        .from(users)
        .where(eq(users.id, target.id));
      expect(stored?.deactivatedAt).toBeNull();
      expect(stored?.tokensRevokedBefore).toBeGreaterThan(-1);
      const completed = await getDb()
        .select({ action: auditEvents.action })
        .from(auditEvents)
        .where(
          and(eq(auditEvents.resourceId, target.id), eq(auditEvents.action, "user.reactivate")),
        );
      expect(completed).toHaveLength(1);

      expect(revoke).toHaveBeenCalledTimes(1);
    } finally {
      revoke.mockRestore();
    }
  });

  it("deactivates a personal owner and deletes the tenant before its identity", async () => {
    const [personalUser] = await getDb()
      .insert(users)
      .values({ email: "delete-personal-owner@example.test", emailVerified: true })
      .returning({ id: users.id });
    const personalTenantId = `personal-${personalUser.id}`;
    await getDb().insert(tenants).values({
      id: personalTenantId,
      name: "Personal deletion owner",
      apiKeyHash: "personal-delete-owner-hash",
    });
    await getDb().insert(userTenants).values({
      userId: personalUser.id,
      tenantId: personalTenantId,
      role: "owner",
    });
    await getDb().insert(accounts).values({
      userId: personalUser.id,
      provider: "google",
      providerAccountId: "google-personal-delete-owner",
    });

    const immutableMembershipRequests = [
      platformRoutes.request(`/tenants/${personalTenantId}/members`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ email: "personal-extra-member@example.test", role: "member" }),
      }),
      platformRoutes.request(`/tenants/${personalTenantId}/members/${personalUser.id}`, {
        method: "PATCH",
        headers: headers(),
        body: JSON.stringify({ role: "member" }),
      }),
      platformRoutes.request(`/tenants/${personalTenantId}/members/${personalUser.id}`, {
        method: "DELETE",
        headers: headers(),
      }),
      platformRoutes.request(`/tenants/${personalTenantId}/invitations`, {
        method: "POST",
        headers: headers(),
        body: JSON.stringify({ email: "personal-invite@example.test" }),
      }),
      platformRoutes.request(`/tenants/${personalTenantId}/invitations/${crypto.randomUUID()}`, {
        method: "DELETE",
        headers: headers(),
      }),
    ];
    for (const response of await Promise.all(immutableMembershipRequests)) {
      expect(response.status).toBe(409);
      expect(((await response.json()) as { error: string }).error).toBe(
        "Personal tenant membership is immutable",
      );
    }
    expect(
      await getDb().select().from(userTenants).where(eq(userTenants.tenantId, personalTenantId)),
    ).toHaveLength(1);
    expect(
      await getDb()
        .select()
        .from(users)
        .where(eq(users.email, "personal-extra-member@example.test")),
    ).toHaveLength(0);

    const deactivate = await platformRoutes.request(`/users/${personalUser.id}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: true }),
    });
    expect(deactivate.status).toBe(200);
    const [deactivated] = await getDb()
      .select({ deactivatedAt: users.deactivatedAt })
      .from(users)
      .where(eq(users.id, personalUser.id));
    expect(deactivated?.deactivatedAt).toBeInstanceOf(Date);

    const prematureRemove = await platformRoutes.request(`/users/${personalUser.id}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(prematureRemove.status).toBe(409);

    const removeTenant = await platformRoutes.request(`/tenants/${personalTenantId}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(removeTenant.status).toBe(200);

    const remove = await platformRoutes.request(`/users/${personalUser.id}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(remove.status).toBe(200);
    expect(await getDb().select().from(users).where(eq(users.id, personalUser.id))).toHaveLength(0);
    expect(
      await getDb()
        .select()
        .from(accounts)
        .where(eq(accounts.providerAccountId, "google-personal-delete-owner")),
    ).toHaveLength(0);
    expect(
      await getDb()
        .select({
          deletedUserId: retainedUserProviderEvidence.deletedUserId,
          provider: retainedUserProviderEvidence.provider,
          providerAccountId: retainedUserProviderEvidence.providerAccountId,
        })
        .from(retainedUserProviderEvidence)
        .where(eq(retainedUserProviderEvidence.deletedUserId, personalUser.id)),
    ).toEqual([
      {
        deletedUserId: personalUser.id,
        provider: "google",
        providerAccountId: "google-personal-delete-owner",
      },
    ]);
    expect(
      await getDb().select().from(tenants).where(eq(tenants.id, personalTenantId)),
    ).toHaveLength(0);
  });

  it("rejects a personal tenant with an extra member before lifecycle mutation", async () => {
    await assertMalformedPersonalTenantRejected("member");
  });

  it("rejects a personal tenant with an extra owner before lifecycle mutation", async () => {
    await assertMalformedPersonalTenantRejected("owner");
  });

  it("still refuses lifecycle removal for a sole owner of a shared tenant", async () => {
    const sharedTenantId = "platform-identity-delete-shared";
    const [sharedOwner] = await getDb()
      .insert(users)
      .values({ email: "delete-shared-owner@example.test", emailVerified: true })
      .returning({ id: users.id });
    await getDb().insert(tenants).values({
      id: sharedTenantId,
      name: "Shared deletion control",
      apiKeyHash: "shared-delete-control-hash",
    });
    await getDb().insert(userTenants).values({
      userId: sharedOwner.id,
      tenantId: sharedTenantId,
      role: "owner",
    });

    const deactivate = await platformRoutes.request(`/users/${sharedOwner.id}/deactivate`, {
      method: "PATCH",
      headers: headers(),
      body: JSON.stringify({ deactivated: true }),
    });
    expect(deactivate.status).toBe(409);

    const remove = await platformRoutes.request(`/users/${sharedOwner.id}`, {
      method: "DELETE",
      headers: headers(),
    });
    expect(remove.status).toBe(409);
    expect(await getDb().select().from(users).where(eq(users.id, sharedOwner.id))).toHaveLength(1);
    expect(await getDb().select().from(tenants).where(eq(tenants.id, sharedTenantId))).toHaveLength(
      1,
    );
  });
});

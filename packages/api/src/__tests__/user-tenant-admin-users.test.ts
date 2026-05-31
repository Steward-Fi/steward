import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const TENANT_ID = "user-tenant-admin-users";
const OTHER_TENANT_ID = "user-tenant-admin-users-other";
const OWNER_PERSONAL_TENANT_ID = "personal-user-tenant-admin-owner";

describe("user tenant-admin user directory routes", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let verifySessionToken: typeof import("../routes/auth").verifySessionToken;
  let ownerId = "";
  let memberId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-tenant-admin-users-master-password";
    process.env.STEWARD_JWT_SECRET = "user-tenant-admin-users-jwt-secret";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values({
        id: OWNER_PERSONAL_TENANT_ID,
        name: "Owner Personal Tenant",
        apiKeyHash: `${OWNER_PERSONAL_TENANT_ID}-hash`,
      });
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "User Tenant Admin Users",
        apiKeyHash: `${TENANT_ID}-hash`,
      });
    await getDb()
      .insert(tenants)
      .values({
        id: OTHER_TENANT_ID,
        name: "Other User Tenant Admin Users",
        apiKeyHash: `${OTHER_TENANT_ID}-hash`,
      });
    const [owner] = await getDb()
      .insert(users)
      .values({ email: "owner@example.test", emailVerified: true, name: "Owner" })
      .returning({ id: users.id });
    const [member] = await getDb()
      .insert(users)
      .values({ email: "member@example.test", emailVerified: true, name: "Member" })
      .returning({ id: users.id });
    ownerId = owner.id;
    memberId = member.id;
    await getDb()
      .insert(tenants)
      .values({
        id: `personal-${ownerId}`,
        name: "Owner Dynamic Personal Tenant",
        apiKeyHash: `personal-${ownerId}-hash`,
      })
      .onConflictDoNothing();
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ownerId, tenantId: `personal-${ownerId}`, role: "owner" },
        { userId: ownerId, tenantId: OWNER_PERSONAL_TENANT_ID, role: "owner" },
        { userId: ownerId, tenantId: TENANT_ID, role: "owner" },
        { userId: ownerId, tenantId: OTHER_TENANT_ID, role: "owner" },
        {
          userId: memberId,
          tenantId: TENANT_ID,
          role: "member",
          customMetadata: { externalId: "crm-member" },
        },
      ]);

    ({ userRoutes } = await import("../routes/user"));
    ({ createSessionToken, verifySessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
  });

  async function tokenFor(userId: string): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId,
      tenantId: TENANT_ID,
      mfaVerifiedAt: Date.now(),
    });
  }

  async function tokenForTenant(userId: string, tenantId: string): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
    });
  }

  async function personalTokenFor(userId: string): Promise<string> {
    const personalTenantId = `personal-${userId}`;
    return createSessionToken("0x0000000000000000000000000000000000000000", personalTenantId, {
      userId,
      tenantId: personalTenantId,
      mfaVerifiedAt: Date.now(),
    });
  }

  async function staleTokenFor(userId: string): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
      userId,
      tenantId: TENANT_ID,
    });
  }

  it("lets tenant owners search tenant users without global identity fields", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users?q=member`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        users: Array<{
          userId: string;
          email: string;
          tenantCustomMetadata: Record<string, unknown>;
          linkedAccounts?: unknown;
          walletAddress?: unknown;
          customMetadata?: unknown;
        }>;
      };
    };
    expect(body.data.users).toHaveLength(1);
    expect(body.data.users[0]).toMatchObject({
      userId: memberId,
      email: "member@example.test",
      tenantCustomMetadata: { externalId: "crm-member" },
    });
    expect(body.data.users[0]?.linkedAccounts).toBeUndefined();
    expect(body.data.users[0]?.walletAddress).toBeUndefined();
    expect(body.data.users[0]?.customMetadata).toBeUndefined();
  });

  it("rejects non-admin tenant members", async () => {
    const token = await tokenFor(memberId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(403);
  });

  it("rejects tenant owners without recent MFA before exposing the user directory", async () => {
    const token = await staleTokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(403);
    const body = (await response.json()) as { error?: string };
    expect(body.error).toContain("recent MFA");
  });

  it("returns tenant-scoped single user details", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { userId: string; tenantId: string } };
    expect(body.data).toMatchObject({ userId: memberId, tenantId: TENANT_ID });
  });

  it("rejects single-user directory reads without recent MFA", async () => {
    const token = await staleTokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(403);
  });

  it("pins tenant-admin user directory reads to the active session tenant", async () => {
    const tenantAToken = await tokenForTenant(ownerId, TENANT_ID);
    const crossTenant = await userRoutes.request(`/me/tenants/${OTHER_TENANT_ID}/users`, {
      headers: { Authorization: `Bearer ${tenantAToken}` },
    });
    expect(crossTenant.status).toBe(403);
    const crossTenantBody = (await crossTenant.json()) as { error?: string };
    expect(crossTenantBody.error).toContain("Session tenant");

    const tenantBToken = await tokenForTenant(ownerId, OTHER_TENANT_ID);
    const matchingTenant = await userRoutes.request(`/me/tenants/${OTHER_TENANT_ID}/users`, {
      headers: { Authorization: `Bearer ${tenantBToken}` },
    });
    expect(matchingTenant.status).toBe(200);
  });

  it("does not carry MFA freshness across tenant switches", async () => {
    const personalToken = await personalTokenFor(ownerId);
    const switchResponse = await userRoutes.request("/me/tenants/switch", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${personalToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tenantId: OTHER_TENANT_ID }),
    });

    expect(switchResponse.status).toBe(200);
    const switchBody = (await switchResponse.json()) as { data: { token: string } };
    const switchedSession = await verifySessionToken(switchBody.data.token);
    expect(switchedSession?.tenantId).toBe(OTHER_TENANT_ID);
    expect(switchedSession).not.toHaveProperty("mfaVerifiedAt");

    const directory = await userRoutes.request(`/me/tenants/${OTHER_TENANT_ID}/users`, {
      headers: { Authorization: `Bearer ${switchBody.data.token}` },
    });
    expect(directory.status).toBe(403);
    const directoryBody = (await directory.json()) as { error?: string };
    expect(directoryBody.error).toContain("recent MFA");
  });
});

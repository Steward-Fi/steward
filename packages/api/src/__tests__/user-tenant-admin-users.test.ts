import { afterAll, beforeAll, describe, expect, it } from "bun:test";

import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

const TENANT_ID = "user-tenant-admin-users";
const OTHER_TENANT_ID = "user-tenant-admin-users-other";

describe("user tenant-admin user directory routes", () => {
  let userRoutes: typeof import("../routes/user").userRoutes;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let verifySessionToken: typeof import("../routes/auth").verifySessionToken;
  let ownerId = "";
  let memberId = "";
  let removableId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "user-tenant-admin-users-master-password";
    process.env.STEWARD_JWT_SECRET = "user-tenant-admin-users-jwt-secret";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
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
    const [removable] = await getDb()
      .insert(users)
      .values({ email: "remove@example.test", emailVerified: true, name: "Removable" })
      .returning({ id: users.id });
    ownerId = owner.id;
    memberId = member.id;
    removableId = removable.id;
    await getDb()
      .insert(tenants)
      .values({
        id: `personal-${ownerId}`,
        name: "Owner Personal",
        apiKeyHash: `personal-${ownerId}-hash`,
      });
    await getDb()
      .insert(userTenants)
      .values([
        { userId: ownerId, tenantId: `personal-${ownerId}`, role: "owner" },
        { userId: ownerId, tenantId: TENANT_ID, role: "owner" },
        { userId: ownerId, tenantId: OTHER_TENANT_ID, role: "owner" },
        {
          userId: memberId,
          tenantId: TENANT_ID,
          role: "member",
          customMetadata: { externalId: "crm-member" },
        },
        { userId: removableId, tenantId: TENANT_ID, role: "viewer" },
      ]);

    ({ userRoutes } = await import("../routes/user"));
    ({ createSessionToken, verifySessionToken } = await import("../routes/auth"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
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
    return createSessionToken("0x0000000000000000000000000000000000000000", `personal-${userId}`, {
      userId,
      tenantId: `personal-${userId}`,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
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

  it("allows viewer role to read but not manage the tenant user directory", async () => {
    const token = await tokenFor(removableId);
    const listed = await userRoutes.request(`/me/tenants/${TENANT_ID}/users?q=member`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(listed.status).toBe(200);

    const read = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(read.status).toBe(200);

    const roleUpdate = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}/role`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "developer" }),
    });
    expect(roleUpdate.status).toBe(403);

    const exported = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(exported.status).toBe(403);
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

  it("exports tenant-scoped users as CSV with formula injection protection", async () => {
    await getDb().update(users).set({ name: "=HYPERLINK(1)" }).where(eq(users.id, memberId));
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/export?q=member`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    const csv = await response.text();
    expect(csv).toContain("user_id,tenant_id,role,status,email");
    expect(csv).toContain("member@example.test");
    expect(csv).toContain("'=HYPERLINK(1)");
    expect(csv).toContain("crm-member");
    expect(csv).not.toContain("customMetadata");
    expect(csv).not.toContain("linkedAccounts");
  });

  it("rejects single-user directory reads without recent MFA", async () => {
    const token = await staleTokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(403);
  });

  it("lets tenant owners replace tenant-scoped user metadata only", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${memberId}/metadata`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ tenantCustomMetadata: { externalId: "crm-updated", tier: "pro" } }),
      },
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: { tenantCustomMetadata: Record<string, unknown>; customMetadata?: unknown };
    };
    expect(body.data.tenantCustomMetadata).toEqual({ externalId: "crm-updated", tier: "pro" });
    expect(body.data.customMetadata).toBeUndefined();

    const [membership] = await getDb()
      .select({ customMetadata: userTenants.customMetadata })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, TENANT_ID), eq(userTenants.userId, memberId)));
    expect(membership?.customMetadata).toEqual({ externalId: "crm-updated", tier: "pro" });
  });

  it("lists tenant-scoped user activity without global identity fields", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}/events`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: {
        events: Array<{
          action: string;
          resourceType: string;
          resourceId: string;
          linkedAccounts?: unknown;
          customMetadata?: unknown;
        }>;
      };
    };
    expect(body.data.events.some((event) => event.action === "tenant.member.metadata.update")).toBe(
      true,
    );
    expect(body.data.events[0]?.resourceType).toBe("user");
    expect(body.data.events[0]?.resourceId).toBe(memberId);
    expect(body.data.events[0]?.linkedAccounts).toBeUndefined();
    expect(body.data.events[0]?.customMetadata).toBeUndefined();
  });

  it("rejects invalid or stale tenant user metadata updates", async () => {
    const staleToken = await staleTokenFor(ownerId);
    const stale = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${memberId}/metadata`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${staleToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ tenantCustomMetadata: { externalId: "stale" } }),
    });
    expect(stale.status).toBe(403);

    const token = await tokenFor(ownerId);
    const invalid = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${memberId}/metadata`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ tenantCustomMetadata: "invalid" }),
      },
    );
    expect(invalid.status).toBe(400);
  });

  it("lets tenant owners deactivate and reactivate app-scoped members", async () => {
    const token = await tokenFor(ownerId);
    const deactivate = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${memberId}/deactivate`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deactivated: true }),
      },
    );
    expect(deactivate.status).toBe(200);
    const deactivateBody = (await deactivate.json()) as { data: { deactivatedAt: string | null } };
    expect(deactivateBody.data.deactivatedAt).toBeTruthy();

    const reactivate = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${memberId}/deactivate`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deactivated: false }),
      },
    );
    expect(reactivate.status).toBe(200);
    const reactivateBody = (await reactivate.json()) as { data: { deactivatedAt: string | null } };
    expect(reactivateBody.data.deactivatedAt).toBeNull();
  });

  it("does not let tenant dashboard lifecycle deactivate sole owners or cross-tenant members", async () => {
    const token = await tokenFor(ownerId);
    const soleOwner = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${ownerId}/deactivate`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deactivated: true }),
      },
    );
    expect(soleOwner.status).toBe(409);

    await getDb()
      .insert(userTenants)
      .values({ userId: memberId, tenantId: OTHER_TENANT_ID, role: "member" })
      .onConflictDoNothing();
    const crossTenant = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users/${memberId}/deactivate`,
      {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deactivated: true }),
      },
    );
    expect(crossTenant.status).toBe(409);
    const body = (await crossTenant.json()) as { error?: string };
    expect(body.error).toContain("without other tenant memberships");

    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.tenantId, OTHER_TENANT_ID), eq(userTenants.userId, memberId)));
  });

  it("lets tenant owners remove non-owner members from the tenant", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${removableId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(200);

    const [membership] = await getDb()
      .select({ role: userTenants.role })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, TENANT_ID), eq(userTenants.userId, removableId)));
    expect(membership).toBeUndefined();
  });

  it("does not let tenant owners remove themselves through member removal", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${ownerId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(400);
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

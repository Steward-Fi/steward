import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";

import {
  closeDb,
  getDb,
  tenantConfigs,
  tenantInvitations,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";

const TENANT_ID = "user-tenant-admin-users";
const OTHER_TENANT_ID = "user-tenant-admin-users-other";
const OWNER_PERSONAL_TENANT_ID = "personal-user-tenant-admin-owner";

describe("user tenant-admin user directory routes", () => {
  const previousDbMode = process.env.STEWARD_DB_MODE;
  const previousPgliteMemory = process.env.STEWARD_PGLITE_MEMORY;
  let userRoutes: typeof import("../routes/user").userRoutes;
  let isUserTenantTransitionRequest: typeof import("../routes/user").isUserTenantTransitionRequest;
  let mountedUserRoutes: Hono;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  let verifySessionToken: typeof import("../routes/auth").verifySessionToken;
  let ownerId = "";
  let secondOwnerId = "";
  let memberId = "";

  beforeAll(async () => {
    process.env.STEWARD_DB_MODE = "pglite";
    delete process.env.STEWARD_PGLITE_MEMORY;
    process.env.STEWARD_MASTER_PASSWORD = "user-tenant-admin-users-master-password";
    process.env.STEWARD_JWT_SECRET = "user-tenant-admin-users-jwt-secret";
    process.env.STEWARD_AUDIT_HMAC_KEY ??= "user-tenant-admin-users-audit-key-with-enough-entropy";

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
      .values({ email: "member@example.test", emailVerified: true, name: "Member\\Only" })
      .returning({ id: users.id });
    const [secondOwner] = await getDb()
      .insert(users)
      .values({ email: "second-owner@example.test", emailVerified: true, name: "Second Owner" })
      .returning({ id: users.id });
    ownerId = owner.id;
    secondOwnerId = secondOwner.id;
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
        { userId: secondOwnerId, tenantId: TENANT_ID, role: "owner" },
        {
          userId: memberId,
          tenantId: TENANT_ID,
          role: "member",
          customMetadata: { externalId: "crm-member" },
        },
      ]);

    const userModule = await import("../routes/user");
    ({ isUserTenantTransitionRequest, userRoutes } = userModule);
    mountedUserRoutes = new Hono();
    mountedUserRoutes.use("/user/*", (c, next) => userModule.userSessionAuth(c as never, next));
    mountedUserRoutes.route("/user", userRoutes);
    ({ createSessionToken, verifySessionToken } = await import("../routes/auth"));
  });

  it("matches only exact mounted invitation transition routes", () => {
    expect(isUserTenantTransitionRequest("POST", "/me/tenants/tenant-a/join")).toBe(true);
    expect(isUserTenantTransitionRequest("POST", "/me/tenants/_tenant-a/join")).toBe(true);
    expect(
      isUserTenantTransitionRequest("POST", "/user/me/tenants/tenant-a/invitations/accept"),
    ).toBe(true);
    expect(isUserTenantTransitionRequest("GET", "/user/me/tenants/tenant-a/join")).toBe(false);
    expect(isUserTenantTransitionRequest("POST", "/v1/user/me/tenants/tenant-a/join")).toBe(false);
    expect(isUserTenantTransitionRequest("POST", "/user/me/tenants/tenant-a/join/extra")).toBe(
      false,
    );
    expect(isUserTenantTransitionRequest("POST", "/user/me/tenants/tenant-a%2Fother/join")).toBe(
      false,
    );
    expect(isUserTenantTransitionRequest("POST", "/user/me/tenants/tenant-a%252Fother/join")).toBe(
      false,
    );
  });

  afterAll(async () => {
    await closeDb();
    if (previousDbMode === undefined) delete process.env.STEWARD_DB_MODE;
    else process.env.STEWARD_DB_MODE = previousDbMode;
    if (previousPgliteMemory === undefined) delete process.env.STEWARD_PGLITE_MEMORY;
    else process.env.STEWARD_PGLITE_MEMORY = previousPgliteMemory;
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

  it("treats backslash-prefixed LIKE metacharacters as literal search text", async () => {
    const token = await tokenFor(ownerId);
    const response = await userRoutes.request(
      `/me/tenants/${TENANT_ID}/users?q=${encodeURIComponent("\\%")}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );

    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { users: unknown[] } };
    expect(body.data.users).toEqual([]);
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

  it("rejects reachable tenant-admin membership mutations for personal tenants", async () => {
    const personalTenantId = `personal-${ownerId}`;
    const token = await personalTokenFor(ownerId);
    const create = await userRoutes.request(`/me/tenants/${personalTenantId}/invitations`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ email: "invitee@example.test", role: "member" }),
    });
    expect(create.status).toBe(409);

    const revoke = await userRoutes.request(
      `/me/tenants/${personalTenantId}/invitations/${crypto.randomUUID()}`,
      { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
    );
    expect(revoke.status).toBe(409);

    const role = await userRoutes.request(`/me/tenants/${personalTenantId}/users/${ownerId}/role`, {
      method: "PATCH",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ role: "owner" }),
    });
    expect(role.status).toBe(403);
    const deactivate = await userRoutes.request(
      `/me/tenants/${personalTenantId}/users/${ownerId}/deactivate`,
      {
        method: "PATCH",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ deactivated: true }),
      },
    );
    expect(deactivate.status).toBe(403);
    const remove = await userRoutes.request(`/me/tenants/${personalTenantId}/users/${ownerId}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(remove.status).toBe(403);
  });

  it("consumes a single-use invitation even when the accepting user is already a member", async () => {
    const token = "a".repeat(64);
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const [invitation] = await getDb()
      .insert(tenantInvitations)
      .values({
        tenantId: TENANT_ID,
        email: "owner@example.test",
        role: "member",
        tokenHash,
        expiresAt: new Date(Date.now() + 60_000),
      })
      .returning({ id: tenantInvitations.id });
    const sessionToken = await personalTokenFor(ownerId);
    const accept = () =>
      mountedUserRoutes.request(`/user/me/tenants/${TENANT_ID}/invitations/accept`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });

    const first = await accept();
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ ok: true, alreadyMember: true });
    const [stored] = await getDb()
      .select({ status: tenantInvitations.status })
      .from(tenantInvitations)
      .where(eq(tenantInvitations.id, invitation.id));
    expect(stored?.status).toBe("accepted");
    expect((await accept()).status).toBe(404);
  });

  it("consumes an invite-mode join token before returning an existing membership", async () => {
    const token = "b".repeat(64);
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const [invitation] = await getDb()
      .insert(tenantInvitations)
      .values({
        tenantId: OTHER_TENANT_ID,
        email: "owner@example.test",
        role: "member",
        tokenHash,
        expiresAt: new Date(Date.now() + 60_000),
      })
      .returning({ id: tenantInvitations.id });
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId: OTHER_TENANT_ID, joinMode: "invite" })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { joinMode: "invite", updatedAt: new Date() },
      });
    const sessionToken = await personalTokenFor(ownerId);
    const join = () =>
      mountedUserRoutes.request(`/user/me/tenants/${OTHER_TENANT_ID}/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });

    const first = await join();
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({ ok: true, role: "owner" });
    const [stored] = await getDb()
      .select({ status: tenantInvitations.status })
      .from(tenantInvitations)
      .where(eq(tenantInvitations.id, invitation.id));
    expect(stored?.status).toBe("accepted");

    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.tenantId, OTHER_TENANT_ID), eq(userTenants.userId, ownerId)));
    expect((await join()).status).toBe(403);
    await getDb().insert(userTenants).values({
      tenantId: OTHER_TENANT_ID,
      userId: ownerId,
      role: "owner",
    });
  });

  it("binds invitation transitions to the exact target tenant and verified user", async () => {
    const token = "c".repeat(64);
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const memberPersonalTenantId = `personal-${memberId}`;
    await getDb()
      .insert(tenants)
      .values({
        id: memberPersonalTenantId,
        name: "Member Personal Tenant",
        apiKeyHash: `${memberPersonalTenantId}-hash`,
      })
      .onConflictDoNothing();
    await getDb()
      .insert(userTenants)
      .values({ userId: memberId, tenantId: memberPersonalTenantId, role: "owner" })
      .onConflictDoNothing();
    const [invitation] = await getDb()
      .insert(tenantInvitations)
      .values({
        tenantId: OTHER_TENANT_ID,
        email: "owner@example.test",
        role: "member",
        tokenHash,
        expiresAt: new Date(Date.now() + 60_000),
      })
      .returning({ id: tenantInvitations.id });
    const request = (requestTenantId: string, sessionToken: string) =>
      mountedUserRoutes.request(`/user/me/tenants/${requestTenantId}/invitations/accept`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });

    expect(await request(TENANT_ID, await personalTokenFor(ownerId))).toHaveProperty("status", 404);
    expect(await request(OTHER_TENANT_ID, await personalTokenFor(memberId))).toHaveProperty(
      "status",
      404,
    );
    const [pending] = await getDb()
      .select({ status: tenantInvitations.status })
      .from(tenantInvitations)
      .where(eq(tenantInvitations.id, invitation.id));
    expect(pending?.status).toBe("pending");

    const accepted = await request(OTHER_TENANT_ID, await personalTokenFor(ownerId));
    expect(accepted.status).toBe(200);
    const [stored] = await getDb()
      .select({
        status: tenantInvitations.status,
        acceptedByUserId: tenantInvitations.acceptedByUserId,
      })
      .from(tenantInvitations)
      .where(eq(tenantInvitations.id, invitation.id));
    expect(stored).toMatchObject({ status: "accepted", acceptedByUserId: ownerId });
  });

  it("revalidates the locked verified identity before accepting or joining", async () => {
    const acceptToken = "d".repeat(64);
    const joinToken = "e".repeat(64);
    const invitations = await getDb()
      .insert(tenantInvitations)
      .values([
        {
          tenantId: TENANT_ID,
          email: "owner@example.test",
          role: "member",
          tokenHash: createHash("sha256").update(acceptToken).digest("hex"),
          expiresAt: new Date(Date.now() + 60_000),
        },
        {
          tenantId: OTHER_TENANT_ID,
          email: "owner@example.test",
          role: "member",
          tokenHash: createHash("sha256").update(joinToken).digest("hex"),
          expiresAt: new Date(Date.now() + 60_000),
        },
      ])
      .returning({ id: tenantInvitations.id });
    await getDb()
      .insert(tenantConfigs)
      .values({ tenantId: OTHER_TENANT_ID, joinMode: "invite" })
      .onConflictDoUpdate({
        target: tenantConfigs.tenantId,
        set: { joinMode: "invite", updatedAt: new Date() },
      });
    const sessionToken = await personalTokenFor(ownerId);
    const accept = () =>
      mountedUserRoutes.request(`/user/me/tenants/${TENANT_ID}/invitations/accept`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token: acceptToken }),
      });
    const join = () =>
      mountedUserRoutes.request(`/user/me/tenants/${OTHER_TENANT_ID}/join`, {
        method: "POST",
        headers: { Authorization: `Bearer ${sessionToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ token: joinToken }),
      });

    await getDb().update(users).set({ emailVerified: false }).where(eq(users.id, ownerId));
    expect((await accept()).status).toBe(404);
    expect((await join()).status).toBe(403);
    const pending = await getDb()
      .select({ status: tenantInvitations.status })
      .from(tenantInvitations)
      .where(
        inArray(
          tenantInvitations.id,
          invitations.map((invitation) => invitation.id),
        ),
      );
    expect(pending.map((invitation) => invitation.status)).toEqual(["pending", "pending"]);

    await getDb().update(users).set({ emailVerified: true }).where(eq(users.id, ownerId));
    expect((await accept()).status).toBe(200);
    expect((await join()).status).toBe(200);
  });

  it("serializes concurrent owner demotions so exactly one wins", async () => {
    await getDb()
      .update(userTenants)
      .set({ role: "owner" })
      .where(and(eq(userTenants.tenantId, TENANT_ID), eq(userTenants.userId, secondOwnerId)));
    const [firstToken, secondToken] = await Promise.all([
      tokenFor(ownerId),
      tokenFor(secondOwnerId),
    ]);
    const responses = await Promise.all([
      userRoutes.request(`/me/tenants/${TENANT_ID}/users/${secondOwnerId}/role`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${firstToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ role: "member" }),
      }),
      userRoutes.request(`/me/tenants/${TENANT_ID}/users/${ownerId}/role`, {
        method: "PATCH",
        headers: { Authorization: `Bearer ${secondToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ role: "member" }),
      }),
    ]);
    const statuses = responses.map((response) => response.status).sort();
    expect(statuses[0]).toBe(200);
    // The winning demotion revokes the losing owner's token before commit. If
    // the losing request has not completed authentication yet, conservative
    // revocation may reject it with 401 instead of the later 403/409 checks.
    expect([401, 403, 409]).toContain(statuses[1]);
    const owners = await getDb()
      .select({ userId: userTenants.userId })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, TENANT_ID), eq(userTenants.role, "owner")));
    expect(owners).toHaveLength(1);

    const winnerId = owners[0]!.userId;
    const loserId = winnerId === ownerId ? secondOwnerId : ownerId;
    const forbidden = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${winnerId}/role`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${await tokenFor(loserId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "member" }),
    });
    expect([401, 403]).toContain(forbidden.status);

    const conflict = await userRoutes.request(`/me/tenants/${TENANT_ID}/users/${winnerId}/role`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${await tokenFor(winnerId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "member" }),
    });
    expect(conflict.status).toBe(409);
  });
});

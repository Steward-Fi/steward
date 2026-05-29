import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, refreshTokens, tenants, users } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

const PLATFORM_KEY = "platform-tenant-create-key";
const TENANT_ID = "platform-tenant-create-tenant";

describe("platform tenant creation", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "platform-tenant-create-master-password";
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: [
        "platform:read",
        "platform:write",
        "platform:tenant:create",
        "platform:tenant:delete",
        "platform:tenant-policy:write",
        "platform:agent:create",
      ],
    });

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, TENANT_ID))
      .catch(() => {});
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, `${TENANT_ID}-policies`))
      .catch(() => {});
    await getDb()
      .delete(tenants)
      .where(eq(tenants.id, `${TENANT_ID}-batch`))
      .catch(() => {});
    await closeDb();
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  it("returns the one-time API key but not its verifier hash", async () => {
    const response = await platformRoutes.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({ id: TENANT_ID, name: "Platform Tenant Create" }),
    });

    expect(response.status).toBe(201);
    const body = (await response.json()) as {
      ok: boolean;
      data: { apiKey: string; apiKeyHash?: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data.apiKey).toStartWith("stw_");
    expect(body.data.apiKeyHash).toBeUndefined();
  });

  it("rejects reserved identity tenant ids", async () => {
    const response = await platformRoutes.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: "eth:0x0000000000000000000000000000000000000001",
        name: "Reserved Identity Tenant",
      }),
    });

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("reserved"),
    });
  });

  it("rejects tenant default policies instead of acknowledging unenforced policy state", async () => {
    const createResponse = await platformRoutes.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: `${TENANT_ID}-policies`,
        name: "Platform Tenant Policies",
        defaultPolicies: [
          { id: "limit", type: "spending-limit", enabled: true, config: { dailyLimit: "1" } },
        ],
      }),
    });

    expect(createResponse.status).toBe(501);
    await expect(createResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("not persisted"),
    });

    await getDb()
      .insert(tenants)
      .values({
        id: `${TENANT_ID}-policies`,
        name: "Platform Tenant Policies",
        apiKeyHash: `hash-${TENANT_ID}-policies`,
      });

    const putResponse = await platformRoutes.request(`/tenants/${TENANT_ID}-policies/policies`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify([
        { id: "limit", type: "spending-limit", enabled: true, config: { dailyLimit: "1" } },
      ]),
    });

    expect(putResponse.status).toBe(501);
    await expect(putResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("not persisted or enforced"),
    });
  });

  it("deletes tenant-scoped refresh tokens when deleting a tenant", async () => {
    const tenantId = `${TENANT_ID}-delete`;
    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Platform Tenant Delete",
      apiKeyHash: `hash-${tenantId}`,
    });
    await getDb()
      .insert(agents)
      .values({
        id: `${tenantId}-agent`,
        tenantId,
        name: "Delete Agent",
        walletAddress: "0x0000000000000000000000000000000000000001",
      });
    const refreshUserId = "00000000-0000-0000-0000-000000000001";
    await getDb()
      .insert(users)
      .values({ id: refreshUserId, email: `${tenantId}@example.test` })
      .onConflictDoNothing();
    await getDb()
      .insert(refreshTokens)
      .values({
        id: `${tenantId}-refresh`,
        userId: refreshUserId,
        tenantId,
        tokenHash: "stale-refresh-hash",
        expiresAt: new Date(Date.now() + 60_000),
      });

    const response = await platformRoutes.request(`/tenants/${tenantId}`, {
      method: "DELETE",
      headers: { "X-Steward-Platform-Key": PLATFORM_KEY },
    });

    expect(response.status).toBe(200);
    const remaining = await getDb()
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.tenantId, tenantId));
    expect(remaining).toEqual([]);
  });

  it("rejects invalid batch applyPolicies before creating agents", async () => {
    const tenantId = `${TENANT_ID}-batch`;
    const agentId = `${tenantId}-agent`;
    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Platform Tenant Batch",
      apiKeyHash: `hash-${tenantId}`,
    });

    const response = await platformRoutes.request(`/tenants/${tenantId}/agents/batch`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        agents: [{ id: agentId, name: "Batch Agent" }],
        applyPolicies: [{ id: "bad", type: "not-a-policy", enabled: true, config: {} }],
      }),
    });

    expect(response.status).toBe(400);
    const createdAgents = await getDb()
      .select({ id: agents.id })
      .from(agents)
      .where(eq(agents.id, agentId));
    expect(createdAgents).toEqual([]);
  });
});

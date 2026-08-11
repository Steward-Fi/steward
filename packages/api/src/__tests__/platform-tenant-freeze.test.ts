import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { closeDb, getDb, tenants, vaultSigningFreezes } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq, isNull } from "drizzle-orm";

const FREEZE_KEY = "platform-tenant-freeze-key";
const NO_SCOPE_KEY = "platform-tenant-freeze-noscope-key";
const TENANT_ID = `platform-freeze-tenant-${Date.now()}`;

setDefaultTimeout(30000);

async function activeTenantFreezes(): Promise<Array<{ id: string }>> {
  return getDb()
    .select({ id: vaultSigningFreezes.id })
    .from(vaultSigningFreezes)
    .where(
      and(
        eq(vaultSigningFreezes.tenantId, TENANT_ID),
        eq(vaultSigningFreezes.scopeType, "tenant"),
        isNull(vaultSigningFreezes.liftedAt),
      ),
    );
}

describe("platform tenant freeze", () => {
  let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "platform-tenant-freeze-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "platform-tenant-freeze-audit-hmac-key-with-entropy";
    process.env.STEWARD_PLATFORM_KEYS = `${FREEZE_KEY},${NO_SCOPE_KEY}`;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [FREEZE_KEY]: ["platform:read", "platform:write", "platform:tenant-freeze:write"],
      // Passes the global write gate but lacks the route-level tenant-freeze scope.
      [NO_SCOPE_KEY]: ["platform:read", "platform:write"],
    });

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Platform Freeze Tenant",
      apiKeyHash: "hash",
    });

    ({ platformRoutes } = await import("../routes/platform"));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    delete process.env.STEWARD_PLATFORM_KEYS;
    delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  });

  it("rejects a platform key lacking the tenant-freeze scope with 403", async () => {
    const res = await platformRoutes.request(`/tenants/${TENANT_ID}/freeze`, {
      method: "POST",
      headers: { "X-Steward-Platform-Key": NO_SCOPE_KEY },
    });
    expect(res.status).toBe(403);
    expect(await activeTenantFreezes()).toHaveLength(0);
  });

  it("freezes and unfreezes a tenant with the scoped platform key", async () => {
    const freezeRes = await platformRoutes.request(`/tenants/${TENANT_ID}/freeze`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Steward-Platform-Key": FREEZE_KEY },
      body: JSON.stringify({ reason: "blast-radius incident" }),
    });
    expect(freezeRes.status).toBe(200);
    await expect(freezeRes.json()).resolves.toMatchObject({
      ok: true,
      data: { tenantId: TENANT_ID, scopeType: "tenant", signingState: "frozen" },
    });
    expect(await activeTenantFreezes()).toHaveLength(1);

    const unfreezeRes = await platformRoutes.request(`/tenants/${TENANT_ID}/unfreeze`, {
      method: "POST",
      headers: { "X-Steward-Platform-Key": FREEZE_KEY },
    });
    expect(unfreezeRes.status).toBe(200);
    await expect(unfreezeRes.json()).resolves.toMatchObject({
      ok: true,
      data: { tenantId: TENANT_ID, scopeType: "tenant", signingState: "active" },
    });
    expect(await activeTenantFreezes()).toHaveLength(0);
  });

  it("returns 404 for a freeze on an unknown tenant", async () => {
    const res = await platformRoutes.request("/tenants/does-not-exist/freeze", {
      method: "POST",
      headers: { "X-Steward-Platform-Key": FREEZE_KEY },
    });
    expect(res.status).toBe(404);
  });
});

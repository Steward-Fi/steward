import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  closeDb,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { asc, eq } from "drizzle-orm";

const PLATFORM_KEY = "tenant-create-atomic-platform-key";
const GOOD_AUDIT_KEY = "tenant-create-atomic-audit-key-with-enough-entropy";
let platformRoutes: Awaited<typeof import("../routes/platform")>["platformRoutes"];
let tenantRoutes: Awaited<typeof import("../routes/tenants")>["tenantRoutes"];

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY = GOOD_AUDIT_KEY;
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
    [PLATFORM_KEY]: ["platform:write", "platform:tenant:create"],
  });
  __resetAuditHmacKeyCacheForTests();
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  ({ platformRoutes } = await import("../routes/platform"));
  ({ tenantRoutes } = await import("../routes/tenants"));
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
  delete process.env.STEWARD_PLATFORM_KEYS;
  delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  __resetAuditHmacKeyCacheForTests();
});

const platformHeaders = {
  "content-type": "application/json",
  "x-steward-platform-key": PLATFORM_KEY,
};

async function platformCreate(id: string) {
  return platformRoutes.request("/tenants", {
    method: "POST",
    headers: platformHeaders,
    body: JSON.stringify({ id, name: `Tenant ${id}` }),
  });
}

async function legacyCreate(id: string) {
  return tenantRoutes.request("/", {
    method: "POST",
    headers: platformHeaders,
    body: JSON.stringify({ id, name: `Tenant ${id}`, apiKeyHash: `raw-${id}` }),
  });
}

async function actionsFor(tenantId: string) {
  return getDb()
    .select({ action: auditEvents.action })
    .from(auditEvents)
    .where(eq(auditEvents.tenantId, tenantId))
    .orderBy(asc(auditEvents.seq));
}

async function withBrokenAuditKey<T>(fn: () => Promise<T>): Promise<T> {
  process.env.STEWARD_AUDIT_HMAC_KEY = "too-weak";
  __resetAuditHmacKeyCacheForTests();
  try {
    return await fn();
  } finally {
    process.env.STEWARD_AUDIT_HMAC_KEY = GOOD_AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
  }
}

describe("tenant creation audit atomicity", () => {
  it("commits platform tenant, API-key custody evidence, and final audits together", async () => {
    const tenantId = "tenant-create-atomic-success";
    const response = await platformCreate(tenantId);
    expect(response.status).toBe(201);
    expect(await getDb().select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(1);
    expect(await actionsFor(tenantId)).toEqual([
      { action: "tenant.create.authorized" },
      { action: "tenant.api_key.create.authorized" },
      { action: "tenant.create" },
      { action: "tenant.api_key.create" },
    ]);
  });

  it("rolls back both creation surfaces when required audit cannot append", async () => {
    for (const [tenantId, create] of [
      ["tenant-create-atomic-platform-failure", platformCreate],
      ["tenant-create-atomic-legacy-failure", legacyCreate],
    ] as const) {
      const response = await withBrokenAuditKey(() => create(tenantId));
      expect(response.status, tenantId).toBe(500);
      expect(await getDb().select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(0);
      expect(await actionsFor(tenantId)).toEqual([]);
      expect(
        await getDb().select().from(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId)),
      ).toHaveLength(0);
    }
  });

  it("serializes duplicate creates to one tenant and one complete audit sequence", async () => {
    const tenantId = "tenant-create-atomic-race";
    const responses = await Promise.all([platformCreate(tenantId), platformCreate(tenantId)]);
    expect(responses.map((response) => response.status).sort()).toEqual([201, 409]);
    expect(await getDb().select().from(tenants).where(eq(tenants.id, tenantId))).toHaveLength(1);
    expect(await actionsFor(tenantId)).toHaveLength(4);
  });
});

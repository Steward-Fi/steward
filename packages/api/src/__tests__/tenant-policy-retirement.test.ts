import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditEvents,
  closeDb,
  getDb,
  policies,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables, PolicyRule } from "../services/context";

const PLATFORM_KEY = "tenant-policy-retirement-platform-key";
const TENANT_ID = "tenant-policy-retirement-existing";
const CREATE_ID = "tenant-policy-retirement-create";
const USER_ID = "33333333-3333-4333-8333-333333333333";
const AUDIT_KEY = "tenant-policy-retirement-audit-key-with-enough-entropy";
const DEFAULT_RULE: PolicyRule = {
  id: "legacy-default",
  type: "spending-limit",
  enabled: true,
  config: { maxPerTx: "1", maxPerDay: "1", maxPerWeek: "1" },
};

let sessionToken: string;
let tenantConfigs: typeof import("../services/context")["tenantConfigs"];
let getPolicySet: typeof import("../services/context")["getPolicySet"];
let apps: Array<Hono<{ Variables: AppVariables }>>;

const historicalProcessLocalConfig = () => ({
  id: TENANT_ID,
  name: "Tenant policy retirement",
  defaultPolicies: [DEFAULT_RULE],
});

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY = AUDIT_KEY;
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
    [PLATFORM_KEY]: ["platform:write", "platform:tenant:create"],
  });
  __resetAuditHmacKeyCacheForTests();
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  const context = await import("../services/context");
  const { tenantRoutes } = await import("../routes/tenants");
  tenantConfigs = context.tenantConfigs;
  getPolicySet = context.getPolicySet;

  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Tenant policy retirement",
      apiKeyHash: `hash-${TENANT_ID}`,
    });
  await getDb()
    .insert(users)
    .values({ id: USER_ID, email: `${USER_ID}@example.test` });
  await getDb().insert(userTenants).values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });
  const { createSessionToken } = await import("../routes/auth");
  sessionToken = await createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
    userId: USER_ID,
    email: `${USER_ID}@example.test`,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  tenantConfigs.set(TENANT_ID, historicalProcessLocalConfig());
  apps = [new Hono<{ Variables: AppVariables }>(), new Hono<{ Variables: AppVariables }>()];
  for (const app of apps) app.route("/tenants", tenantRoutes);
});

afterAll(async () => {
  tenantConfigs?.delete(TENANT_ID);
  await getDb().delete(policies).where(eq(policies.agentId, "missing-policy-agent"));
  await getDb().delete(userTenants).where(eq(userTenants.tenantId, TENANT_ID));
  await getDb().delete(users).where(eq(users.id, USER_ID));
  await getDb()
    .delete(tenants)
    .where(inArray(tenants.id, [TENANT_ID, CREATE_ID]));
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
  delete process.env.STEWARD_PLATFORM_KEYS;
  delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
  __resetAuditHmacKeyCacheForTests();
});

async function policyAuditRows() {
  return getDb()
    .select({ id: auditEvents.id, action: auditEvents.action })
    .from(auditEvents)
    .where(inArray(auditEvents.tenantId, [TENANT_ID, CREATE_ID]));
}

async function updateFrom(app: Hono<{ Variables: AppVariables }>) {
  return app.request(`/tenants/${TENANT_ID}/webhook`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${sessionToken}`,
      "content-type": "application/json",
      "x-steward-tenant": TENANT_ID,
    },
    body: JSON.stringify({ defaultPolicies: [DEFAULT_RULE] }),
  });
}

describe("retired process-local tenant policy authority", () => {
  it("rejects create and update writes before database, cache, or audit mutation", async () => {
    const auditsBefore = await policyAuditRows();
    const create = await apps[0].request("/tenants", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-platform-key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: CREATE_ID,
        name: "Must not exist",
        apiKeyHash: "raw-key",
        defaultPolicies: [DEFAULT_RULE],
      }),
    });
    const update = await updateFrom(apps[0]);

    for (const response of [create, update]) {
      expect(response.status).toBe(410);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: expect.stringContaining("not durable"),
      });
    }
    expect(await getDb().select().from(tenants).where(eq(tenants.id, CREATE_ID))).toHaveLength(0);
    expect(tenantConfigs.get(TENANT_ID)).toMatchObject(historicalProcessLocalConfig());
    expect(await policyAuditRows()).toEqual(auditsBefore);
  });

  it("is restart- and replica-independent because no process-local write remains", async () => {
    const first = await updateFrom(apps[0]);
    tenantConfigs.delete(TENANT_ID);
    const second = await updateFrom(apps[1]);
    expect(first.status).toBe(410);
    expect(second.status).toBe(410);
    expect(await first.json()).toEqual(await second.json());
    expect(tenantConfigs.has(TENANT_ID)).toBe(false);
  });

  it("never treats historical map defaults as policy authority", async () => {
    tenantConfigs.set(TENANT_ID, historicalProcessLocalConfig());
    expect(await getPolicySet(TENANT_ID, "missing-policy-agent")).toEqual([]);
    const read = await apps[0].request(`/tenants/${TENANT_ID}`, {
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "x-steward-tenant": TENANT_ID,
      },
    });
    expect(read.status).toBe(200);
    const payload = (await read.json()) as { ok: boolean; data: { id: string } };
    expect(JSON.stringify(payload)).not.toContain("legacy-default");
    expect(payload).toMatchObject({ ok: true, data: { id: TENANT_ID } });
  });
});

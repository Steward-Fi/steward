import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditEvents,
  closeDb,
  digitalAssetAccountAggregations,
  digitalAssetAccounts,
  digitalAssetAccountWallets,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `account-audit-atomic-${Date.now()}`;
const WALLET_ID = `account-audit-wallet-${Date.now()}`;
const ACCOUNT_ID = "acct_audit_atomic";
const AGGREGATION_ID = "acct_agg_audit_atomic";
const STRONG_AUDIT_KEY = "account-audit-atomic-test-key-with-at-least-thirty-two-bytes";

describe("digital asset account audit atomicity", () => {
  let app: Hono<{ Variables: AppVariables }>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "account-audit-atomic-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = STRONG_AUDIT_KEY;
    __resetAuditHmacKeyCacheForTests();
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: TENANT_ID, name: TENANT_ID, apiKeyHash: "hash" });
    await getDb().insert(agents).values({
      id: WALLET_ID,
      tenantId: TENANT_ID,
      name: WALLET_ID,
      walletAddress: "0x1111111111111111111111111111111111111111",
    });
    const { accountRoutes } = await import("../routes/accounts");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", TENANT_ID);
      c.set("authType", "api-key");
      await next();
    });
    app.route("/accounts", accountRoutes);
    app.onError((_error, c) => c.json({ ok: false, error: "forced failure" }, 500));
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
    __resetAuditHmacKeyCacheForTests();
  });

  async function withFailingAudit<T>(operation: () => Promise<T>): Promise<T> {
    process.env.STEWARD_AUDIT_HMAC_KEY = "too-short";
    __resetAuditHmacKeyCacheForTests();
    try {
      return await operation();
    } finally {
      process.env.STEWARD_AUDIT_HMAC_KEY = STRONG_AUDIT_KEY;
      __resetAuditHmacKeyCacheForTests();
    }
  }

  it("rolls back every account and aggregation write when its completion audit fails", async () => {
    const failedCreate = await withFailingAudit(() =>
      app.request("/accounts", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: ACCOUNT_ID, wallet_ids: [WALLET_ID] }),
      }),
    );
    expect(failedCreate.status).toBe(400);
    expect(
      await getDb()
        .select({ id: digitalAssetAccounts.id })
        .from(digitalAssetAccounts)
        .where(
          and(
            eq(digitalAssetAccounts.tenantId, TENANT_ID),
            eq(digitalAssetAccounts.id, ACCOUNT_ID),
          ),
        ),
    ).toHaveLength(0);

    await getDb().insert(digitalAssetAccounts).values({
      id: ACCOUNT_ID,
      tenantId: TENANT_ID,
      displayName: "Before",
      metadata: {},
    });
    await getDb().insert(digitalAssetAccountWallets).values({
      tenantId: TENANT_ID,
      accountId: ACCOUNT_ID,
      walletAgentId: WALLET_ID,
      chainFamily: null,
    });

    const failedAggregationCreate = await withFailingAudit(() =>
      app.request(`/accounts/${ACCOUNT_ID}/aggregations`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ id: AGGREGATION_ID }),
      }),
    );
    expect(failedAggregationCreate.status).toBe(400);
    expect(
      await getDb()
        .select({ id: digitalAssetAccountAggregations.id })
        .from(digitalAssetAccountAggregations)
        .where(eq(digitalAssetAccountAggregations.id, AGGREGATION_ID)),
    ).toHaveLength(0);

    const failedUpdate = await withFailingAudit(() =>
      app.request(`/accounts/${ACCOUNT_ID}`, {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ display_name: "After" }),
      }),
    );
    expect(failedUpdate.status).toBe(400);
    const [unchanged] = await getDb()
      .select({ displayName: digitalAssetAccounts.displayName })
      .from(digitalAssetAccounts)
      .where(eq(digitalAssetAccounts.id, ACCOUNT_ID));
    expect(unchanged?.displayName).toBe("Before");

    await getDb()
      .insert(digitalAssetAccountAggregations)
      .values({
        id: AGGREGATION_ID,
        tenantId: TENANT_ID,
        accountId: ACCOUNT_ID,
        walletAgentIds: [WALLET_ID],
        chainFamilies: ["evm"],
        metadata: {},
      });
    const failedAggregationDelete = await withFailingAudit(() =>
      app.request(`/accounts/${ACCOUNT_ID}/aggregations/${AGGREGATION_ID}`, {
        method: "DELETE",
      }),
    );
    expect(failedAggregationDelete.status).toBe(500);
    expect(
      await getDb()
        .select({ id: digitalAssetAccountAggregations.id })
        .from(digitalAssetAccountAggregations)
        .where(eq(digitalAssetAccountAggregations.id, AGGREGATION_ID)),
    ).toHaveLength(1);

    const failedDelete = await withFailingAudit(() =>
      app.request(`/accounts/${ACCOUNT_ID}`, { method: "DELETE" }),
    );
    expect(failedDelete.status).toBe(500);
    expect(
      await getDb()
        .select({ id: digitalAssetAccounts.id })
        .from(digitalAssetAccounts)
        .where(eq(digitalAssetAccounts.id, ACCOUNT_ID)),
    ).toHaveLength(1);
    expect(
      await getDb()
        .select({ id: auditEvents.id })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, TENANT_ID)),
    ).toHaveLength(0);
  });
});

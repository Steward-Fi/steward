import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants, tradeSessions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

afterAll(async () => {
  await closeDb();
});

describe("trade policy audit", () => {
  it("rejects out-of-policy Hyperliquid orders before submission and writes audit", async () => {
    const tenantId = `tenant-trade-policy-${Date.now()}`;
    const agentId = `agent-trade-policy-${Date.now()}`;
    const sessionId = `ses_${crypto.randomUUID()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "Trade Policy Test Tenant",
      apiKeyHash: "test-hash",
      ownerAddress: "0x0000000000000000000000000000000000000000",
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Trade Policy Test Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb()
      .insert(tradeSessions)
      .values({
        id: sessionId,
        tenantId,
        agentId,
        venue: "hyperliquid",
        walletId: "0x0000000000000000000000000000000000000001",
        status: "active",
        dailySpendUsd: "0",
        dailyCapUsd: "100",
        perOrderCapUsd: "50",
        leverageCap: "2",
        allowedAssets: ["BTC", "ETH"],
        expiresAt: new Date(Date.now() + 60_000),
      });

    process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
    process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
    const { tradeRoutes } = await import("../routes/trade");
    const app = new Hono<{
      Variables: {
        tenantId: string;
        agentScope: string;
        authType: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("agentScope", agentId);
      c.set("authType", "agent");
      await next();
    });
    app.route("/v1/trade", tradeRoutes);

    const res = await app.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId,
        asset: "ETH",
        side: "buy",
        size: 1,
        limitPx: 200,
        leverage: 3,
      }),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      code: "policy-violation",
      reason: "leverage-cap: leverage 3 exceeds cap 2",
    });

    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, "trade.order.policy-rejected"));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ tenantId, actorId: agentId, requestId: sessionId });
    expect(rows[0]?.metadata).toMatchObject({
      sessionId,
      reason: "leverage-cap: leverage 3 exceeds cap 2",
      correlationId: sessionId,
    });
  });
});

import { afterAll, beforeAll, describe, expect, it, mock, setDefaultTimeout } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  agents,
  agentWallets,
  auditEvents,
  closeDb,
  getDb,
  tenants,
  tradeSessions,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

setDefaultTimeout(30000);

const auditHmacKey = "trade-policy-audit-test-audit-hmac-key-0123456789abcdef";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY ??= auditHmacKey;
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });
});

const originalFetch = globalThis.fetch;

afterAll(async () => {
  mock.restore();
  globalThis.fetch = originalFetch;
  await closeDb();
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe("trade policy audit", () => {
  it("binds Hyperliquid sessions to the agent venue wallet instead of caller-supplied metadata", async () => {
    const tenantId = `tenant-trade-wallet-${Date.now()}`;
    const agentId = `agent-trade-wallet-${Date.now()}`;
    const realWallet = "0x00000000000000000000000000000000000000aa";
    const spoofedWallet = "0x00000000000000000000000000000000000000bb";

    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Trade Wallet Test Tenant",
        apiKeyHash: `test-hash-${tenantId}`,
        ownerAddress: `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`,
      });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Trade Wallet Test Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
    await getDb().insert(agentWallets).values({
      agentId,
      chainFamily: "evm",
      venue: "hyperliquid",
      address: realWallet,
    });

    process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
    const { tradeRoutes } = await import("../routes/trade");
    const app = new Hono<{
      Variables: {
        tenantId: string;
        agentScope: null;
        authType: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("agentScope", null);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/v1/trade", tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "hyperliquid",
        walletAddress: spoofedWallet,
        dailyCap: 100,
        perOrderCap: 50,
        leverageCap: 2,
        allowedAssets: ["BTC"],
      }),
    });

    expect(res.status).toBe(201);
    const created = (await res.json()) as { data: { sessionId: string } };
    const [session] = await getDb()
      .select()
      .from(tradeSessions)
      .where(eq(tradeSessions.id, created.data.sessionId));
    expect(session?.walletId).toBe(realWallet);
    expect(session?.walletId).not.toBe(spoofedWallet);
  });

  it("rejects out-of-policy Hyperliquid orders before submission and writes audit", async () => {
    const tenantId = `tenant-trade-policy-${Date.now()}`;
    const agentId = `agent-trade-policy-${Date.now()}`;
    const sessionId = `ses_${crypto.randomUUID()}`;

    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Trade Policy Test Tenant",
        apiKeyHash: `test-hash-${tenantId}`,
        ownerAddress: `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`,
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
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
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

  it("uses live mids for sell-order notional so low limits cannot bypass caps", async () => {
    const tenantId = `tenant-trade-notional-${Date.now()}`;
    const agentId = `agent-trade-notional-${Date.now()}`;
    const sessionId = `ses_${crypto.randomUUID()}`;

    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Trade Notional Test Tenant",
        apiKeyHash: `test-hash-${tenantId}`,
        ownerAddress: `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`,
      });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Trade Notional Test Agent",
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

    globalThis.fetch = mock(async () => {
      return new Response(JSON.stringify({ BTC: "60000", ETH: "3000" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as unknown as typeof fetch;

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
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({
        sessionId,
        asset: "BTC",
        side: "sell",
        size: 1,
        limitPx: 1,
        leverage: 1,
      }),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      code: "policy-violation",
      reason: "per-order-cap: order $60000 exceeds cap $50",
    });
  });

  it("rejects non-decimal Hyperliquid prices before policy reservation", async () => {
    const tenantId = `tenant-trade-price-${Date.now()}`;
    const agentId = `agent-trade-price-${Date.now()}`;
    const sessionId = `ses_${crypto.randomUUID()}`;

    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Trade Price Test Tenant",
        apiKeyHash: `test-hash-${tenantId}`,
        ownerAddress: `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`,
      });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Trade Price Test Agent",
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
        allowedAssets: ["BTC"],
        expiresAt: new Date(Date.now() + 60_000),
      });

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
      c.set("authType", "agent-token");
      await next();
    });
    app.route("/v1/trade", tradeRoutes);

    const res = await app.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": crypto.randomUUID() },
      body: JSON.stringify({
        sessionId,
        asset: "BTC",
        side: "buy",
        size: 1,
        limitPx: "0x1",
        leverage: 1,
      }),
    });

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      ok: false,
      error: "limitPx must be a positive finite price",
    });

    const [session] = await getDb()
      .select()
      .from(tradeSessions)
      .where(eq(tradeSessions.id, sessionId));
    expect(Number(session?.dailySpendUsd)).toBe(0);
  });

  it("requires tenant-level auth for unscoped trade session management", async () => {
    const tenantId = `tenant-trade-member-${Date.now()}`;
    const agentId = `agent-trade-member-${Date.now()}`;

    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Trade Member Test Tenant",
        apiKeyHash: `test-hash-${tenantId}`,
        ownerAddress: `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`,
      });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Trade Member Test Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });

    process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
    const { tradeRoutes } = await import("../routes/trade");
    const app = new Hono<{
      Variables: {
        tenantId: string;
        agentScope: null;
        authType: string;
        tenantRole: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("agentScope", null);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "member");
      await next();
    });
    app.route("/v1/trade", tradeRoutes);

    const res = await app.request("/v1/trade/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId,
        venue: "hyperliquid",
        dailyCap: 100,
        perOrderCap: 50,
        leverageCap: 2,
        allowedAssets: ["BTC"],
      }),
    });

    expect(res.status).toBe(403);
    expect(((await res.json()) as { error: string }).error).toContain("insufficient access");
  });

  it("keeps tenant-admin trade session management from accepting agent tokens", () => {
    const tradeSource = readFileSync(join(import.meta.dir, "..", "routes", "trade.ts"), "utf8");
    const helperStart = tradeSource.indexOf("function canManageTradeSession");
    expect(helperStart).toBeGreaterThanOrEqual(0);
    const helperEnd = tradeSource.indexOf("function canAgentSelfManageSession", helperStart);
    const helperSource = tradeSource.slice(helperStart, helperEnd);
    expect(helperSource).toContain('authType === "session-jwt"');
    expect(helperSource).toContain('authType === "api-key"');
    expect(helperSource).not.toContain('authType === "agent-token"');
  });

  it("deletes newly created trade sessions if the final creation audit fails", () => {
    const tradeSource = readFileSync(join(import.meta.dir, "..", "routes", "trade.ts"), "utf8");
    const sessionManagerSource = readFileSync(
      join(import.meta.dir, "..", "..", "..", "trade-sessions", "src", "index.ts"),
      "utf8",
    );
    const createStart = tradeSource.indexOf('tradeRoutes.post("/sessions"');
    expect(createStart).toBeGreaterThanOrEqual(0);
    const createRoute = tradeSource.slice(
      createStart,
      tradeSource.indexOf('tradeRoutes.get("/sessions/:id"', createStart),
    );
    const managerCreate = createRoute.indexOf("sessionManager.createSession");
    const finalAudit = createRoute.indexOf("trade.session.created", managerCreate);
    const rollback = createRoute.indexOf("sessionManager.deleteSession", finalAudit);
    expect(managerCreate).toBeGreaterThanOrEqual(0);
    expect(finalAudit).toBeGreaterThan(managerCreate);
    expect(rollback).toBeGreaterThan(finalAudit);
    expect(sessionManagerSource).toContain("async deleteSession(input: GetSessionInput)");
    expect(sessionManagerSource).toContain(".delete(tradeSessions)");
    expect(sessionManagerSource).toContain("await this.deleteRedis(input.tenantId, input.id)");
  });

  it("requires idempotency keys for trade order submission", async () => {
    const tenantId = `tenant-trade-idempotency-${Date.now()}`;
    const agentId = `agent-trade-idempotency-${Date.now()}`;

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
      c.set("authType", "agent-token");
      await next();
    });
    app.route("/v1/trade", tradeRoutes);

    const res = await app.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sessionId: "session-without-idempotency",
        asset: "BTC",
        side: "buy",
        size: 1,
        limitPx: 100,
        leverage: 1,
      }),
    });

    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain("Idempotency-Key");
  });

  it("replays trade idempotency with the original HTTP envelope", () => {
    const tradeSource = readFileSync(join(import.meta.dir, "..", "routes", "trade.ts"), "utf8");
    expect(tradeSource).toContain("type TradeIdempotencyResponse");
    expect(tradeSource).toContain("function tradeReplayResponse");
    expect(tradeSource).toContain('headers: { "Idempotency-Replayed": "true" }');
    expect(tradeSource).toContain("status: 502");
    expect(tradeSource).toContain("status: 400");
    expect(tradeSource).not.toContain("return c.json(responseData(idempotency.response))");
  });
});

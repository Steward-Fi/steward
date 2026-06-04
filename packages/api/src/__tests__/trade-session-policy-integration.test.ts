import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentPolicies, agents, closeDb, getDb, tenants, tradeSessions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

process.env.DATABASE_URL = "postgres://test:test@localhost:5432/test";
process.env.STEWARD_MASTER_PASSWORD = "test-master-password";

const tenantId = "tenant-trade-session-policy";
const policyAgentId = "agent-trade-session-policy";
const defaultAgentId = "agent-trade-session-default";
let app: Hono;

async function createSession(agentId: string, body: Record<string, unknown> = {}) {
  return app.request("/v1/trade/sessions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agentId,
      venue: "hyperliquid",
      walletAddress: "0x0000000000000000000000000000000000000001",
      ...body,
    }),
  });
}

async function sessionRowFromResponse(res: Response) {
  const body = (await res.json()) as { data: { sessionId: string } };
  const [row] = await getDb()
    .select()
    .from(tradeSessions)
    .where(eq(tradeSessions.id, body.data.sessionId));
  return row;
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  await closeDb().catch(() => undefined);
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const { tradeRoutes } = await import("../routes/trade");

  await getDb().insert(tenants).values({
    id: tenantId,
    name: "Trade Session Policy Tenant",
    apiKeyHash: "unused",
  });
  await getDb()
    .insert(agents)
    .values([
      {
        id: policyAgentId,
        tenantId,
        name: "Policy Agent",
        walletAddress: "0x0000000000000000000000000000000000000001",
      },
      {
        id: defaultAgentId,
        tenantId,
        name: "Default Agent",
        walletAddress: "0x0000000000000000000000000000000000000002",
      },
    ]);
  await getDb()
    .insert(agentPolicies)
    .values({
      agentId: policyAgentId,
      tenantId,
      dailyCapUsd: "250",
      perOrderCapUsd: "50",
      leverageCap: "3",
      allowedAssets: ["BTC", "ETH", "BNB"],
      allowedVenues: ["hyperliquid"],
      updatedBy: `agent:${policyAgentId}`,
      updatedReason: "test policy",
    });
  app = new Hono();
  app.use("*", async (c, next) => {
    c.set("tenantId", tenantId);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "owner");
    c.set("userId", "trade-session-policy-owner");
    c.set("sessionMfaVerifiedAt", Date.now());
    await next();
  });
  app.route("/v1/trade", tradeRoutes);
});

afterAll(async () => {
  await closeDb().catch(() => undefined);
});

describe("trade session agent policy integration", () => {
  it("clamps omitted session caps to the agent policy", async () => {
    const res = await createSession(policyAgentId);

    expect(res.status).toBe(201);
    const row = await sessionRowFromResponse(res);
    expect(Number(row?.dailyCapUsd)).toBe(250);
    expect(Number(row?.perOrderCapUsd)).toBe(50);
    expect(Number(row?.leverageCap)).toBe(3);
  });

  it("uses schema defaults for an agent without a policy", async () => {
    const res = await createSession(defaultAgentId);

    expect(res.status).toBe(201);
    const row = await sessionRowFromResponse(res);
    expect(Number(row?.dailyCapUsd)).toBe(300);
    expect(Number(row?.perOrderCapUsd)).toBe(100);
    expect(Number(row?.leverageCap)).toBe(5);
  });

  it("rejects requested session caps above the agent policy", async () => {
    const res = await createSession(policyAgentId, { dailyCap: 251 });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { code: string; message: string };
    expect(body.code).toBe("policy-violation");
    expect(body.message).toBe("session cap 251 exceeds agent policy cap 250");
  });
});

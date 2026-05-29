import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `agent-spend-tenant-${Date.now()}`;
const AGENT_ID = `agent-spend-agent-${Date.now()}`;

async function makeApp() {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "api-key");
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent spend API", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-spend-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Agent Spend Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Agent Spend Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    await getDb()
      .insert(transactions)
      .values([
        {
          id: `spend-today-${Date.now()}`,
          agentId: AGENT_ID,
          status: "signed",
          toAddress: "0x0000000000000000000000000000000000000001",
          value: "100",
          chainId: 8453,
          policyResults: [],
        },
        {
          id: `spend-rejected-${Date.now()}`,
          agentId: AGENT_ID,
          status: "rejected",
          toAddress: "0x0000000000000000000000000000000000000002",
          value: "999",
          chainId: 8453,
          policyResults: [],
        },
      ]);
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("returns DB-backed on-chain spend and disabled realtime state without Redis", async () => {
    const response = await app.request(`/agents/${AGENT_ID}/spend`);
    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        agentId: string;
        walletAddress: string;
        onchain: { todayWei: string; weekWei: string; monthWei: string };
        realtime: {
          enabled: boolean;
          periods: Array<{
            period: string;
            spentUsd: number | null;
            byHost: Record<string, number>;
          }>;
        };
        sponsorship: { enabled: boolean; provider: string | null };
      };
    };

    expect(body.ok).toBe(true);
    expect(body.data.agentId).toBe(AGENT_ID);
    expect(body.data.walletAddress).toBe("0x1234567890123456789012345678901234567890");
    expect(body.data.onchain.todayWei).toBe("100");
    expect(body.data.onchain.weekWei).toBe("100");
    expect(body.data.onchain.monthWei).toBe("100");
    expect(body.data.realtime.enabled).toBe(false);
    expect(body.data.realtime.periods.map((period) => period.period)).toEqual([
      "day",
      "week",
      "month",
    ]);
    expect(body.data.realtime.periods.every((period) => period.spentUsd === null)).toBe(true);
    expect(body.data.sponsorship).toEqual({ enabled: false, provider: null });
  });
});

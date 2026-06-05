import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agents, closeDb, getDb, policies, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `proxy-sim-chain-tenant-${Date.now()}`;
const AGENT_ID = `proxy-sim-chain-agent-${Date.now()}`;
const DEFAULT_CHAIN_ID = 84532;
const OTHER_CHAIN_ID = 8453;

async function makeApp() {
  const { policiesStandaloneRoutes } = await import("../routes/policies-standalone");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    c.set("authType", "session-jwt");
    c.set("tenantRole", "admin");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("userId", "22222222-2222-4222-8222-222222222222");
    await next();
  });
  app.route("/policies", policiesStandaloneRoutes);
  return app;
}

describe("standalone policy proxy simulation chain scoping", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "proxy-sim-chain-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "proxy-sim-chain-audit-key-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });

    await getDb()
      .insert(tenants)
      .values({ id: TENANT_ID, name: "Proxy Simulation Tenant", apiKeyHash: `hash-${TENANT_ID}` });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Proxy Simulation Agent",
      walletAddress: "0x1111111111111111111111111111111111111111",
    });
    await getDb()
      .insert(policies)
      .values({
        id: `${AGENT_ID}-spend`,
        agentId: AGENT_ID,
        type: "spending-limit",
        enabled: true,
        // maxPerTx must be set: the fail-closed engine treats a missing per-tx
        // limit as 0 and denies, which would mask the chain-scoped daily-spend
        // behavior this test verifies.
        config: { maxPerTx: "20", maxPerDay: "20", maxPerWeek: "20" },
      });
    await getDb()
      .insert(transactions)
      .values([
        {
          id: `${AGENT_ID}-default-chain`,
          agentId: AGENT_ID,
          status: "signed",
          toAddress: "0x3333333333333333333333333333333333333333",
          value: "10",
          chainId: DEFAULT_CHAIN_ID,
          policyResults: [],
          signedAt: new Date(),
        },
        {
          id: `${AGENT_ID}-other-chain`,
          agentId: AGENT_ID,
          status: "signed",
          toAddress: "0x4444444444444444444444444444444444444444",
          value: "1000",
          chainId: OTHER_CHAIN_ID,
          policyResults: [],
          signedAt: new Date(),
        },
      ]);
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("defaults a no-chainId proxy simulation to default-chain spend stats only", async () => {
    const response = await app.request("/policies/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        agentId: AGENT_ID,
        request: {
          kind: "proxy",
          method: "POST",
          url: "https://example.com/orders",
          body: { value: "1" },
        },
      }),
    });

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: {
        approved: boolean;
        counters: { spentToday: string; spentThisWeek: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.approved).toBe(true);
    expect(body.data.counters.spentToday).toBe("10");
    expect(body.data.counters.spentThisWeek).toBe("10");
  });
});

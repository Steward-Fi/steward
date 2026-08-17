import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agentPolicies, agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

/**
 * SEC-208 regression: PUT /agents/:agentId/policy is the only writer of the
 * trade-session ceiling table. The human-ceiling model requires an
 * owner/admin session with recent MFA for unrestricted writes; agent tokens
 * are tighten-only (covered in agent-policy.test.ts).
 */

const TENANT_ID = `agent-trade-policy-admin-${Date.now()}`;
const AGENT_ID = `agent-trade-policy-admin-agent-${Date.now()}`;

setDefaultTimeout(30000);

type AuthMode = "admin" | "admin-no-mfa" | "member" | "api-key";

async function makeApp(authMode: AuthMode = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "api-key") {
      c.set("authType", "api-key");
    } else {
      c.set("authType", "session-jwt");
      c.set("tenantRole", authMode === "member" ? "member" : "owner");
      c.set("userId", "trade-policy-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

function putPolicy(app: Awaited<ReturnType<typeof makeApp>>, body: Record<string, unknown>) {
  return app.request(`/agents/${AGENT_ID}/policy`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

describe("agent trade policy admin path (SEC-208)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-trade-policy-admin-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-trade-policy-admin-audit-hmac-key-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Trade Policy Admin Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Trade Policy Admin Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("rejects a tenant API key with 403 (no machine self-escalation)", async () => {
    const app = await makeApp("api-key");
    const res = await putPolicy(app, { dailyCap: 5000, reason: "api-key raise" });
    expect(res.status).toBe(403);
  });

  it("rejects a non-admin session with 403", async () => {
    const app = await makeApp("member");
    const res = await putPolicy(app, { dailyCap: 5000, reason: "member raise" });
    expect(res.status).toBe(403);
  });

  it("rejects an admin session without recent MFA with 403", async () => {
    const app = await makeApp("admin-no-mfa");
    const res = await putPolicy(app, { dailyCap: 5000, reason: "no-mfa raise" });
    expect(res.status).toBe(403);
    await expect(res.json()).resolves.toMatchObject({
      ok: false,
      error: "Agent policy updates requires recent MFA verification",
    });
  });

  it("allows an owner/admin session with recent MFA to loosen limits", async () => {
    const app = await makeApp("admin");
    const res = await putPolicy(app, {
      dailyCap: 5000,
      perOrderCap: 1000,
      leverageCap: 20,
      allowedAssets: ["BTC", "ETH", "SOL"],
      allowedVenues: ["hyperliquid"],
      allowBuilderPerps: true,
      reason: "human-approved ceiling raise",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        policy: {
          dailyCap: number;
          perOrderCap: number;
          leverageCap: number;
          allowedAssets: string[];
          allowBuilderPerps: boolean;
          updatedBy: string;
        };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.policy).toMatchObject({
      dailyCap: 5000,
      perOrderCap: 1000,
      leverageCap: 20,
      allowBuilderPerps: true,
      updatedBy: "trade-policy-admin",
    });
    expect(body.data.policy.allowedAssets).toEqual(["BTC", "ETH", "SOL"]);

    const [row] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, AGENT_ID));
    expect(row?.updatedBy).toBe("trade-policy-admin");
  });
});

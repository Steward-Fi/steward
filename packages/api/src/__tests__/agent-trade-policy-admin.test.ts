import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  agentPolicies,
  agents,
  auditEvents,
  closeDb,
  getDb,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, asc, eq, sql } from "drizzle-orm";
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
const USE_REAL_POSTGRES = Boolean(process.env.DATABASE_URL);
const MUTATED_ENV = [
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_AUDIT_HMAC_KEY",
] as const;
const originalEnv = new Map(MUTATED_ENV.map((name) => [name, process.env[name]]));

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
  app.onError((_error, c) => c.json({ ok: false, error: "Internal server error" }, 500));
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
    process.env.STEWARD_MASTER_PASSWORD = "agent-trade-policy-admin-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "agent-trade-policy-admin-audit-hmac-key-entropy";
    __resetAuditHmacKeyCacheForTests();
    if (!USE_REAL_POSTGRES) {
      process.env.STEWARD_PGLITE_MEMORY = "true";
      const { db, client } = await createPGLiteDb("memory://");
      setPGLiteOverride(db, async () => {
        await client.close();
      });
    } else {
      delete process.env.STEWARD_PGLITE_MEMORY;
    }
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
    if (USE_REAL_POSTGRES) {
      await getDb().delete(agentPolicies).where(eq(agentPolicies.agentId, AGENT_ID));
      await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
      await getDb().execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${TENANT_ID}`);
      await getDb().delete(agents).where(eq(agents.id, AGENT_ID));
      await getDb().delete(tenants).where(eq(tenants.id, TENANT_ID));
    }
    await closeDb();
    for (const [name, value] of originalEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    __resetAuditHmacKeyCacheForTests();
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

  it("rolls back the policy row when its required audit append fails", async () => {
    const app = await makeApp("admin");
    const [before] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, AGENT_ID));
    const reason = "must roll back with audit";

    try {
      await getDb().execute(
        sql.raw(`
        CREATE OR REPLACE FUNCTION fail_agent_policy_completion_audit()
        RETURNS trigger AS $$
        BEGIN
          IF NEW.action = 'agent.policy.updated' THEN
            RAISE EXCEPTION 'required agent policy audit failed';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        `),
      );
      await getDb().execute(
        sql.raw(`
        CREATE TRIGGER agent_policy_completion_audit_failure
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_agent_policy_completion_audit()
        `),
      );
      const response = await putPolicy(app, { dailyCap: 9000, reason });
      expect(response.status).toBe(500);
      await expect(response.json()).resolves.toEqual({
        ok: false,
        error: "Internal server error",
      });
      const [after] = await getDb()
        .select()
        .from(agentPolicies)
        .where(eq(agentPolicies.agentId, AGENT_ID));
      expect(after).toEqual(before);
      expect(
        await getDb()
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, TENANT_ID),
              eq(auditEvents.action, "agent.policy.updated"),
              eq(auditEvents.resourceId, AGENT_ID),
              sql`${auditEvents.metadata}->>'reason' = ${reason}`,
            ),
          ),
      ).toHaveLength(0);
    } finally {
      await getDb().execute(
        sql.raw("DROP TRIGGER IF EXISTS agent_policy_completion_audit_failure ON audit_events"),
      );
      await getDb().execute(
        sql.raw("DROP FUNCTION IF EXISTS fail_agent_policy_completion_audit()"),
      );
    }
  });

  it("serializes concurrent human partial patches and audits the exact committed chain", async () => {
    const app = await makeApp("admin");
    const reasons = ["concurrent human daily patch", "concurrent human leverage patch"];
    const responses = await Promise.all([
      putPolicy(app, { dailyCap: 4500, reason: reasons[0] }),
      putPolicy(app, { leverageCap: 18, reason: reasons[1] }),
    ]);
    expect(responses.map((response) => response.status)).toEqual([200, 200]);

    const [row] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, AGENT_ID));
    expect(row).toMatchObject({ dailyCapUsd: "4500", leverageCap: "18" });

    const events = (
      await getDb()
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, TENANT_ID),
            eq(auditEvents.action, "agent.policy.updated"),
            eq(auditEvents.resourceId, AGENT_ID),
          ),
        )
        .orderBy(asc(auditEvents.seq))
    ).filter((event) => reasons.includes(String(event.metadata.reason)));
    expect(events).toHaveLength(2);
    expect(events[1].seq).toBe(events[0].seq + 1);
    expect(Buffer.from(events[1].prevHash).equals(Buffer.from(events[0].hmac))).toBe(true);
    expect(events[1].metadata.before).toEqual(events[0].metadata.after);
    expect(events.map((event) => event.metadata.reason).sort()).toEqual([...reasons].sort());
  });
});

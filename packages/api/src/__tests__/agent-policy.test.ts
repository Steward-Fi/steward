import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { agentPolicies, agents, auditEvents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

process.env.DATABASE_URL = "postgres://test:test@localhost:5432/test";
process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
setDefaultTimeout(30000);

const tenantId = "tenant-agent-policy-test";
const agentId = "agent-policy-test";
const missingAgentId = "agent-policy-missing-row";
let app: Awaited<typeof import("../app")>["app"];
let apiKey = "";
let agentToken = "";

// Policy/cap mutations are now agent-token scoped. Tenant-level API-key writes
// are rejected by the route before the policy body is evaluated.
async function putPolicy(body: Record<string, unknown>) {
  return app.request(`/v1/agents/${agentId}/policy`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${agentToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
  process.env.STEWARD_JWT_SECRET = "agent-policy-test-jwt-secret-with-enough-entropy";
  process.env.STEWARD_AUDIT_HMAC_KEY = "agent-policy-test-audit-hmac-key-with-enough-entropy";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ app } = await import("../app"));

  const keyPair = generateApiKey();
  apiKey = keyPair.key;
  await getDb().insert(tenants).values({
    id: tenantId,
    name: "Agent Policy Tenant",
    apiKeyHash: keyPair.hash,
  });
  await getDb()
    .insert(agents)
    .values([
      {
        id: agentId,
        tenantId,
        name: "Agent Policy Test Agent",
        walletAddress: "0x0000000000000000000000000000000000000001",
      },
      {
        id: missingAgentId,
        tenantId,
        name: "Agent Policy Missing Row",
        walletAddress: "0x0000000000000000000000000000000000000002",
      },
    ]);
  agentToken = await signAgentToken({ agentId, tenantId, sub: `agent:${agentId}` } as never, "1h");
});

afterAll(async () => {
  await closeDb().catch(() => undefined);
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_AUDIT_HMAC_KEY;
});

describe("agent trade policy", () => {
  it("GET returns 404 with defaults for an agent with no policy", async () => {
    const res = await app.request(`/v1/agents/${missingAgentId}/policy`, {
      headers: {
        "X-Steward-Tenant": tenantId,
        "X-Steward-Key": apiKey,
      },
    });

    expect(res.status).toBe(404);
    const body = (await res.json()) as {
      ok: boolean;
      error: string;
      data: { defaults: { dailyCap: number; perOrderCap: number; leverageCap: number } };
    };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("Agent policy not found");
    expect(body.data.defaults).toMatchObject({ dailyCap: 1000, perOrderCap: 500, leverageCap: 10 });
  });

  it("PUT creates a new policy from defaults and records updated_by", async () => {
    const res = await putPolicy({
      dailyCap: 800,
      perOrderCap: 250,
      leverageCap: 8,
      allowedAssets: ["BTC", "ETH"],
      allowedVenues: ["hyperliquid"],
      reason: "initial governance policy",
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        policy: { updatedBy: string; dailyCap: number; perOrderCap: number; leverageCap: number };
        diff: { dailyCap: { before: number; after: number } };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.policy).toMatchObject({
      updatedBy: `agent:${agentId}`,
      dailyCap: 800,
      perOrderCap: 250,
      leverageCap: 8,
    });
    expect(body.data.diff.dailyCap).toEqual({ before: 1000, after: 800 });

    const [row] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, agentId));
    expect(row?.updatedBy).toBe(`agent:${agentId}`);
  });

  it("rejects a tenant API-key PUT before policy mutation", async () => {
    const res = await app.request(`/v1/agents/${agentId}/policy`, {
      method: "PUT",
      headers: {
        "X-Steward-Tenant": tenantId,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dailyCap: 999, reason: "tenant api-key write attempt" }),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Agent policy updates require agent JWT authentication");
  });

  it("GET returns an existing policy row", async () => {
    const res = await app.request(`/v1/agents/${agentId}/policy`, {
      headers: {
        "X-Steward-Tenant": tenantId,
        "X-Steward-Key": apiKey,
      },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { agentId: string; dailyCap: number } };
    expect(body.ok).toBe(true);
    expect(body.data.agentId).toBe(agentId);
    expect(body.data.dailyCap).toBe(800);
  });

  it("PUT updates an existing policy with a full diff", async () => {
    const res = await putPolicy({
      dailyCap: 700,
      perOrderCap: 200,
      leverageCap: 6,
      allowedAssets: ["BTC"],
      reason: "tighten risk",
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      data: {
        policy: {
          dailyCap: number;
          perOrderCap: number;
          leverageCap: number;
          allowedAssets: string[];
        };
        diff: {
          dailyCap: { before: number; after: number };
          allowedAssets: { before: string[]; after: string[] };
        };
      };
    };
    expect(body.data.policy).toMatchObject({ dailyCap: 700, perOrderCap: 200, leverageCap: 6 });
    expect(body.data.policy.allowedAssets).toEqual(["BTC"]);
    expect(body.data.diff.dailyCap).toEqual({ before: 800, after: 700 });
    expect(body.data.diff.allowedAssets).toEqual({ before: ["BTC", "ETH"], after: ["BTC"] });
  });

  it("rejects values exceeding Layer 1 ceilings", async () => {
    const res = await putPolicy({ dailyCap: 50_001, reason: "too high" });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("dailyCap exceeds platform ceiling 50000");
  });

  it("requires allowBuilderPerps before adding builder symbols to allowedAssets", async () => {
    const rejected = await putPolicy({
      allowedAssets: ["xyz:SPCX"],
      reason: "try builder without explicit opt-in",
    });
    expect(rejected.status).toBe(400);
    expect(((await rejected.json()) as { error: string }).error).toContain(
      "allowBuilderPerps=true",
    );

    const accepted = await putPolicy({
      allowedAssets: ["BTC", "xyz:SPCX"],
      allowBuilderPerps: true,
      reason: "explicitly allow Trade.xyz SPCX builder perp",
    });
    expect(accepted.status).toBe(200);
    const body = (await accepted.json()) as {
      data: { policy: { allowedAssets: string[]; allowBuilderPerps: boolean } };
    };
    expect(body.data.policy.allowedAssets).toEqual(["BTC", "xyz:SPCX"]);
    expect(body.data.policy.allowBuilderPerps).toBe(true);
  });

  it("emits an agent.policy.updated audit event with diff", async () => {
    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, "agent.policy.updated"));

    expect(rows.length).toBeGreaterThanOrEqual(2);
    const latest = rows.at(-1);
    expect(latest).toMatchObject({ tenantId, actorId: `agent:${agentId}`, resourceId: agentId });
    expect(latest?.metadata).toMatchObject({
      agentId,
      reason: "explicitly allow Trade.xyz SPCX builder perp",
    });
  });
});

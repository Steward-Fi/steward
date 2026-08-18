import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { agentPolicies, agents, auditEvents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

process.env.DATABASE_URL = "postgres://test:test@localhost:5432/test";
process.env.STEWARD_MASTER_PASSWORD = "test-master-password";
setDefaultTimeout(60000);

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

  // SEC-208 residual: agent tokens can no longer CREATE the initial policy row
  // (creation activates the trade ceilings; it requires a human owner/admin
  // session with recent MFA). Seed the row the way the human path would leave
  // it — platform defaults — so the agent-token PUTs below exercise
  // tighten-only UPDATES.
  await getDb().insert(agentPolicies).values({
    agentId,
    tenantId,
    updatedBy: "user:bootstrap-admin",
    updatedReason: "initial human-created policy",
  });
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

  it("rejects agent-token creation of the initial policy row (SEC-208 residual)", async () => {
    // missingAgentId has NO policy row: an agent token must not self-CREATE
    // one at platform defaults — creation requires the human admin+MFA path.
    const res = await app.request(`/v1/agents/${missingAgentId}/policy`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${agentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dailyCap: 800, reason: "agent self-create attempt" }),
    });

    // The scoped token does not match missingAgentId, so this fails at the
    // scope check; use a correctly-scoped token to isolate the creation gate.
    expect(res.status).toBe(403);

    const missingAgentToken = await signAgentToken(
      { agentId: missingAgentId, tenantId, sub: `agent:${missingAgentId}` } as never,
      "1h",
    );
    const createRes = await app.request(`/v1/agents/${missingAgentId}/policy`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${missingAgentToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dailyCap: 800, reason: "agent self-create attempt" }),
    });
    expect(createRes.status).toBe(403);
    const createBody = (await createRes.json()) as { ok: boolean; error: string };
    expect(createBody.ok).toBe(false);
    expect(createBody.error).toContain(
      "Initial trade policy creation requires an owner/admin session",
    );

    // No row may have been created as a side effect.
    const [row] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, missingAgentId));
    expect(row).toBeUndefined();
  });

  it("PUT tighten-updates the admin-seeded policy row and records updated_by", async () => {
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
    expect(body.error).toContain(
      "Agent policy updates require an agent token or an owner/admin session",
    );
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

  it("SEC-208: concurrent partial tightenings cannot overwrite and re-raise each other", async () => {
    const requests = [
      { dailyCap: 600, reason: "concurrent daily tightening" },
      { leverageCap: 5, reason: "concurrent leverage tightening" },
    ];
    const firstResponses = await Promise.all(requests.map((body) => putPolicy(body)));

    // Depending on scheduling, the second request either observes the first
    // commit and succeeds, or its stale conditional update is rejected. Retry
    // only the stale request against the new row.
    for (let i = 0; i < firstResponses.length; i += 1) {
      const response = firstResponses[i];
      expect([200, 409]).toContain(response.status);
      if (response.status === 409) {
        const retry = await putPolicy(requests[i]);
        expect(retry.status).toBe(200);
      }
    }

    const [row] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, agentId));
    expect(Number(row?.dailyCapUsd)).toBe(600);
    expect(Number(row?.leverageCap)).toBe(5);
  });

  it("SEC-208: one stale attribution-only CAS loses deterministically", async () => {
    const { buildAgentPolicyCompareAndSwapPredicate } = await import("../routes/agents");
    const [expected] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, agentId));
    expect(expected).toBeDefined();
    if (!expected) throw new Error("expected seeded agent policy");

    // Both writes preserve every enforcement field, but claim a different
    // reason. Only one may commit against this exact audit snapshot.
    const results = await Promise.all(
      ["first concurrent reason", "second concurrent reason"].map((reason) =>
        getDb()
          .update(agentPolicies)
          .set({ updatedReason: reason })
          .where(buildAgentPolicyCompareAndSwapPredicate(agentId, tenantId, expected))
          .returning({ agentId: agentPolicies.agentId }),
      ),
    );

    expect(results.map((rows) => rows.length).sort()).toEqual([0, 1]);
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
  });

  it("SEC-208: an agent token cannot widen allowedAssets or enable builder perps", async () => {
    const widen = await putPolicy({
      allowedAssets: ["BTC", "xyz:SPCX"],
      allowBuilderPerps: true,
      reason: "explicitly allow Trade.xyz SPCX builder perp",
    });
    expect(widen.status).toBe(403);
    expect(((await widen.json()) as { error: string }).error).toContain(
      "allowedAssets cannot be widened with an agent token",
    );
  });

  it("SEC-208: an agent token cannot raise its own caps", async () => {
    const raiseDaily = await putPolicy({ dailyCap: 10_000, reason: "raise my own daily cap" });
    expect(raiseDaily.status).toBe(403);
    expect(((await raiseDaily.json()) as { error: string }).error).toContain(
      "dailyCap cannot be raised",
    );

    const raiseLeverage = await putPolicy({ leverageCap: 50, reason: "raise my own leverage" });
    expect(raiseLeverage.status).toBe(403);
    expect(((await raiseLeverage.json()) as { error: string }).error).toContain(
      "leverageCap cannot be raised",
    );

    const enableBuilder = await putPolicy({
      allowBuilderPerps: true,
      reason: "flip builder perps on",
    });
    expect(enableBuilder.status).toBe(403);
    expect(((await enableBuilder.json()) as { error: string }).error).toContain(
      "allowBuilderPerps cannot be enabled with an agent token",
    );
  });

  it("SEC-208: an agent token cannot create an initial policy row at all", async () => {
    const res = await app.request(`/v1/agents/${missingAgentId}/policy`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${await signAgentToken({ agentId: missingAgentId, tenantId, sub: `agent:${missingAgentId}` } as never, "1h")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dailyCap: 100_000, reason: "maximal initial policy" }),
    });
    // 10_000 exceeds the Layer-1 platform ceiling AND the defaults; the
    // platform-ceiling 400 fires before the tighten-only 403.
    expect(res.status).toBe(400);

    const justAboveDefaults = await app.request(`/v1/agents/${missingAgentId}/policy`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${await signAgentToken({ agentId: missingAgentId, tenantId, sub: `agent:${missingAgentId}` } as never, "1h")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ dailyCap: 1_001, reason: "just above default" }),
    });
    // SEC-208 residual: creation-by-agent-token is denied outright — the gate
    // fires before the loosening-vs-defaults comparison, whatever the body.
    expect(justAboveDefaults.status).toBe(403);
    expect(((await justAboveDefaults.json()) as { error: string }).error).toContain(
      "Initial trade policy creation requires an owner/admin session",
    );
  });

  it("emits an agent.policy.updated audit event with diff", async () => {
    const rows = await getDb()
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, "agent.policy.updated"));

    expect(rows.length).toBeGreaterThanOrEqual(2);
    const tightened = rows.find(
      (row) => (row.metadata as { reason?: string } | null)?.reason === "tighten risk",
    );
    expect(tightened).toMatchObject({ tenantId, actorId: `agent:${agentId}`, resourceId: agentId });
    expect(tightened?.metadata).toMatchObject({
      agentId,
      reason: "tighten risk",
    });
  });
});

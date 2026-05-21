import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";

setDefaultTimeout(30000);

/**
 * Agent-token privilege-escalation regression coverage.
 *
 * NOTE on test isolation:
 *   This file deliberately does NOT call `createPGLiteDb` or
 *   `setPGLiteOverride`. The `Integration Tests (Postgres)` CI job provisions
 *   a real Postgres before running `bun test packages/api`, and several
 *   sibling tests rely on that shared db connection persisting across the
 *   run. An earlier version of this file replaced the global pglite handle
 *   in `beforeAll`, which broke every subsequent test in the suite once the
 *   handle was closed in `afterAll`. We instead use the ambient `DATABASE_URL`
 *   like `cross-tenant.test.ts` and rely on a unique TENANT_ID to avoid
 *   colliding with other test fixtures.
 */

const TENANT_ID = "test-agent-route-scope";
const AGENT_A = "test-ars-agent-a";
const AGENT_B = "test-ars-agent-b";
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

let apiKey = "";
let app: typeof import("../app")["app"];

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  ({ app } = await import("../app"));

  const apiKeyPair = generateApiKey();
  apiKey = apiKeyPair.key;
  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Agent Route Scope Tenant",
      apiKeyHash: apiKeyPair.hash,
    })
    .onConflictDoNothing();

  for (const agentId of [AGENT_A, AGENT_B]) {
    const res = await app.request("/agents", {
      method: "POST",
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id: agentId, name: agentId }),
    });
    // The fixture POST is the canary for "tenant-level auth is wired up
    // correctly", so a non-200 here is interesting and we surface the
    // server's error message instead of just an opaque status mismatch.
    if (res.status !== 200) {
      const body = await res.text();
      throw new Error(`Fixture POST /agents for ${agentId} returned ${res.status}: ${body}`);
    }
  }
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;
  // Clean up the test tenant; the db connection itself is shared across the
  // package-wide test run and must NOT be closed here.
  const db = getDb();
  await db
    .delete(tenants)
    .where(eq(tenants.id, TENANT_ID))
    .catch(() => {});
});

describeWithDatabase("agent route scope enforcement", () => {
  it("blocks agent tokens from listing agents and creating new agents", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    const listRes = await app.request("/agents", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(listRes.status).toBe(403);

    const createRes = await app.request("/agents", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id: "test-ars-agent-c", name: "test-ars-agent-c" }),
    });
    expect(createRes.status).toBe(403);
  });

  it("only allows an agent token to read its own agent record", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    const ownRes = await app.request(`/agents/${AGENT_A}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(ownRes.status).toBe(200);

    const otherRes = await app.request(`/agents/${AGENT_B}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(otherRes.status).toBe(403);
    const body = (await otherRes.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("scope does not match");
  });

  it("keeps tenant-level agent listing working", async () => {
    const res = await app.request("/agents", {
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
      },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: Array<{ id: string }> };
    expect(body.ok).toBe(true);
    const ids = body.data.map((agent) => agent.id).sort();
    // Other tests may inject agents into this tenant in parallel, so we
    // assert containment rather than exact equality.
    expect(ids).toContain(AGENT_A);
    expect(ids).toContain(AGENT_B);
  });

  it("blocks agent tokens from batch-creating agents", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    const res = await app.request("/agents/batch", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        agents: [{ id: "test-ars-batch-x", name: "test-ars-batch-x" }],
      }),
    });
    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("tenant-level authentication");
  });

  it("only allows an agent token to read its own policies", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    const ownRes = await app.request(`/agents/${AGENT_A}/policies`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(ownRes.status).toBe(200);

    const otherRes = await app.request(`/agents/${AGENT_B}/policies`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(otherRes.status).toBe(403);
    const otherBody = (await otherRes.json()) as { ok: boolean; error: string };
    expect(otherBody.ok).toBe(false);
    expect(otherBody.error).toContain("scope does not match");
  });

  it("only allows an agent token to write its own policies", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    // Cross-agent policy write was the most severe path of the three
    // (compromised agent token could grant itself auto-approval on a
    // sibling agent and drain its wallet). Verify the gate rejects it.
    const writeOtherRes = await app.request(`/agents/${AGENT_B}/policies`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([{ type: "auto-approve-threshold", config: { thresholdUsd: "10000" } }]),
    });
    expect(writeOtherRes.status).toBe(403);
    const writeOtherBody = (await writeOtherRes.json()) as { ok: boolean; error: string };
    expect(writeOtherBody.ok).toBe(false);
    expect(writeOtherBody.error).toContain("scope does not match");
  });
});

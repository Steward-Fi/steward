import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { agents, auditEvents, getDb, tenants, users, userTenants } from "@stwd/db";
import { and, desc, eq } from "drizzle-orm";

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
const OWNER_USER_ID = "00000000-0000-4000-8000-0000000000a1";
const ADMIN_USER_ID = "00000000-0000-4000-8000-0000000000a2";
const MEMBER_USER_ID = "00000000-0000-4000-8000-0000000000a3";
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

let apiKey = "";
let app: typeof import("../app")["app"];
let createSessionToken: typeof import("../routes/auth").createSessionToken;
let ownerSessionToken = "";
let adminSessionToken = "";
let memberSessionToken = "";

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  ({ app } = await import("../app"));
  ({ createSessionToken } = await import("../routes/auth"));

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

  await getDb()
    .insert(users)
    .values([
      { id: OWNER_USER_ID, email: "test-ars-owner@example.test", emailVerified: true },
      { id: ADMIN_USER_ID, email: "test-ars-admin@example.test", emailVerified: true },
      { id: MEMBER_USER_ID, email: "test-ars-member@example.test", emailVerified: true },
    ])
    .onConflictDoNothing();
  await getDb()
    .insert(userTenants)
    .values([
      { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: ADMIN_USER_ID, tenantId: TENANT_ID, role: "admin" },
      { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
    ])
    .onConflictDoNothing();

  ownerSessionToken = await createSessionToken(
    "0x0000000000000000000000000000000000000001",
    TENANT_ID,
    {
      userId: OWNER_USER_ID,
      email: "test-ars-owner@example.test",
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    },
  );
  adminSessionToken = await createSessionToken(
    "0x0000000000000000000000000000000000000002",
    TENANT_ID,
    {
      userId: ADMIN_USER_ID,
      email: "test-ars-admin@example.test",
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    },
  );
  memberSessionToken = await createSessionToken(
    "0x0000000000000000000000000000000000000003",
    TENANT_ID,
    {
      userId: MEMBER_USER_ID,
      email: "test-ars-member@example.test",
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    },
  );

  // Seed agents directly so this test remains focused on agent-token scope and
  // agent-token minting gates, not the agent creation payload validators.
  for (const agentId of [AGENT_A, AGENT_B]) {
    await getDb()
      .insert(agents)
      .values({
        id: agentId,
        tenantId: TENANT_ID,
        name: agentId,
        walletAddress: `0x${agentId
          .replace(/[^a-f0-9]/gi, "")
          .padEnd(40, "0")
          .slice(0, 40)}`,
      })
      .onConflictDoNothing();
  }
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;
  // Clean up the test tenant; the db connection itself is shared across the
  // package-wide test run and must NOT be closed here.
  const db = getDb();
  await db
    .delete(userTenants)
    .where(eq(userTenants.tenantId, TENANT_ID))
    .catch(() => {});
  await db
    .delete(users)
    .where(eq(users.id, OWNER_USER_ID))
    .catch(() => {});
  await db
    .delete(users)
    .where(eq(users.id, ADMIN_USER_ID))
    .catch(() => {});
  await db
    .delete(users)
    .where(eq(users.id, MEMBER_USER_ID))
    .catch(() => {});
  await db
    .delete(tenants)
    .where(eq(tenants.id, TENANT_ID))
    .catch(() => {});
});

describeWithDatabase("agent route scope enforcement", () => {
  it("rejects agent tokens whose agent no longer exists before tenant route access", async () => {
    const token = await signAgentToken(
      { agentId: "test-ars-missing-agent", tenantId: TENANT_ID },
      "1h",
    );

    const res = await app.request("/condition-sets", {
      headers: { Authorization: `Bearer ${token}` },
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Agent not found");
  });

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

  it("does not upgrade proxy-only tokens into agent metadata read tokens", async () => {
    const token = await signAgentToken(
      { agentId: AGENT_A, tenantId: TENANT_ID, scopes: ["api:proxy"] },
      "1h",
    );

    const ownRecord = await app.request(`/agents/${AGENT_A}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(ownRecord.status).toBe(403);

    const account = await app.request(`/agents/${AGENT_A}/account`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(account.status).toBe(403);

    const policies = await app.request(`/agents/${AGENT_A}/policies`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(policies.status).toBe(403);
  });

  it("keeps tenant-level agent listing working", async () => {
    const res = await app.request("/agents", {
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
      },
    });

    expect(res.status).toBe(200);
    // The listing response is now { data: { agents, limit, offset } } rather
    // than a bare data array.
    const body = (await res.json()) as {
      ok: boolean;
      data: { agents: Array<{ id: string }> };
    };
    expect(body.ok).toBe(true);
    const ids = body.data.agents.map((agent) => agent.id).sort();
    // Other tests may inject agents into this tenant in parallel, so we
    // assert containment rather than exact equality.
    expect(ids).toContain(AGENT_A);
    expect(ids).toContain(AGENT_B);
  });

  it("lets the tenant root API key mint an agent token without session MFA", async () => {
    const res = await app.request(`/agents/${AGENT_A}/token`, {
      method: "POST",
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { token: string; agentId: string; tenantId: string; scope: string; scopes: string[] };
    };
    expect(body.ok).toBe(true);
    expect(body.data.token).toBeDefined();
    expect(body.data.agentId).toBe(AGENT_A);
    expect(body.data.tenantId).toBe(TENANT_ID);
    expect(body.data.scope).toBe("agent");
    expect(body.data.scopes).toEqual(["agent"]);

    const [audit] = await getDb()
      .select({ actorType: auditEvents.actorType, actorId: auditEvents.actorId })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, TENANT_ID),
          eq(auditEvents.resourceId, AGENT_A),
          eq(auditEvents.action, "agent.token.create.authorized"),
        ),
      )
      .orderBy(desc(auditEvents.seq));
    expect(audit).toEqual({ actorType: "api-key", actorId: TENANT_ID });
  });

  it("keeps owner and admin sessions authorized to mint agent tokens", async () => {
    for (const token of [ownerSessionToken, adminSessionToken]) {
      const res = await app.request(`/agents/${AGENT_A}/token`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({}),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as { ok: boolean; data: { agentId: string } };
      expect(body.ok).toBe(true);
      expect(body.data.agentId).toBe(AGENT_A);
    }
  });

  it("rejects agent-token, member session, missing credentials, and invalid API key for agent token minting", async () => {
    const agentToken = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");
    const cases: Array<{
      name: string;
      headers?: Record<string, string>;
      expectedStatus: number;
    }> = [
      {
        name: "agent-token",
        headers: { Authorization: `Bearer ${agentToken}`, "Content-Type": "application/json" },
        expectedStatus: 403,
      },
      {
        name: "member-session",
        headers: {
          Authorization: `Bearer ${memberSessionToken}`,
          "Content-Type": "application/json",
        },
        expectedStatus: 403,
      },
      {
        name: "missing-credentials",
        headers: { "Content-Type": "application/json" },
        expectedStatus: 403,
      },
      {
        name: "invalid-api-key",
        headers: {
          "X-Steward-Tenant": TENANT_ID,
          "X-Steward-Key": "stwd_invalid_key",
          "Content-Type": "application/json",
        },
        expectedStatus: 403,
      },
    ];

    for (const testCase of cases) {
      const res = await app.request(`/agents/${AGENT_A}/token`, {
        method: "POST",
        headers: testCase.headers,
        body: JSON.stringify({}),
      });
      expect(res.status, testCase.name).toBe(testCase.expectedStatus);
    }
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
    expect(body.error).toContain("owner or admin session");
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

  it("blocks agent tokens from writing policies, including their own", async () => {
    const token = await signAgentToken({ agentId: AGENT_A, tenantId: TENANT_ID }, "1h");

    const writeOwnRes = await app.request(`/agents/${AGENT_A}/policies`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([
        { type: "auto-approve-threshold", enabled: true, config: { thresholdUsd: "10000" } },
      ]),
    });
    expect(writeOwnRes.status).toBe(403);
    const writeOwnBody = (await writeOwnRes.json()) as { ok: boolean; error: string };
    expect(writeOwnBody.ok).toBe(false);
    expect(writeOwnBody.error).toContain("owner or admin session");

    const writeOtherRes = await app.request(`/agents/${AGENT_B}/policies`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify([
        { type: "auto-approve-threshold", enabled: true, config: { thresholdUsd: "10000" } },
      ]),
    });
    expect(writeOtherRes.status).toBe(403);
    const writeOtherBody = (await writeOtherRes.json()) as { ok: boolean; error: string };
    expect(writeOtherBody.ok).toBe(false);
    expect(writeOtherBody.error).toContain("owner or admin session");
  });
});

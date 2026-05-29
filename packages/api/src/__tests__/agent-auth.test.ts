import { afterAll, beforeAll, describe, expect, it } from "bun:test";

// Skip all DB-dependent tests when DATABASE_URL is not configured
const SKIP = !process.env.DATABASE_URL;

import { generateApiKey, signAgentToken, verifyToken } from "@stwd/auth";
import { agents, encryptedKeys, getDb, tenants, users, userTenants } from "@stwd/db";
import { and, eq } from "drizzle-orm";

// ─── Test Config ──────────────────────────────────────────────────────────

const TEST_PORT = 3299;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const TEST_TENANT_ID = "test-agent-auth";
const TEST_AGENT_ID = "agent-001";
const OTHER_AGENT_ID = "agent-002";
const TEST_USER_EMAIL = "agent-auth-owner@example.com";

let testApiKey: string;
let testUserId: string;

// ─── Helpers ──────────────────────────────────────────────────────────────

function tenantHeaders(apiKey: string, tenantId = TEST_TENANT_ID) {
  return {
    "X-Steward-Tenant": tenantId,
    "X-Steward-Key": apiKey,
    "Content-Type": "application/json",
  };
}

function agentBearerHeaders(token: string) {
  return {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
}

// Owner session headers. Agent-token minting and agent creation now require a
// session-jwt scoped to the tenant with an owner/admin role and a recent MFA
// step-up — the tenant API key alone is no longer sufficient.
async function adminSessionHeaders(tenantId = TEST_TENANT_ID) {
  const { createSessionToken } = await import("../routes/auth");
  const token = await createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
    userId: testUserId,
    email: TEST_USER_EMAIL,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  return {
    Authorization: `Bearer ${token}`,
    "X-Steward-Tenant": tenantId,
    "Content-Type": "application/json",
  };
}

async function createAgentToken(agentId: string, tenantId: string, expiresIn = "30d") {
  return signAgentToken({ agentId, tenantId }, expiresIn);
}

// ─── Setup ────────────────────────────────────────────────────────────────

beforeAll(async () => {
  if (SKIP) return;
  const db = getDb();
  const apiKeyPair = generateApiKey();
  testApiKey = apiKeyPair.key;

  // Create test tenant
  await db
    .insert(tenants)
    .values({
      id: TEST_TENANT_ID,
      name: "Test Agent Auth Tenant",
      apiKeyHash: apiKeyPair.hash,
    })
    .onConflictDoNothing();

  // Owner user for the tenant — required to mint owner sessions that pass the
  // session-jwt + owner-role checks now guarding agent creation/token minting.
  const [user] = await db
    .insert(users)
    .values({ email: TEST_USER_EMAIL, emailVerified: true })
    .onConflictDoNothing()
    .returning();
  if (user) {
    testUserId = user.id;
  } else {
    const [existing] = await db.select().from(users).where(eq(users.email, TEST_USER_EMAIL));
    testUserId = existing.id;
  }
  await db
    .insert(userTenants)
    .values({ userId: testUserId, tenantId: TEST_TENANT_ID, role: "owner" })
    .onConflictDoNothing();

  // Create test agents directly in the DB with deterministic IDs. The agent
  // creation route now generates server-side IDs and ignores any client-supplied
  // id, so the only way to get fixed test IDs is a direct insert.
  await db
    .insert(agents)
    .values([
      {
        id: TEST_AGENT_ID,
        tenantId: TEST_TENANT_ID,
        name: "Agent One",
        walletAddress: "0x1111111111111111111111111111111111111111",
      },
      {
        id: OTHER_AGENT_ID,
        tenantId: TEST_TENANT_ID,
        name: "Agent Two",
        walletAddress: "0x2222222222222222222222222222222222222222",
      },
    ])
    .onConflictDoNothing();
});

afterAll(async () => {
  if (SKIP) return;
  // Clean up test data
  const db = getDb();
  await db.delete(encryptedKeys).where(eq(encryptedKeys.agentId, TEST_AGENT_ID));
  await db.delete(encryptedKeys).where(eq(encryptedKeys.agentId, OTHER_AGENT_ID));
  await db.delete(agents).where(eq(agents.tenantId, TEST_TENANT_ID));
  await db.delete(userTenants).where(eq(userTenants.tenantId, TEST_TENANT_ID));
  if (testUserId) await db.delete(users).where(eq(users.id, testUserId));
  await db.delete(tenants).where(eq(tenants.id, TEST_TENANT_ID));
});

// ─── Tests ────────────────────────────────────────────────────────────────

describe.skipIf(SKIP)("POST /agents/:agentId/token", () => {
  it("generates a scoped JWT with an owner session", async () => {
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as any;
    expect(json.ok).toBe(true);
    expect(json.data.token).toBeDefined();
    expect(json.data.agentId).toBe(TEST_AGENT_ID);
    expect(json.data.tenantId).toBe(TEST_TENANT_ID);
    expect(json.data.scope).toBe("agent");
    expect(json.data.scopes).toEqual(["agent"]);

    // Verify the JWT payload
    const payload = await verifyToken(json.data.token);
    expect(payload.agentId).toBe(TEST_AGENT_ID);
    expect(payload.tenantId).toBe(TEST_TENANT_ID);
    expect(payload.scope).toBe("agent");
    expect(payload.scopes).toEqual(["agent"]);
  });

  it("returns 404 for non-existent agent", async () => {
    const res = await fetch(`${BASE_URL}/agents/nonexistent-agent/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(404);
  });

  it("rejects request with a tenant API key (no longer sufficient)", async () => {
    // Token minting now requires an owner session-jwt; a bare tenant API key is
    // authenticated but lacks the owner/admin session, so the route rejects it.
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: tenantHeaders(testApiKey),
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(403);
    const json = (await res.json()) as any;
    expect(json.error).toContain("owner or admin session");
  });

  it("rejects request with invalid API key", async () => {
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: tenantHeaders("stw_invalid_key"),
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(403);
  });

  it("rejects request from an agent-scoped token", async () => {
    const agentToken = await createAgentToken(TEST_AGENT_ID, TEST_TENANT_ID);
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: agentBearerHeaders(agentToken),
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(403);
    const json = (await res.json()) as any;
    expect(json.error).toContain("owner or admin session");
  });

  it("accepts custom expiresIn", async () => {
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({ expiresIn: "7d" }),
    });

    expect(res.status).toBe(200);
    const json = (await res.json()) as any;
    expect(json.data.expiresIn).toBe("7d");
  });

  it("rejects excessive custom expiresIn values", async () => {
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({ expiresIn: "100y" }),
    });

    expect(res.status).toBe(400);
    const json = (await res.json()) as any;
    expect(json.error).toContain("up to 30d");
  });
});

describe.skipIf(SKIP)("Agent-scoped JWT access to vault endpoints", () => {
  let agentToken: string;
  let _otherAgentToken: string;

  beforeAll(async () => {
    // Generate tokens via the API (requires an owner session now).
    const res1 = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({}),
    });
    const json1 = (await res1.json()) as any;
    agentToken = json1.data.token;

    const res2 = await fetch(`${BASE_URL}/agents/${OTHER_AGENT_ID}/token`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({}),
    });
    const json2 = (await res2.json()) as any;
    _otherAgentToken = json2.data.token;
  });

  describe("GET /agents/:agentId/balance", () => {
    it("allows agent to access own balance", async () => {
      const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/balance`, {
        headers: agentBearerHeaders(agentToken),
      });
      // Should succeed (200) or fail with a chain error, but NOT 403
      expect(res.status).not.toBe(403);
    });

    it("blocks agent from accessing another agent's balance", async () => {
      const res = await fetch(`${BASE_URL}/agents/${OTHER_AGENT_ID}/balance`, {
        headers: agentBearerHeaders(agentToken),
      });
      expect(res.status).toBe(403);
      const json = (await res.json()) as any;
      expect(json.error).toContain("scope does not match");
    });

    it("allows tenant API key to access any agent balance", async () => {
      const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/balance`, {
        headers: tenantHeaders(testApiKey),
      });
      // Should not be 403
      expect(res.status).not.toBe(403);
    });
  });

  describe("GET /vault/:agentId/pending", () => {
    it("allows agent to access own pending", async () => {
      const res = await fetch(`${BASE_URL}/vault/${TEST_AGENT_ID}/pending`, {
        headers: agentBearerHeaders(agentToken),
      });
      expect(res.status).not.toBe(403);
    });

    it("blocks agent from accessing another agent's pending", async () => {
      const res = await fetch(`${BASE_URL}/vault/${OTHER_AGENT_ID}/pending`, {
        headers: agentBearerHeaders(agentToken),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("GET /vault/:agentId/history", () => {
    it("allows agent to access own history", async () => {
      const res = await fetch(`${BASE_URL}/vault/${TEST_AGENT_ID}/history`, {
        headers: agentBearerHeaders(agentToken),
      });
      expect(res.status).not.toBe(403);
    });

    it("blocks agent from accessing another agent's history", async () => {
      const res = await fetch(`${BASE_URL}/vault/${OTHER_AGENT_ID}/history`, {
        headers: agentBearerHeaders(agentToken),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("POST /vault/:agentId/sign", () => {
    it("blocks agent from signing for another agent", async () => {
      const res = await fetch(`${BASE_URL}/vault/${OTHER_AGENT_ID}/sign`, {
        method: "POST",
        headers: agentBearerHeaders(agentToken),
        body: JSON.stringify({ to: `0x${"a".repeat(40)}`, value: "1000" }),
      });
      expect(res.status).toBe(403);
    });
  });
});

describe.skipIf(SKIP)("POST /vault/:agentId/import", () => {
  const IMPORT_AGENT_ID = "import-test-agent";

  afterAll(async () => {
    const db = getDb();
    await db.delete(encryptedKeys).where(eq(encryptedKeys.agentId, IMPORT_AGENT_ID));
    await db
      .delete(agents)
      .where(and(eq(agents.id, IMPORT_AGENT_ID), eq(agents.tenantId, TEST_TENANT_ID)));
  });

  // Private key import is a break-glass operation gated behind
  // STEWARD_ALLOW_PRIVATE_KEY_IMPORT + STEWARD_ALLOW_VAULT_PRIVATE_KEY_IMPORT.
  // The verify server runs with these unset (the secure default), so every
  // import request is rejected at the disabled gate (403) regardless of caller.
  it("is blocked by default even for an owner session", async () => {
    const res = await fetch(`${BASE_URL}/vault/${IMPORT_AGENT_ID}/import`, {
      method: "POST",
      headers: await adminSessionHeaders(),
      body: JSON.stringify({ privateKey: `0x${"ab".repeat(32)}`, chain: "evm" }),
    });

    expect(res.status).toBe(403);
    const json = (await res.json()) as any;
    expect(json.ok).toBe(false);
  });

  it("rejects import from agent-scoped token", async () => {
    const agentToken = await createAgentToken(IMPORT_AGENT_ID, TEST_TENANT_ID);

    const res = await fetch(`${BASE_URL}/vault/${IMPORT_AGENT_ID}/import`, {
      method: "POST",
      headers: agentBearerHeaders(agentToken),
      body: JSON.stringify({
        privateKey: `0x${"cd".repeat(32)}`,
        chain: "evm",
      }),
    });

    expect(res.status).toBe(403);
  });

  it("rejects request with invalid API key", async () => {
    const res = await fetch(`${BASE_URL}/vault/${IMPORT_AGENT_ID}/import`, {
      method: "POST",
      headers: tenantHeaders("stw_bad_key"),
      body: JSON.stringify({
        privateKey: `0x${"ab".repeat(32)}`,
        chain: "evm",
      }),
    });

    expect(res.status).toBe(403);
  });
});

describe.skipIf(SKIP)("Backward compatibility", () => {
  it("tenant API key still works for all agent endpoints", async () => {
    const res = await fetch(`${BASE_URL}/agents`, {
      headers: tenantHeaders(testApiKey),
    });
    expect(res.status).toBe(200);
    const json = (await res.json()) as any;
    expect(json.ok).toBe(true);
  });

  it("tenant API key can access any agent's balance", async () => {
    const res = await fetch(`${BASE_URL}/agents/${TEST_AGENT_ID}/balance`, {
      headers: tenantHeaders(testApiKey),
    });
    // 200 or non-403 (might fail due to RPC but not auth)
    expect(res.status).not.toBe(403);
  });

  it("tenant API key can access any agent's history", async () => {
    const res = await fetch(`${BASE_URL}/vault/${TEST_AGENT_ID}/history`, {
      headers: tenantHeaders(testApiKey),
    });
    expect(res.status).toBe(200);
  });
});

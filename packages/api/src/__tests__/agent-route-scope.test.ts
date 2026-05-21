import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

setDefaultTimeout(30000);

const TENANT_ID = "agent-route-scope";
const AGENT_A = "agent-a";
const AGENT_B = "agent-b";
let apiKey = "";
let app: typeof import("../app")["app"];

beforeAll(async () => {
  process.env.DATABASE_URL = "pglite://embedded";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "agent-route-scope-master-password";
  process.env.STEWARD_JWT_SECRET = "agent-route-scope-jwt-secret-with-enough-bytes";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ app } = await import("../app"));

  const apiKeyPair = generateApiKey();
  apiKey = apiKeyPair.key;
  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Agent Route Scope Tenant",
    apiKeyHash: apiKeyPair.hash,
  });

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
    expect(res.status).toBe(200);
  }
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

describe("agent route scope enforcement", () => {
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
      body: JSON.stringify({ id: "agent-c", name: "agent-c" }),
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
    expect(body.data.map((agent) => agent.id).sort()).toEqual([AGENT_A, AGENT_B]);
  });
});

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { agentSigners, agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const TENANT_ID = `agent-quorums-tenant-${Date.now()}`;
const AGENT_ID = `agent-quorums-agent-${Date.now()}`;

async function makeApp(authMode: "admin" | "admin-no-mfa" | "api-key" = "admin") {
  const { agentRoutes } = await import("../routes/agents");
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", TENANT_ID);
    if (authMode === "admin" || authMode === "admin-no-mfa") {
      c.set("authType", "session-jwt");
      c.set("tenantRole", "owner");
      c.set("userId", "quorum-admin");
      if (authMode === "admin") c.set("sessionMfaVerifiedAt", Date.now());
    } else {
      c.set("authType", "api-key");
    }
    await next();
  });
  app.route("/agents", agentRoutes);
  return app;
}

describe("agent key quorum API", () => {
  let app: Awaited<ReturnType<typeof makeApp>>;
  let signerA = "";
  let signerB = "";
  let pausedSigner = "";
  let quorumId = "";

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "agent-quorums-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Agent Quorums Tenant",
      apiKeyHash: "hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Agent Quorums Agent",
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    const rows = await getDb()
      .insert(agentSigners)
      .values([
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xaaa",
          address: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "active",
          createdBy: "seed",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xbbb",
          address: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "active",
          createdBy: "seed",
        },
        {
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          signerType: "delegated",
          subjectType: "wallet",
          subjectId: "0xccc",
          address: "0xcccccccccccccccccccccccccccccccccccccccc",
          chainFamily: "evm",
          permissions: ["sign_transaction"],
          status: "paused",
          createdBy: "seed",
        },
      ])
      .returning({ id: agentSigners.id });
    signerA = rows[0].id;
    signerB = rows[1].id;
    pausedSigner = rows[2].id;
    app = await makeApp();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("creates, lists, updates, and revokes key quorums", async () => {
    const createResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Treasury quorum",
        threshold: 2,
        memberSignerIds: [signerA, signerB],
        permissions: ["sign_transaction"],
        metadata: { scope: "treasury" },
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      ok: boolean;
      data: {
        id: string;
        name: string;
        threshold: number;
        memberSignerIds: string[];
        permissions: string[];
        status: string;
        metadata: Record<string, unknown>;
      };
    };
    expect(created.ok).toBe(true);
    expect(created.data.name).toBe("Treasury quorum");
    expect(created.data.threshold).toBe(2);
    expect(created.data.memberSignerIds).toEqual([signerA, signerB]);
    expect(created.data.permissions).toEqual(["sign_transaction"]);
    expect(created.data.status).toBe("active");
    expect(created.data.metadata).toEqual({ scope: "treasury" });
    quorumId = created.data.id;

    const listResponse = await app.request(`/agents/${AGENT_ID}/key-quorums?status=active`);
    expect(listResponse.status).toBe(200);
    const listed = (await listResponse.json()) as {
      ok: boolean;
      data: { quorums: Array<{ id: string; status: string }> };
    };
    expect(listed.ok).toBe(true);
    expect(listed.data.quorums).toHaveLength(1);
    expect(listed.data.quorums[0].id).toBe(quorumId);

    const updateResponse = await app.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ threshold: 1, status: "paused" }),
    });
    expect(updateResponse.status).toBe(200);
    const updated = (await updateResponse.json()) as {
      ok: boolean;
      data: { threshold: number; status: string };
    };
    expect(updated.data.threshold).toBe(1);
    expect(updated.data.status).toBe("paused");

    const revokeResponse = await app.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "DELETE",
    });
    expect(revokeResponse.status).toBe(200);
    const revoked = (await revokeResponse.json()) as { data: { status: string } };
    expect(revoked.data.status).toBe("revoked");
  });

  it("rejects invalid thresholds and inactive members", async () => {
    const thresholdResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Bad quorum",
        threshold: 3,
        memberSignerIds: [signerA, signerB],
      }),
    });
    const thresholdBody = (await thresholdResponse.json()) as { ok: boolean; error?: string };
    expect(thresholdResponse.status).toBe(400);
    expect(thresholdBody.ok).toBe(false);
    expect(thresholdBody.error).toContain("threshold");

    const inactiveResponse = await app.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "Inactive signer quorum",
        threshold: 1,
        memberSignerIds: [pausedSigner],
      }),
    });
    const inactiveBody = (await inactiveResponse.json()) as { ok: boolean; error?: string };
    expect(inactiveResponse.status).toBe(400);
    expect(inactiveBody.ok).toBe(false);
    expect(inactiveBody.error).toContain("inactive signer");
  });

  it("does not expose key quorums to non-admin tenant credentials", async () => {
    const apiKeyApp = await makeApp("api-key");
    const response = await apiKeyApp.request(`/agents/${AGENT_ID}/key-quorums?status=active`);
    const body = (await response.json()) as { ok: boolean; error?: string };

    expect(response.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("owner or admin");
  });

  it("requires recent MFA for key quorum creation and privilege changes", async () => {
    const noMfaApp = await makeApp("admin-no-mfa");
    const createResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: "No MFA quorum",
        threshold: 1,
        memberSignerIds: [signerA],
        permissions: ["sign_transaction"],
      }),
    });
    expect(createResponse.status).toBe(403);
    await expect(createResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });

    const updateResponse = await noMfaApp.request(`/agents/${AGENT_ID}/key-quorums/${quorumId}`, {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ permissions: ["sign_transaction", "sign_message"] }),
    });
    expect(updateResponse.status).toBe(403);
    await expect(updateResponse.json()).resolves.toMatchObject({
      ok: false,
      error: expect.stringContaining("recent MFA"),
    });
  });
});

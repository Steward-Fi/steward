import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  agentRegistrations,
  agents,
  closeDb,
  getDb,
  registryIndex,
  reputationCache,
  tenants,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { Hono } from "hono";

describe("public discovery routes", () => {
  let discoveryRoutes: typeof import("../routes/erc8004").discoveryRoutes;
  let erc8004Routes: typeof import("../routes/erc8004").erc8004Routes;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "discovery-routes-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    ({ discoveryRoutes, erc8004Routes } = await import("../routes/erc8004"));
  });

  afterAll(async () => {
    await closeDb().catch(() => {});
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
  });

  it("rejects malformed chainId instead of hitting the database error path", async () => {
    const response = await discoveryRoutes.request("/agents?chainId=not-a-number");

    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: "chainId must be a positive integer",
    });
  });

  it("does not expose registry RPC URLs on the public registry list", async () => {
    await getDb().insert(registryIndex).values({
      chainId: 999001,
      name: "Internal Registry",
      rpcUrl: "https://internal-rpc.example.invalid/secret",
      registryAddress: "0x0000000000000000000000000000000000008004",
      isActive: true,
    });

    const response = await discoveryRoutes.request("/registries");

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      ok: boolean;
      data: Array<{ chain_id?: number; rpc_url?: string; rpcUrl?: string }>;
    };
    expect(body.ok).toBe(true);
    const registry = body.data.find((row) => row.chain_id === 999001);
    expect(registry?.rpc_url).toBeUndefined();
    expect(registry?.rpcUrl).toBeUndefined();
  });

  it("registers ERC-8004 cards with the agent wallet, not a caller-supplied wallet", async () => {
    const tenantId = `tenant-erc8004-${Date.now()}`;
    const agentId = `agent-erc8004-${Date.now()}`;
    const realWallet = "0x00000000000000000000000000000000000000aa";
    const spoofedWallet = "0x00000000000000000000000000000000000000bb";

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "ERC8004 Agent",
      walletAddress: realWallet,
    });

    const app = new Hono<{
      Variables: {
        tenantId: string;
        authType: string;
        tenantRole: string;
        sessionMfaVerifiedAt: number;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/agents", erc8004Routes);

    const response = await app.request(`/agents/${agentId}/register-onchain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        walletAddress: spoofedWallet,
        apiUrl: "https://agent.example.invalid/api",
        capabilities: ["trade"],
      }),
    });

    expect(response.status).toBe(200);
    const [registration] = await getDb()
      .select()
      .from(agentRegistrations)
      .where(eq(agentRegistrations.agentId, agentId));
    expect(registration?.agentCardJson).toMatchObject({ walletAddress: realWallet });
    expect(registration?.agentCardJson).not.toMatchObject({ walletAddress: spoofedWallet });
  });

  it("rejects unsafe ERC-8004 agent card URLs", async () => {
    const tenantId = `tenant-erc8004-url-${Date.now()}`;
    const agentId = `agent-erc8004-url-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 URL Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "ERC8004 URL Agent",
      walletAddress: "0x00000000000000000000000000000000000000aa",
    });

    const app = new Hono<{
      Variables: {
        tenantId: string;
        authType: string;
        tenantRole: string;
        sessionMfaVerifiedAt: number;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      await next();
    });
    app.route("/agents", erc8004Routes);

    for (const apiUrl of [
      "javascript:alert(1)",
      "http://example.com/agent-card",
      "http://127.0.0.1/admin",
      "https://localhost/admin",
      "https://localhost./admin",
      "https://service.internal./agent-card",
      "https://printer.local./agent-card",
      "https://169.254.169.254/latest/meta-data",
      "https://[::1]/agent-card",
    ]) {
      const response = await app.request(`/agents/${agentId}/register-onchain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiUrl }),
      });

      expect(response.status).toBe(400);
    }
  });

  it("rejects tenant API keys for ERC-8004 registration mutations", async () => {
    const tenantId = `tenant-erc8004-api-key-${Date.now()}`;
    const agentId = `agent-erc8004-api-key-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 API Key Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "ERC8004 API Key Agent",
      walletAddress: "0x00000000000000000000000000000000000000aa",
    });

    const app = new Hono<{
      Variables: {
        tenantId: string;
        authType: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "api-key");
      await next();
    });
    app.route("/agents", erc8004Routes);

    const response = await app.request(`/agents/${agentId}/register-onchain`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ apiUrl: "https://agent.example.invalid/api" }),
    });

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toMatchObject({
      ok: false,
      error: "ERC-8004 registration requires owner or admin session",
    });
  });

  it("does not let an agent-scoped token read another agent's onchain reputation", async () => {
    const tenantId = `tenant-erc8004-scope-${Date.now()}`;
    const scopedAgentId = `agent-erc8004-scoped-${Date.now()}`;
    const targetAgentId = `agent-erc8004-target-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Scope Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb()
      .insert(agents)
      .values([
        {
          id: scopedAgentId,
          tenantId,
          name: "Scoped Agent",
          walletAddress: "0x00000000000000000000000000000000000000aa",
        },
        {
          id: targetAgentId,
          tenantId,
          name: "Target Agent",
          walletAddress: "0x00000000000000000000000000000000000000bb",
        },
      ]);
    await getDb().insert(reputationCache).values({
      agentId: targetAgentId,
      chainId: 8453,
      tokenId: targetAgentId,
      scoreInternal: "5",
      scoreCombined: "5",
      feedbackCount: 99,
    });

    const app = new Hono<{
      Variables: {
        tenantId: string;
        authType: string;
        agentScope: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "agent-token");
      c.set("agentScope", scopedAgentId);
      await next();
    });
    app.route("/agents", erc8004Routes);

    const response = await app.request(`/agents/${targetAgentId}/onchain`);

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      error: "Forbidden: agent scope mismatch",
    });
  });

  it("rejects tenant member sessions reading agent onchain reputation", async () => {
    const tenantId = `tenant-erc8004-member-${Date.now()}`;
    const agentId = `agent-erc8004-member-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Member Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Member Hidden Agent",
      walletAddress: "0x00000000000000000000000000000000000000cc",
    });
    await getDb()
      .insert(agentRegistrations)
      .values({
        tenantId,
        agentId,
        chainId: 8453,
        registryAddress: "0x0000000000000000000000000000000000008004",
        agentCardJson: {
          apiUrl: "https://private-agent.example.invalid",
          walletAddress: "0x00000000000000000000000000000000000000cc",
        },
        status: "confirmed",
      });
    await getDb().insert(reputationCache).values({
      agentId,
      chainId: 8453,
      tokenId: agentId,
      scoreInternal: "5",
      scoreCombined: "5",
      feedbackCount: 99,
    });

    const app = new Hono<{
      Variables: {
        tenantId: string;
        authType: string;
        tenantRole: string;
      };
    }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", tenantId);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "member");
      await next();
    });
    app.route("/agents", erc8004Routes);

    const response = await app.request(`/agents/${agentId}/onchain`);

    expect(response.status).toBe(403);
    await expect(response.json()).resolves.toEqual({
      ok: false,
      error: "Tenant-level agent access required",
    });
  });

  it("does not rank public discovery by tenant-submitted internal feedback", async () => {
    const tenantId = `tenant-erc8004-ranking-${Date.now()}`;
    const feedbackAgentId = `agent-feedback-ranked-${Date.now()}`;
    const onchainAgentId = `agent-onchain-ranked-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Ranking Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb()
      .insert(agents)
      .values([
        {
          id: feedbackAgentId,
          tenantId,
          name: "Feedback Ranked Agent",
          walletAddress: "0x00000000000000000000000000000000000000ca",
        },
        {
          id: onchainAgentId,
          tenantId,
          name: "Onchain Ranked Agent",
          walletAddress: "0x00000000000000000000000000000000000000cb",
        },
      ]);
    await getDb()
      .insert(agentRegistrations)
      .values([
        {
          tenantId,
          agentId: feedbackAgentId,
          chainId: 8453,
          registryAddress: "0x0000000000000000000000000000000000008004",
          status: "confirmed",
        },
        {
          tenantId,
          agentId: onchainAgentId,
          chainId: 8453,
          registryAddress: "0x0000000000000000000000000000000000008004",
          status: "confirmed",
        },
      ]);
    await getDb()
      .insert(reputationCache)
      .values([
        {
          agentId: feedbackAgentId,
          chainId: 8453,
          tokenId: feedbackAgentId,
          scoreOnchain: "0",
          scoreInternal: "5",
          scoreCombined: "5",
          feedbackCount: 500,
        },
        {
          agentId: onchainAgentId,
          chainId: 8453,
          tokenId: onchainAgentId,
          scoreOnchain: "4",
          scoreInternal: "0",
          scoreCombined: "4",
          feedbackCount: 0,
        },
      ]);

    const response = await discoveryRoutes.request("/agents?chainId=8453&limit=20");

    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: Array<{ token_id: string }> };
    const rankedIds = body.data.map((row) => row.token_id);
    expect(rankedIds.indexOf(onchainAgentId)).toBeLessThan(rankedIds.indexOf(feedbackAgentId));
  });

  it("does not expose tenant-submitted feedback counts in public discovery", async () => {
    const tenantId = `tenant-erc8004-feedback-count-${Date.now()}`;
    const agentId = `agent-feedback-count-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Feedback Count Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Feedback Count Agent",
      walletAddress: "0x00000000000000000000000000000000000000cc",
    });
    await getDb().insert(agentRegistrations).values({
      tenantId,
      agentId,
      chainId: 8453,
      registryAddress: "0x0000000000000000000000000000000000008004",
      status: "confirmed",
    });
    await getDb().insert(reputationCache).values({
      agentId,
      chainId: 8453,
      tokenId: agentId,
      scoreInternal: "5",
      scoreCombined: "5",
      feedbackCount: 999,
    });

    const response = await discoveryRoutes.request("/agents?chainId=8453");

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: Array<{ token_id: string; feedback_count: number }>;
    };
    const row = body.data.find((entry) => entry.token_id === agentId);
    expect(row?.feedback_count).toBe(0);
  });

  it("does not expose raw tenant agent-card metadata in public discovery", async () => {
    const tenantId = `tenant-erc8004-card-redaction-${Date.now()}`;
    const agentId = `agent-card-redaction-${Date.now()}`;

    await getDb().insert(tenants).values({
      id: tenantId,
      name: "ERC8004 Card Redaction Tenant",
      apiKeyHash: `${tenantId}-hash`,
    });
    await getDb().insert(agents).values({
      id: agentId,
      tenantId,
      name: "Card Redaction Agent",
      walletAddress: "0x00000000000000000000000000000000000000dd",
    });
    await getDb()
      .insert(agentRegistrations)
      .values({
        tenantId,
        agentId,
        chainId: 8453,
        registryAddress: "0x0000000000000000000000000000000000008004",
        tokenId: "card-redaction-token",
        status: "confirmed",
        agentCardJson: {
          walletAddress: "0x00000000000000000000000000000000000000dd",
          apiUrl: "https://internal-agent.example.invalid/private",
          capabilities: ["private-capability"],
          services: ["private-service"],
        },
      });

    const response = await discoveryRoutes.request("/agents?chainId=8453");

    expect(response.status).toBe(200);
    const body = (await response.json()) as {
      data: Array<Record<string, unknown>>;
    };
    const row = body.data.find((entry) => entry.token_id === "card-redaction-token");
    expect(row).toBeDefined();
    expect(row?.agent_id).toBeUndefined();
    expect(row?.created_at).toBeUndefined();
    expect(row?.updated_at).toBeUndefined();
    expect(row?.agent_card_json).toBeUndefined();
    expect(row?.agentCardJson).toBeUndefined();
    expect(row?.agent_card).toBeUndefined();
  });
});

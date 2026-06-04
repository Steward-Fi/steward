import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const TENANT_ID = "test-agent-token-expiry";
const TENANT_NO_KEY_ID = "test-agent-token-expiry-no-key";
const AGENT_ID = "test-token-watch-agent";
const KID = "test-agent-token-kid";

const auditEvents: Array<{ action: string; metadata?: Record<string, unknown>; actorId?: string }> =
  [];

mock.module("../services/audit", () => ({
  trackAuditEvent: (event: {
    action: string;
    metadata?: Record<string, unknown>;
    actorId?: string;
  }) => {
    auditEvents.push(event);
  },
  writeAuditEvent: async (event: {
    action: string;
    metadata?: Record<string, unknown>;
    actorId?: string;
  }) => {
    auditEvents.push(event);
  },
}));

let privateKey: CryptoKey;
let publicJwk: JsonWebKey;
let apiKey = "";
let requireAgentJwt: typeof import("../middleware/agent-jwt")["requireAgentJwt"];
let clearAgentJwksCacheForTests: typeof import("../middleware/agent-jwt")["clearAgentJwksCacheForTests"];
let clearAgentTokenStatusForTests: typeof import("../services/agent-token-status")["clearAgentTokenStatusForTests"];
let tradeRoutes: typeof import("../routes/trade")["tradeRoutes"];
let tenantAuth: typeof import("../services/context")["tenantAuth"];

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const keys = await generateKeyPair("RS256", { extractable: true });
  privateKey = keys.privateKey;
  publicJwk = await exportJWK(keys.publicKey);
  publicJwk.kid = KID;
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";

  globalThis.fetch = mock(async () =>
    Response.json({ keys: [publicJwk] }),
  ) as unknown as typeof fetch;

  ({ requireAgentJwt, clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt"));
  ({ clearAgentTokenStatusForTests } = await import("../services/agent-token-status"));
  ({ tradeRoutes } = await import("../routes/trade"));
  const contextModule = await import("../services/context");
  ({ tenantAuth } = contextModule);

  const apiKeyPair = generateApiKey();
  apiKey = apiKeyPair.key;
  await getDb()
    .insert(tenants)
    .values([
      {
        id: TENANT_ID,
        name: "Agent Token Expiry Tenant",
        apiKeyHash: apiKeyPair.hash,
      },
      {
        id: TENANT_NO_KEY_ID,
        name: "Agent Token Expiry No Key Tenant",
        apiKeyHash: "",
      },
    ])
    .onConflictDoNothing();

  // PR #79 hardening: requireAgentJwt rejects tokens for agents that are not
  // registered for the tenant, so provision the agent (and its signing key).
  await contextModule.vault.createAgent(TENANT_ID, AGENT_ID, "Token Watch Agent");
});

afterAll(async () => {
  await closeDb();
});

beforeEach(() => {
  auditEvents.length = 0;
  clearAgentJwksCacheForTests?.();
  clearAgentTokenStatusForTests?.();
});

async function signTradeToken(expiresAt: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  // PR #79 hardening: requireAgentJwt now enforces the trade:order scope and a
  // tenant_id claim that matches the X-Steward-Tenant header.
  return new SignJWT({
    agent_id: AGENT_ID,
    tenant_id: TENANT_ID,
    scopes: ["trade:order"],
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setSubject(`agent:${AGENT_ID}`)
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setIssuedAt(now - 10)
    .setNotBefore(now - 10)
    .setExpirationTime(expiresAt)
    .sign(privateKey);
}

function buildAgentJwtApp() {
  const app = new Hono();
  app.use("/v1/trade/hyperliquid/order", (c, next) => requireAgentJwt(c as never, next));
  app.post("/v1/trade/hyperliquid/order", (c) => c.json({ ok: true }));
  return app;
}

function buildTokenStatusApp() {
  const app = new Hono();
  app.use("/v1/trade/*", (c, next) => tenantAuth(c as never, next));
  app.route("/v1/trade", tradeRoutes);
  return app;
}

describe("agent trade token expiry monitoring", () => {
  it("emits an expiring event for a token inside the warning threshold", async () => {
    const exp = Math.floor(Date.now() / 1000) + 120;
    const token = await signTradeToken(exp);
    const app = buildAgentJwtApp();

    const res = await app.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Steward-Tenant": TENANT_ID,
      },
    });

    expect(res.status).toBe(200);
    const event = auditEvents.find((entry) => entry.action === "agent.token.expiring");
    expect(event?.actorId).toBe(AGENT_ID);
    expect(event?.metadata?.agentId).toBe(AGENT_ID);
    expect(event?.metadata?.exp).toBe(exp);
    expect(event?.metadata?.expiresInSeconds).toBeGreaterThan(0);
    expect(event?.metadata?.expiresInSeconds).toBeLessThanOrEqual(300);
  });

  it("keeps rejecting expired tokens and emits an expired event", async () => {
    const exp = Math.floor(Date.now() / 1000) - 60;
    const token = await signTradeToken(exp);
    const app = buildAgentJwtApp();

    const res = await app.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Steward-Tenant": TENANT_ID,
      },
    });

    expect(res.status).toBe(401);
    const event = auditEvents.find((entry) => entry.action === "agent.token.expired");
    expect(event?.actorId).toBe(AGENT_ID);
    expect(event?.metadata?.agentId).toBe(AGENT_ID);
    expect(event?.metadata?.exp).toBe(exp);
    expect(event?.metadata?.expiresInSeconds).toBeLessThanOrEqual(0);
  });

  it("requires tenant auth for token-status and reports observed or unknown state", async () => {
    const app = buildTokenStatusApp();

    const unauthenticated = await app.request(
      `/v1/trade/token-status?agentId=${encodeURIComponent(AGENT_ID)}`,
      { headers: { "X-Steward-Tenant": TENANT_NO_KEY_ID } },
    );
    // PR #79 hardening: tenantAuth rejects a tenant with no/invalid API key with
    // 403 Forbidden (previously 401).
    expect(unauthenticated.status).toBe(403);

    const unknown = await app.request("/v1/trade/token-status?agentId=missing-agent", {
      headers: {
        "X-Steward-Tenant": TENANT_ID,
        "X-Steward-Key": apiKey,
      },
    });
    expect(unknown.status).toBe(200);
    const unknownBody = (await unknown.json()) as { data: { status: string; exp: number | null } };
    expect(unknownBody.data.status).toBe("unknown");
    expect(unknownBody.data.exp).toBeNull();

    const exp = Math.floor(Date.now() / 1000) + 600;
    const token = await signTradeToken(exp);
    const agentJwtApp = buildAgentJwtApp();
    const observedWrite = await agentJwtApp.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Steward-Tenant": TENANT_ID,
      },
    });
    expect(observedWrite.status).toBe(200);

    const observed = await app.request(
      `/v1/trade/token-status?agentId=${encodeURIComponent(AGENT_ID)}`,
      {
        headers: {
          "X-Steward-Tenant": TENANT_ID,
          "X-Steward-Key": apiKey,
        },
      },
    );
    expect(observed.status).toBe(200);
    const observedBody = (await observed.json()) as {
      data: { status: string; agentId: string; exp: number; expiresInSeconds: number };
    };
    expect(observedBody.data.status).toBe("observed");
    expect(observedBody.data.agentId).toBe(AGENT_ID);
    expect(observedBody.data.exp).toBe(exp);
    expect(observedBody.data.expiresInSeconds).toBeGreaterThan(0);
  });
});

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";
import { generateApiKey, signAgentToken } from "@stwd/auth";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

setDefaultTimeout(30_000);

const TENANT_ID = "test-agent-token-expiry";
const TENANT_NO_KEY_ID = "test-agent-token-expiry-no-key";
const AGENT_ID = "test-token-watch-agent";
const OTHER_TENANT_ID = "test-agent-token-expiry-other";
const FOREIGN_AGENT_ID = "test-token-watch-foreign";
const KID = "test-agent-token-kid";
const TEST_JWKS_URL = "https://jwks.example.test/.well-known/jwks.json";
const originalJwksUrl = process.env.ELIZA_CLOUD_JWKS_URL;
const originalFetch = globalThis.fetch;

const auditEvents: Array<{ action: string; metadata?: Record<string, unknown>; actorId?: string }> =
  [];

mock.module("../../../api/src/services/audit", () => ({
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
let requireAgentJwt: typeof import("../../../api/src/middleware/agent-jwt")["requireAgentJwt"];
let clearAgentJwksCacheForTests: typeof import("../../../api/src/middleware/agent-jwt")["clearAgentJwksCacheForTests"];
let clearAgentTokenStatusForTests: typeof import("../../../api/src/services/agent-token-status")["clearAgentTokenStatusForTests"];
let tradeRoutes: Hono;
let tenantAuth: typeof import("../../../api/src/services/context")["tenantAuth"];

beforeAll(async () => {
  process.env.ELIZA_CLOUD_JWKS_URL = TEST_JWKS_URL;
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.DATABASE_URL ??= "postgres://test:test@localhost:5432/test";
  process.env.STEWARD_MASTER_PASSWORD ??= "test-master-password";
  // Platform agent-token signing (SEC-091 test): tenantAuth verifies Bearer
  // tokens with the canonical JWT secret, so configure one explicitly.
  process.env.STEWARD_JWT_SECRET ??= "test-jwt-secret-32-chars-minimum!!!!";

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

  globalThis.fetch = mock(async (input) => {
    if (String(input) !== TEST_JWKS_URL) throw new Error(`Unexpected JWKS URL: ${String(input)}`);
    return Response.json({ keys: [publicJwk] });
  }) as unknown as typeof fetch;

  ({ requireAgentJwt, clearAgentJwksCacheForTests } = await import(
    "../../../api/src/middleware/agent-jwt"
  ));
  ({ clearAgentTokenStatusForTests } = await import(
    "../../../api/src/services/agent-token-status"
  ));
  const { createTradeRoutes } = await import("../routes/trade");
  const { testCtx } = await import("./_ctx");
  tradeRoutes = createTradeRoutes(testCtx());
  const contextModule = await import("../../../api/src/services/context");
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
      {
        id: OTHER_TENANT_ID,
        name: "Agent Token Expiry Other Tenant",
        // api_key_hash has a unique index; a second "" row would be silently
        // dropped by onConflictDoNothing and break the agents FK below.
        apiKeyHash: "not-a-real-key-hash-other-tenant",
      },
    ])
    .onConflictDoNothing();

  // PR #79 hardening: requireAgentJwt rejects tokens for agents that are not
  // registered for the tenant, so provision the agent (and its signing key).
  await contextModule.vault.createAgent(TENANT_ID, AGENT_ID, "Token Watch Agent");
  // SEC-091: a second tenant with its own agent, used to prove the token-status
  // route no longer leaks cross-tenant agent/token state.
  await contextModule.vault.createAgent(OTHER_TENANT_ID, FOREIGN_AGENT_ID, "Foreign Token Watch");
});

afterAll(async () => {
  globalThis.fetch = originalFetch;
  if (originalJwksUrl === undefined) {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
  } else {
    process.env.ELIZA_CLOUD_JWKS_URL = originalJwksUrl;
  }
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

async function signForeignTradeToken(expiresAt: number): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    agent_id: FOREIGN_AGENT_ID,
    tenant_id: OTHER_TENANT_ID,
    scopes: ["trade:order"],
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setSubject(`agent:${FOREIGN_AGENT_ID}`)
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

  it("SEC-091: reports a foreign tenant's agent as unknown even when its token was observed", async () => {
    // Observe the foreign agent's token through the order endpoint (records
    // global agent-token status), then query it with THIS tenant's api key.
    const exp = Math.floor(Date.now() / 1000) + 600;
    const foreignToken = await signForeignTradeToken(exp);
    const agentJwtApp = buildAgentJwtApp();
    const observedWrite = await agentJwtApp.request("/v1/trade/hyperliquid/order", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${foreignToken}`,
        "X-Steward-Tenant": OTHER_TENANT_ID,
      },
    });
    expect(observedWrite.status).toBe(200);

    const app = buildTokenStatusApp();
    const crossTenant = await app.request(
      `/v1/trade/token-status?agentId=${encodeURIComponent(FOREIGN_AGENT_ID)}`,
      {
        headers: {
          "X-Steward-Tenant": TENANT_ID,
          "X-Steward-Key": apiKey,
        },
      },
    );
    expect(crossTenant.status).toBe(200);
    const crossTenantBody = (await crossTenant.json()) as {
      data: { status: string; exp: number | null };
    };
    // A foreign tenant's agent is indistinguishable from a nonexistent one.
    expect(crossTenantBody.data.status).toBe("unknown");
    expect(crossTenantBody.data.exp).toBeNull();
  });

  it("SEC-091: forbids an agent-scoped token from querying another agent's token status", async () => {
    const token = await signAgentToken({ agentId: AGENT_ID, tenantId: TENANT_ID });
    const app = buildTokenStatusApp();

    const other = await app.request("/v1/trade/token-status?agentId=some-other-agent", {
      headers: {
        Authorization: `Bearer ${token}`,
        "X-Steward-Tenant": TENANT_ID,
      },
    });
    expect(other.status).toBe(403);

    const self = await app.request(
      `/v1/trade/token-status?agentId=${encodeURIComponent(AGENT_ID)}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "X-Steward-Tenant": TENANT_ID,
        },
      },
    );
    expect(self.status).toBe(200);
    const selfBody = (await self.json()) as { data: { status: string } };
    // Status store is cleared in beforeEach; self-query returns the unknown shape.
    expect(selfBody.data.status).toBe("unknown");
  });
});

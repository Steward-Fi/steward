import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { createServer, type Server } from "node:http";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

const TENANT = `agent-jwt-tenant-${Date.now()}`;
const OTHER_TENANT = `agent-jwt-other-${Date.now()}`;
const AGENT = `agent-jwt-agent-${Date.now()}`;
const KID = "agent-jwt-hardening-key";

let app: Hono<{ Variables: AppVariables }>;
let jwksServer: Server | undefined;
let jwksUrl: string;
let jwksBody: string;
let privateKey: KeyLike;

async function signToken(
  claims: Record<string, unknown> = {},
  scopes: string[] = ["trade:order"],
): Promise<string> {
  return new SignJWT({ agent_id: AGENT, scopes, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${AGENT}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}

async function probe(token: string, tenantId = TENANT): Promise<Response> {
  return app.request("/probe", {
    headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": tenantId },
  });
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY ||= "1".repeat(64);
  process.env.STEWARD_MASTER_PASSWORD ||= "agent-jwt-hardening-test-password";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());

  await getDb()
    .insert(tenants)
    .values([
      { id: TENANT, name: "Agent JWT Tenant", apiKeyHash: `hash-${TENANT}` },
      { id: OTHER_TENANT, name: "Other Agent JWT Tenant", apiKeyHash: `hash-${OTHER_TENANT}` },
    ]);
  await getDb().insert(agents).values({
    id: AGENT,
    tenantId: TENANT,
    platformId: "platform-a",
    name: AGENT,
    walletAddress: "0x00000000000000000000000000000000000000a1",
  });

  const keyPair = await generateKeyPair("RS256");
  privateKey = keyPair.privateKey;
  const jwk = await exportJWK(keyPair.publicKey);
  jwksBody = JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }] });
  jwksServer = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(jwksBody);
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));
  const address = jwksServer.address();
  const port = typeof address === "object" && address ? address.port : 0;
  jwksUrl = `http://127.0.0.1:${port}/jwks`;
  process.env.ELIZA_CLOUD_JWKS_URL = jwksUrl;

  const { clearAgentJwksCacheForTests, requireAgentJwt } = await import("../middleware/agent-jwt");
  clearAgentJwksCacheForTests();
  app = new Hono<{ Variables: AppVariables }>();
  app.use("*", requireAgentJwt);
  app.get("/probe", (context) =>
    context.json({
      agentId: context.get("agentScope"),
      scopes: context.get("agentScopes"),
    }),
  );
});

afterEach(async () => {
  process.env.ELIZA_CLOUD_JWKS_URL = jwksUrl;
  delete process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS;
  process.env.NODE_ENV = "test";
  const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
  clearAgentJwksCacheForTests();
});

afterAll(async () => {
  await closeDb();
  if (jwksServer) {
    await new Promise<void>((resolve) => jwksServer?.close(() => resolve()));
  }
  delete process.env.ELIZA_CLOUD_JWKS_URL;
  delete process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS;
});

describe("external agent JWT authentication", () => {
  test("accepts an omitted tenant claim only for the agent's registered tenant", async () => {
    const accepted = await probe(await signToken());
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({
      agentId: AGENT,
      scopes: ["agent", "trade:order"],
    });

    const wrongTenant = await probe(await signToken(), OTHER_TENANT);
    expect(wrongTenant.status).toBe(403);
    expect((await wrongTenant.json()).error).toContain("not registered for tenant");
  });

  test("rejects tenant and platform claims that conflict with server-side registration", async () => {
    const tenantMismatch = await probe(await signToken({ tenant_id: OTHER_TENANT }));
    expect(tenantMismatch.status).toBe(401);
    expect((await tenantMismatch.json()).reason).toBe("invalid tenant claims");

    const platformMismatch = await probe(await signToken({ platform_id: "platform-b" }));
    expect(platformMismatch.status).toBe(401);
    expect((await platformMismatch.json()).reason).toBe("invalid platform claims");
  });

  test("requires the explicit trade scope", async () => {
    const response = await probe(await signToken({}, ["api:proxy"]));
    expect(response.status).toBe(403);
    expect((await response.json()).error).toBe("Token missing required trade:order scope");
  });

  test("fails closed without a configured JWKS URL", async () => {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
    delete process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS;
    process.env.NODE_ENV = "test";
    const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
    clearAgentJwksCacheForTests();

    const response = await probe(await signToken());
    expect(response.status).toBe(401);
    expect((await response.json()).reason).toBe("jwks-url-required");
  });

  test("allows the development trust anchor only with an explicit opt-in", async () => {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
    process.env.NODE_ENV = "test";
    process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS = "true";
    const originalFetch = globalThis.fetch;
    let requestedUrl = "";
    globalThis.fetch = (async (input) => {
      requestedUrl = String(input);
      return new Response(jwksBody, {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    try {
      const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
      clearAgentJwksCacheForTests();
      expect((await probe(await signToken())).status).toBe(200);
      expect(requestedUrl).toBe("https://milady.shad0w.xyz/.well-known/jwks.json");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("never enables the development trust anchor in production", async () => {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS = "true";
    const originalFetch = globalThis.fetch;
    let fetched = false;
    globalThis.fetch = (async () => {
      fetched = true;
      throw new Error("unexpected fetch");
    }) as typeof fetch;
    try {
      const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
      clearAgentJwksCacheForTests();
      const response = await probe(await signToken());
      expect(response.status).toBe(401);
      expect((await response.json()).reason).toBe("jwks-url-required");
      expect(fetched).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

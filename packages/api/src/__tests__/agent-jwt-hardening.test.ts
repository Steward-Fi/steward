import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import { createServer, type Server } from "node:http";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30_000);

const TENANT = `agent-jwt-tenant-${Date.now()}`;
const OTHER_TENANT = `agent-jwt-other-${Date.now()}`;
const AGENT = `agent-jwt-agent-${Date.now()}`;
const KID_1 = "agent-jwt-hardening-key-1";
const KID_2 = "agent-jwt-hardening-key-2";

let app: Hono<{ Variables: AppVariables }>;
let capabilityApp: Hono<{ Variables: AppVariables }>;
let jwksServer: Server;
let jwksUrl = "";
let jwksBody = "";
let firstJwksBody = "";
let rotatedJwksBody = "";
let privateKey1: KeyLike;
let privateKey2: KeyLike;
let downstreamCalls = 0;
let jwksFetches = 0;
let jwksResponseBarrier: { observed: () => void; release: Promise<void> } | null = null;

type TokenOptions = {
  agentId?: string;
  alg?: "RS256" | "HS256";
  audience?: string;
  expiresAt?: number;
  issuedAt?: number;
  issuer?: string;
  kid?: string;
  notBefore?: number;
  scopes?: string[];
  tenantId?: string | null;
  platformId?: string | null;
  key?: KeyLike | Uint8Array;
};

async function signToken(options: TokenOptions = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const agentId = options.agentId ?? AGENT;
  const alg = options.alg ?? "RS256";
  const claims: Record<string, unknown> = {
    agent_id: agentId,
    scopes: options.scopes ?? ["trade:order"],
  };
  if (options.tenantId !== null) claims.tenant_id = options.tenantId ?? TENANT;
  if (options.platformId !== null) claims.platform_id = options.platformId ?? "platform-a";

  const token = new SignJWT(claims)
    .setProtectedHeader({ alg, kid: options.kid ?? KID_1 })
    .setIssuer(options.issuer ?? "eliza-cloud")
    .setAudience(options.audience ?? "steward")
    .setSubject(`agent:${agentId}`)
    .setIssuedAt(options.issuedAt ?? now)
    .setExpirationTime(options.expiresAt ?? now + 600);
  if (options.notBefore !== undefined) token.setNotBefore(options.notBefore);
  return token.sign(options.key ?? privateKey1);
}

async function probe(token: string, tenantId = TENANT, path = "/trade"): Promise<Response> {
  return app.request(path, {
    headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": tenantId },
  });
}

async function denial(response: Response, status: number, reason: string) {
  expect(response.status).toBe(status);
  const body = (await response.json()) as { code?: string; reason?: string; error?: string };
  if (status === 401) {
    expect(body.code).toBe("invalid-jwt");
    expect(body.reason).toBe(reason);
  } else {
    expect(body.error).toBe(reason);
  }
}

beforeAll(async () => {
  process.env.NODE_ENV = "test";
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

  const keyPair1 = await generateKeyPair("RS256");
  const keyPair2 = await generateKeyPair("RS256");
  privateKey1 = keyPair1.privateKey;
  privateKey2 = keyPair2.privateKey;
  const publicJwk1 = await exportJWK(keyPair1.publicKey);
  const publicJwk2 = await exportJWK(keyPair2.publicKey);
  firstJwksBody = JSON.stringify({
    keys: [{ ...publicJwk1, kid: KID_1, alg: "RS256", use: "sig" }],
  });
  rotatedJwksBody = JSON.stringify({
    keys: [
      { ...publicJwk1, kid: KID_1, alg: "RS256", use: "sig" },
      { ...publicJwk2, kid: KID_2, alg: "RS256", use: "sig" },
    ],
  });
  jwksBody = firstJwksBody;
  jwksServer = createServer(async (_request, response) => {
    jwksFetches += 1;
    const barrier = jwksResponseBarrier;
    if (barrier) {
      barrier.observed();
      await barrier.release;
    }
    response.writeHead(200, { "content-type": "application/json" });
    response.end(jwksBody);
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));
  const address = jwksServer.address();
  const port = typeof address === "object" && address ? address.port : 0;
  jwksUrl = `http://127.0.0.1:${port}/jwks`;
  process.env.ELIZA_CLOUD_JWKS_URL = jwksUrl;

  const { clearAgentJwksCacheForTests, requireAgentJwt, requireCapabilityAgentJwt } = await import(
    "../middleware/agent-jwt"
  );
  clearAgentJwksCacheForTests();
  app = new Hono<{ Variables: AppVariables }>();
  app.use("*", requireAgentJwt);
  app.get("/trade", (context) => {
    downstreamCalls += 1;
    return context.json({ agentId: context.get("agentScope"), scopes: context.get("agentScopes") });
  });
  app.get("/metadata", () => {
    downstreamCalls += 1;
    return new Response("unexpected");
  });
  app.get("/admin", () => {
    downstreamCalls += 1;
    return new Response("unexpected");
  });

  capabilityApp = new Hono<{ Variables: AppVariables }>();
  capabilityApp.use("*", requireCapabilityAgentJwt);
  capabilityApp.get("/capability", () => {
    downstreamCalls += 1;
    return new Response("unexpected");
  });
});

afterEach(async () => {
  process.env.NODE_ENV = "test";
  process.env.ELIZA_CLOUD_JWKS_URL = jwksUrl;
  delete process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS;
  jwksBody = firstJwksBody;
  jwksResponseBarrier = null;
  const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
  clearAgentJwksCacheForTests();
});

afterAll(async () => {
  await closeDb();
  await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  delete process.env.ELIZA_CLOUD_JWKS_URL;
  delete process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS;
});

describe("external agent JWT trust and scope boundaries", () => {
  test("binds signed tenant/platform claims and admits an explicitly scoped trade token", async () => {
    const response = await probe(await signToken());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ agentId: AGENT, scopes: ["agent", "trade:order"] });

    await denial(
      await probe(await signToken({ tenantId: OTHER_TENANT })),
      401,
      "invalid tenant claims",
    );
    await denial(
      await probe(await signToken({ platformId: "platform-b" })),
      401,
      "invalid platform claims",
    );
  });

  test("accepts an omitted tenant claim only through server-side agent registration", async () => {
    expect((await probe(await signToken({ tenantId: null }))).status).toBe(200);
    await denial(
      await probe(await signToken({ tenantId: null }), OTHER_TENANT),
      403,
      "Forbidden: agent is not registered for tenant",
    );
  });

  test("accepts an omitted platform claim only through server-side agent registration", async () => {
    expect((await probe(await signToken({ platformId: null }))).status).toBe(200);
  });

  test("rejects missing trade scope and never upgrades api:proxy on metadata/admin routes", async () => {
    const calls = downstreamCalls;
    for (const path of ["/trade", "/metadata", "/admin"]) {
      await denial(
        await probe(await signToken({ scopes: ["api:proxy"] }), TENANT, path),
        403,
        "Token missing required trade:order scope",
      );
    }
    expect(downstreamCalls).toBe(calls);
  });

  test("rejects cap scopes before tenant/agent resolution, including mixed broad scopes", async () => {
    const calls = downstreamCalls;
    const agentsBefore = await getDb().select().from(agents);
    const tenantsBefore = await getDb().select().from(tenants);
    for (const scopes of [["cap:github:write"], ["trade:order", "api:proxy", "cap:github:write"]]) {
      const response = await app.request("/trade", {
        headers: {
          authorization: `Bearer ${await signToken({ scopes })}`,
          "X-Steward-Tenant": "does-not-exist",
        },
      });
      await denial(response, 401, "unsupported capability scope");
    }
    expect(downstreamCalls).toBe(calls);
    expect(await getDb().select().from(agents)).toEqual(agentsBefore);
    expect(await getDb().select().from(tenants)).toEqual(tenantsBefore);
  });

  test("accepts a non-capability extra scope without weakening the explicit trade gate", async () => {
    expect((await probe(await signToken({ scopes: ["trade:order", "api:proxy"] }))).status).toBe(
      200,
    );
  });

  test("returns stable denials for unknown kid and unsupported algorithm", async () => {
    await denial(await probe(await signToken({ kid: "unknown-kid" })), 401, "unknown kid");
    await denial(
      await probe(await signToken({ alg: "HS256", key: new TextEncoder().encode("x".repeat(32)) })),
      401,
      "unsupported alg",
    );
  });

  test("returns stable denials for issuer, audience, expiry, and future timestamps", async () => {
    const now = Math.floor(Date.now() / 1000);
    await denial(await probe(await signToken({ issuer: "attacker" })), 401, "invalid issuer");
    await denial(await probe(await signToken({ audience: "attacker" })), 401, "invalid audience");
    await denial(await probe(await signToken({ expiresAt: now - 1 })), 401, "token expired");
    await denial(await probe(await signToken({ notBefore: now + 300 })), 401, "token not active");
    await denial(
      await probe(await signToken({ issuedAt: now + 300 })),
      401,
      "token issued in the future",
    );
  });

  test("refreshes cached JWKS once when a rotated kid appears", async () => {
    const fetchesBefore = jwksFetches;
    expect((await probe(await signToken())).status).toBe(200);
    jwksBody = rotatedJwksBody;
    const rotated = await signToken({ kid: KID_2, key: privateKey2 });
    expect((await probe(rotated)).status).toBe(200);
    expect(jwksFetches - fetchesBefore).toBe(2);
  });

  test("shares one forced JWKS refresh across concurrent rotated-token requests", async () => {
    expect((await probe(await signToken())).status).toBe(200);
    jwksBody = rotatedJwksBody;
    let releaseResponse = () => {};
    let observeRequest = () => {};
    const requestObserved = new Promise<void>((resolve) => {
      observeRequest = resolve;
    });
    const release = new Promise<void>((resolve) => {
      releaseResponse = resolve;
    });
    jwksResponseBarrier = { observed: observeRequest, release };
    const fetchesBefore = jwksFetches;
    const rotated = await signToken({ kid: KID_2, key: privateKey2 });
    const requests = Array.from({ length: 8 }, () => probe(rotated));
    await requestObserved;
    releaseResponse();
    const responses = await Promise.all(requests);
    jwksResponseBarrier = null;
    expect(responses.every((response) => response.status === 200)).toBe(true);
    expect(jwksFetches - fetchesBefore).toBe(1);
  });

  test("isolates JWKS miss-refresh throttles between configured trust anchors", async () => {
    expect((await probe(await signToken())).status).toBe(200);
    const rotated = await signToken({ kid: KID_2, key: privateKey2 });
    await denial(await probe(rotated), 401, "unknown kid");

    process.env.ELIZA_CLOUD_JWKS_URL = `${jwksUrl}?anchor=second`;
    expect((await probe(await signToken())).status).toBe(200);
    jwksBody = rotatedJwksBody;
    expect((await probe(rotated)).status).toBe(200);
  });

  test("does not retain keys when the configured JWKS trust anchor changes", async () => {
    expect((await probe(await signToken())).status).toBe(200);
    jwksBody = JSON.stringify({ keys: JSON.parse(rotatedJwksBody).keys.slice(1) });
    process.env.ELIZA_CLOUD_JWKS_URL = `${jwksUrl}?anchor=rotated`;
    await denial(await probe(await signToken()), 401, "unknown kid");
    expect((await probe(await signToken({ kid: KID_2, key: privateKey2 }))).status).toBe(200);
  });

  test("production and unconfigured development both fail closed", async () => {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
    process.env.NODE_ENV = "production";
    await denial(await probe(await signToken()), 401, "jwks-url-required");

    process.env.NODE_ENV = "test";
    await denial(await probe(await signToken()), 401, "jwks-url-required");
  });

  test("the default development anchor requires explicit opt-in", async () => {
    delete process.env.ELIZA_CLOUD_JWKS_URL;
    process.env.STEWARD_ALLOW_DEFAULT_ELIZA_JWKS = "true";
    const originalFetch = globalThis.fetch;
    let requestedUrl = "";
    globalThis.fetch = (async (input) => {
      requestedUrl = String(input);
      return new Response(firstJwksBody, {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    try {
      expect((await probe(await signToken())).status).toBe(200);
      expect(requestedUrl).toBe("https://milady.shad0w.xyz/.well-known/jwks.json");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

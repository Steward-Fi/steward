/**
 * SEC-092 regression: the agent-facing capability surface must not be gated by
 * the TRADING scope. Capability invoke/manifest/issuance routes
 * mounted the legacy `requireAgentJwt`, which hard-requires `trade:order` — so
 * capability-only agents were locked out and every trading agent implicitly
 * carried capability access (scope conflation). The dedicated
 * `requireCapabilityAgentJwt` authenticates the same JWT but leaves
 * authorization to the capability grant + capability-intent policy
 * (default-deny) in the invoke path.
 *
 * Behavioral proof over a real RS256 agent JWT (local JWKS fixture + PGLite):
 *   - a token WITHOUT `trade:order` passes requireCapabilityAgentJwt
 *   - the same token is still rejected by requireAgentJwt (control: the
 *     trading gate itself is untouched)
 *   - an unverifiable token is still a 401 (authentication is unchanged)
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createServer, type Server } from "node:http";
import { agents, closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

setDefaultTimeout(30000);

const TENANT = `cap-gate-tenant-${Date.now()}`;
const AGENT = `cap-gate-agent-${Date.now()}`;
const KID = "cap-gate-kid-1";

let jwksServer: Server;
let privateKey: KeyLike;
let app: Hono<{ Variables: AppVariables }>;

async function signToken(scopes: string[]): Promise<string> {
  return new SignJWT({ agent_id: AGENT, scopes })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${AGENT}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_AUDIT_HMAC_KEY ||= "1".repeat(64);
  process.env.STEWARD_MASTER_PASSWORD ||= "capability-gate-test-master-password";
  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => client.close());
  await getDb().insert(tenants).values({ id: TENANT, name: "Cap Gate Tenant", apiKeyHash: "hash" });
  await getDb()
    .insert(agents)
    .values({ id: AGENT, tenantId: TENANT, name: AGENT, walletAddress: "0x4" });

  const kp = await generateKeyPair("RS256");
  privateKey = kp.privateKey;
  const jwk = await exportJWK(kp.publicKey);
  const jwks = JSON.stringify({ keys: [{ ...jwk, kid: KID, alg: "RS256", use: "sig" }] });
  jwksServer = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(jwks);
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, resolve));
  const address = jwksServer.address();
  const port = typeof address === "object" && address ? address.port : 0;
  process.env.ELIZA_CLOUD_JWKS_URL = `http://127.0.0.1:${port}/jwks`;

  const { clearAgentJwksCacheForTests, requireAgentJwt, requireCapabilityAgentJwt } = await import(
    "../middleware/agent-jwt"
  );
  clearAgentJwksCacheForTests();

  app = new Hono<{ Variables: AppVariables }>();
  app.use("/cap/*", (c, next) => requireCapabilityAgentJwt(c, next));
  app.get("/cap/probe", (c) => c.json({ ok: true, agentId: c.get("agentScope") }));
  app.use("/trade/*", (c, next) => requireAgentJwt(c, next));
  app.get("/trade/probe", (c) => c.json({ ok: true, agentId: c.get("agentScope") }));
});

afterAll(async () => {
  await closeDb();
  await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
  delete process.env.ELIZA_CLOUD_JWKS_URL;
});

async function probe(path: string, token: string): Promise<Response> {
  return app.request(path, {
    headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT },
  });
}

describe("requireCapabilityAgentJwt (SEC-092)", () => {
  test("admits a capability-only agent JWT with no trade:order scope", async () => {
    const res = await probe("/cap/probe", await signToken(["cap:github:app:org"]));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; agentId: string };
    expect(body.ok).toBe(true);
    expect(body.agentId).toBe(AGENT);
  });

  test("admits a scope-less agent JWT (authz is the grant + policy, not the scope)", async () => {
    const res = await probe("/cap/probe", await signToken([]));
    expect(res.status).toBe(200);
  });

  test("control: requireAgentJwt still hard-requires trade:order", async () => {
    const res = await probe("/trade/probe", await signToken(["cap:github:app:org"]));
    expect(res.status).toBe(401);
    const scoped = await probe("/trade/probe", await signToken(["trade:order"]));
    expect(scoped.status).toBe(200);
  });

  test("still rejects an unverifiable token (authentication unchanged)", async () => {
    const res = await probe("/cap/probe", "not-a-jwt");
    expect(res.status).toBe(401);
  });
});

/**
 * provider-actions route HTTP tests (PGLite + real mounted Hono app + signed
 * JWKS fixture).
 *
 * Proves the route-level contract: media-type + duplicate-key + unknown-field
 * denials happen before any decision; provider identity works WITHOUT the
 * `trade:order` scope; a forged actor/tenant field is rejected as an unknown
 * field; and a granted allow flows end-to-end through the mounted route.
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createServer, type Server } from "node:http";
import {
  agents,
  closeDb,
  getDb,
  providerAccounts,
  providerGrants,
  providerOperations,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { type Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

setDefaultTimeout(120_000);

const TENANT = "tenant-main";
const AGENT = "agent-x";
const WORKSPACE_A = "20000000-0000-4000-8000-000000000001";
const ACCOUNT_A = "30000000-0000-4000-8000-000000000001";
const OP_A_READ = "40000000-0000-4000-8000-000000000001";
const GRANTOR = "10000000-0000-4000-8000-000000000001";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);
const KID = "test-kid-1";

let app: Hono<{ Variables: AppVariables }>;
let jwksServer: Server;
let privateKey: KeyLike;

async function signAgentToken(scopes: string[]): Promise<string> {
  return new SignJWT({ agent_id: AGENT, scopes })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${AGENT}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}

async function seed() {
  const db = getDb();
  await db.insert(tenants).values([{ id: TENANT, name: "Main", apiKeyHash: "h" }]);
  await db.insert(users).values([{ id: GRANTOR, email: "g@t.test" }]);
  await db
    .insert(agents)
    .values([{ id: AGENT, tenantId: TENANT, name: "X", walletAddress: "0x1" }]);
  await db.insert(workspaces).values([
    {
      id: WORKSPACE_A,
      tenantId: TENANT,
      key: "client-a",
      name: "A",
      environment: "production",
      createdBy: GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: ACCOUNT_A,
      tenantId: TENANT,
      workspaceId: WORKSPACE_A,
      adapterKey: "github",
      externalRef: "a",
      displayName: "A",
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: OP_A_READ,
      tenantId: TENANT,
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
      operationKey: "github.issue.list",
      riskClass: "read",
      requestProfile: {
        policyRules: [
          {
            id: "11111111-1111-4111-8111-111111111111",
            type: "capability-intent",
            enabled: true,
            config: { capabilities: ["github.issue.list"], effect: "allow" },
          },
        ],
      },
    },
  ]);
  await db.insert(providerGrants).values({
    tenantId: TENANT,
    workspaceId: WORKSPACE_A,
    providerAccountId: ACCOUNT_A,
    agentId: AGENT,
    operationKeys: ["github.issue.list"],
    environment: "production",
    expiresAt: FUTURE,
    grantedByUserId: GRANTOR,
    reason: "test",
  });
}

async function post(token: string, body: string, contentType = "application/json") {
  return app.request("/v2/provider-actions", {
    method: "POST",
    headers: {
      "content-type": contentType,
      authorization: `Bearer ${token}`,
      "X-Steward-Tenant": TENANT,
    },
    body,
  });
}

describe("POST /v2/provider-actions (route)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD ||= "provider-actions-route-master-password";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await seed();

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
    const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
    clearAgentJwksCacheForTests();

    // Use the FULLY composed app (createApp + mountCoreIdempotencyAndRoutes), not
    // the Phase-1 middleware-only app, so all `/v2` routes are mounted.
    const mod = await import("../app");
    app = mod.app as Hono<{ Variables: AppVariables }>;
  });

  afterAll(async () => {
    await closeDb();
    await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.ELIZA_CLOUD_JWKS_URL;
  });

  test("rejects an unsupported media type before any decision", async () => {
    const token = await signAgentToken([]);
    const res = await post(token, "not-json", "text/plain");
    expect(res.status).toBe(415);
    const j = (await res.json()) as { error: string };
    expect(j.error).toBe("CANON_REQUEST_CONTENT_TYPE_UNSUPPORTED");
  });

  test("rejects a duplicate JSON key (JSON.parse would silently accept)", async () => {
    const token = await signAgentToken([]);
    const res = await post(
      token,
      '{"workspaceId":"a","workspaceId":"b","providerAccountId":"x","operationKey":"github.issue.list","arguments":{},"idempotencyKey":"idem-0001"}',
    );
    expect(res.status).toBe(400);
    const j = (await res.json()) as { error: string };
    expect(j.error).toBe("CANON_JSON_DUPLICATE_KEY");
  });

  test("rejects a forged actor/tenant field as an unknown top-level field", async () => {
    const token = await signAgentToken([]);
    const res = await post(
      token,
      JSON.stringify({
        workspaceId: WORKSPACE_A,
        providerAccountId: ACCOUNT_A,
        operationKey: "github.issue.list",
        arguments: { owner: "octo", repo: "hello" },
        idempotencyKey: "idem-forge-1",
        actor: "agent-evil",
      }),
    );
    expect(res.status).toBe(400);
    const j = (await res.json()) as { error: string };
    expect(j.error).toBe("CANON_UNKNOWN_FIELD");
  });

  test("provider identity works WITHOUT the trade:order scope (granted allow flows end-to-end)", async () => {
    const token = await signAgentToken(["some:unrelated:scope"]); // NO trade:order
    const res = await post(
      token,
      JSON.stringify({
        workspaceId: WORKSPACE_A,
        providerAccountId: ACCOUNT_A,
        operationKey: "github.issue.list",
        arguments: { owner: "octo", repo: "hello", state: "open" },
        idempotencyKey: "idem-allow-1",
      }),
    );
    expect(res.status).toBe(200);
    const j = (await res.json()) as { status: string; actionDigest: string };
    expect(j.status).toBe("stub_succeeded");
    expect(j.actionDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("a missing bearer token is rejected before parsing", async () => {
    const res = await app.request("/v2/provider-actions", {
      method: "POST",
      headers: { "content-type": "application/json", "X-Steward-Tenant": TENANT },
      body: "{}",
    });
    expect(res.status).toBe(401);
  });
});

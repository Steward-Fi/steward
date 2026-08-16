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
import { generateApiKey } from "@stwd/auth";
import {
  agents,
  closeDb,
  getDb,
  intents,
  providerAccounts,
  providerGrants,
  providerOperations,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import { type Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

setDefaultTimeout(120_000);

const TENANT = "tenant-main";
const TENANT_OTHER = "tenant-other";
const AGENT = "agent-x";
const AGENT_OTHER = "agent-y";
const AGENT_OTHER_TENANT = "agent-z";
const WORKSPACE_A = "20000000-0000-4000-8000-000000000001";
const ACCOUNT_A = "30000000-0000-4000-8000-000000000001";
const OP_A_READ = "40000000-0000-4000-8000-000000000001";
const GRANTOR = "10000000-0000-4000-8000-000000000001";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);
const KID = "test-kid-1";
const TENANT_KEY = generateApiKey();
const CREDENTIAL_CANARY = "credential-canary-issue-233";

let app: Hono<{ Variables: AppVariables }>;
let jwksServer: Server;
let privateKey: KeyLike;
let statusIntentId = "";

async function signAgentToken(scopes: string[], agentId = AGENT): Promise<string> {
  return new SignJWT({ agent_id: agentId, scopes })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${agentId}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(privateKey);
}

async function seed() {
  const db = getDb();
  await db.insert(tenants).values([
    { id: TENANT, name: "Main", apiKeyHash: TENANT_KEY.hash },
    { id: TENANT_OTHER, name: "Other", apiKeyHash: "other-hash" },
  ]);
  await db.insert(users).values([{ id: GRANTOR, email: "g@t.test" }]);
  await db.insert(agents).values([
    { id: AGENT, tenantId: TENANT, name: "X", walletAddress: "0x1" },
    { id: AGENT_OTHER, tenantId: TENANT, name: "Y", walletAddress: "0x2" },
    {
      id: AGENT_OTHER_TENANT,
      tenantId: TENANT_OTHER,
      name: "Z",
      walletAddress: "0x3",
    },
  ]);
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

async function post(
  token: string,
  body: string,
  contentType = "application/json",
  tenantId = TENANT,
) {
  return app.request("/v2/provider-actions", {
    method: "POST",
    headers: {
      "content-type": contentType,
      authorization: `Bearer ${token}`,
      "X-Steward-Tenant": tenantId,
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

    // Create one real provider action through the mounted HTTP route. The status
    // tests below then exercise the exact persisted binding + intent rows.
    const token = await signAgentToken([]);
    const created = await post(
      token,
      JSON.stringify({
        workspaceId: WORKSPACE_A,
        providerAccountId: ACCOUNT_A,
        operationKey: "github.issue.list",
        arguments: { owner: "octo", repo: "hello" },
        idempotencyKey: "idem-status-fixture",
      }),
    );
    expect(created.status).toBe(200);
    statusIntentId = ((await created.json()) as { id: string }).id;

    // Every generic JSON surface is hostile at the agent response boundary.
    // Populate nested/array variants of common credential shapes; the status
    // DTO must omit the blobs wholesale, rather than trying to redact them.
    await getDb()
      .update(intents)
      .set({
        authorizationDetails: [
          {
            nested: [
              { password: `${CREDENTIAL_CANARY}-password` },
              { passphrase: `${CREDENTIAL_CANARY}-passphrase` },
              { auth: `Bearer ${CREDENTIAL_CANARY}-auth` },
            ],
          },
        ],
        payload: {
          operationKey: "github.issue.list",
          items: [
            { clientSecretValue: `${CREDENTIAL_CANARY}-client-secret` },
            { cookieHeader: `session=${CREDENTIAL_CANARY}-cookie` },
            { endpoint: `https://user:${CREDENTIAL_CANARY}-userinfo@example.test/path` },
          ],
        },
        executionResult: {
          privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${CREDENTIAL_CANARY}-pem\n-----END PRIVATE KEY-----`,
          nested: [{ apiKey: `${CREDENTIAL_CANARY}-api-key` }],
        },
      })
      .where(eq(intents.id, statusIntentId));
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

  test("agent reads its own provider action through an explicit scalar-only status DTO", async () => {
    const token = await signAgentToken(["some:unrelated:scope"]);
    const own = await app.request(`/v2/provider-actions/${statusIntentId}`, {
      headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT },
    });
    expect(own.status).toBe(200);
    expect(own.headers.get("cache-control")).toBe("no-store, max-age=0");
    const ownBody = (await own.json()) as { ok: boolean; data: Record<string, unknown> };

    expect(ownBody.ok).toBe(true);
    expect(Object.keys(ownBody.data).sort()).toEqual(
      [
        "actionDigest",
        "createdAt",
        "expiresAt",
        "id",
        "operationId",
        "operationRevision",
        "providerAccountId",
        "requestHash",
        "status",
        "updatedAt",
        "version",
        "workspaceId",
      ].sort(),
    );
    expect(ownBody.data).toMatchObject({
      id: statusIntentId,
      status: "stub_succeeded",
      version: 1,
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
      operationId: OP_A_READ,
      operationRevision: 1,
    });
  });

  test("omits nested and array credential canaries instead of redacting extensible blobs", async () => {
    const token = await signAgentToken([]);
    const res = await app.request(`/v2/provider-actions/${statusIntentId}`, {
      headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT },
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(CREDENTIAL_CANARY);
    for (const forbiddenField of [
      "authorizationDetails",
      "payload",
      "executionResult",
      "safeSummary",
      "requestEnvelope",
      "accessDecision",
      "policyDecision",
    ]) {
      expect(text).not.toContain(forbiddenField);
    }
  });

  test("returns the same uniform 404 for foreign agent, foreign tenant, absent, and malformed ids", async () => {
    const cases = [
      {
        token: await signAgentToken([], AGENT_OTHER),
        tenantId: TENANT,
        id: statusIntentId,
      },
      {
        token: await signAgentToken([], AGENT_OTHER_TENANT),
        tenantId: TENANT_OTHER,
        id: statusIntentId,
      },
      {
        token: await signAgentToken([]),
        tenantId: TENANT,
        id: "pa_00000000-0000-4000-8000-000000000000",
      },
      { token: await signAgentToken([]), tenantId: TENANT, id: "not-an-action" },
    ];

    const responses: Array<{ status: number; body: unknown }> = [];
    for (const item of cases) {
      const res = await app.request(`/v2/provider-actions/${item.id}`, {
        headers: {
          authorization: `Bearer ${item.token}`,
          "X-Steward-Tenant": item.tenantId,
        },
      });
      responses.push({ status: res.status, body: await res.json() });
    }

    expect(responses).toEqual(
      cases.map(() => ({
        status: 404,
        body: { ok: false, error: "PROVIDER_ACTION_NOT_FOUND" },
      })),
    );
  });

  test("exact status route does not weaken approval/case/evidence human-MFA gates", async () => {
    const token = await signAgentToken([]);
    for (const suffix of ["approval", "case", "evidence"]) {
      const res = await app.request(`/v2/provider-actions/${statusIntentId}/${suffix}`, {
        headers: { authorization: `Bearer ${token}`, "X-Steward-Tenant": TENANT },
      });
      expect(res.status).toBe(403);
    }
  });

  test("status route requires an agent JWT", async () => {
    const res = await app.request(`/v2/provider-actions/${statusIntentId}`, {
      headers: { "X-Steward-Tenant": TENANT },
    });
    expect(res.status).toBe(401);
  });
});

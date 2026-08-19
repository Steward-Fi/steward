/**
 * #201 public-boundary generic-http governed action E2E.
 *
 * Unlike the service-focused generic-http suite, this fixture does not insert a
 * provider account, operation, grant, role binding, workspace, or secret route.
 * An owner authors every authority object through the fully composed HTTP app;
 * a genuinely verified RS256 agent token invokes and reads the action; and real
 * human-session routes approve, execute, and export the resulting case/evidence.
 */

import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { signAccessToken } from "@stwd/auth";
import { agents, closeDb, secrets, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { GENERIC_HTTP_PROVIDER_ACTION_PROFILE } from "@stwd/shared";
import { KeyStore } from "@stwd/vault";
import type { Hono } from "hono";
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from "jose";
import type { AppVariables } from "../services/context";

setDefaultTimeout(120_000);

const F = {
  tenant: "tenant-generic-public",
  owner: "11000000-0000-4000-8000-000000000001",
  approver: "11000000-0000-4000-8000-000000000002",
  agent: "agent-generic-public",
  secret: "51000000-0000-4000-8000-000000000001",
  operationKey: "acme.ticket.create",
} as const;
const KID = "generic-public-boundary-kid";
const CREDENTIAL = "generic_public_boundary_secret_canary";

let app: Hono<{ Variables: AppVariables }>;
let jwksServer: Server;
let agentPrivateKey: KeyLike;
let dispatchGovernedExecution: typeof import("@stwd/proxy/src/handlers/governed-execution")["dispatchGovernedExecution"];
let capturedForward:
  | { url: string; method: string; headers: Record<string, string>; body: string }
  | undefined;

async function sessionToken(userId: string): Promise<string> {
  return signAccessToken(
    {
      address: `0x${userId.slice(0, 8)}`,
      tenantId: F.tenant,
      userId,
      mfaVerifiedAt: Date.now(),
    } as never,
    "10m",
  );
}

async function agentToken(): Promise<string> {
  return new SignJWT({ agent_id: F.agent, scopes: [], tenant_id: F.tenant })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer("eliza-cloud")
    .setAudience("steward")
    .setSubject(`agent:${F.agent}`)
    .setIssuedAt()
    .setExpirationTime("10m")
    .sign(agentPrivateKey);
}

async function ownerJson(path: string, body: unknown, idempotencyKey: string) {
  return app.request(path, {
    method: "POST",
    headers: {
      authorization: `Bearer ${await sessionToken(F.owner)}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
      "x-steward-tenant": F.tenant,
    },
    body: JSON.stringify(body),
  });
}

async function expectCreated(response: Response, label: string): Promise<void> {
  if (response.status !== 201) {
    throw new Error(`${label} failed (${response.status}): ${await response.text()}`);
  }
}

describe("#201 generic-http true public-boundary E2E", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "0".repeat(64);
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "1".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = "generic-public-boundary-master-password";
    process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = "api.example.com";
    process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.example.com";
    process.env.STEWARD_JWT_SECRET =
      "generic-public-boundary-jwt-secret-0123456789abcdef0123456789";
    const signingKeys = generateKeyPairSync("ed25519");
    process.env.STEWARD_AUDIT_SIGNING_KEY = signingKeys.privateKey
      .export({ format: "pem", type: "pkcs8" })
      .toString();

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());

    const keyStore = new KeyStore(process.env.STEWARD_MASTER_PASSWORD, undefined, "secret-vault");
    const encrypted = keyStore.encrypt(CREDENTIAL, {
      tenantId: F.tenant,
      name: "acme-public-token",
      version: 1,
    });
    await db.insert(tenants).values({ id: F.tenant, name: "Generic public", apiKeyHash: "x" });
    await db.insert(users).values([
      { id: F.owner, email: "generic-owner@example.test" },
      { id: F.approver, email: "generic-approver@example.test" },
    ]);
    await db.insert(userTenants).values([
      { tenantId: F.tenant, userId: F.owner, role: "owner" },
      { tenantId: F.tenant, userId: F.approver, role: "member" },
    ]);
    await db.insert(agents).values({
      id: F.agent,
      tenantId: F.tenant,
      name: "Generic public agent",
      walletAddress: "0x201",
    });
    // Secret creation/encryption is not part of provider authority. This is the
    // only unavoidable direct fixture row; every governed authority object is
    // authored through its authenticated public route below.
    await db.insert(secrets).values({
      id: F.secret,
      tenantId: F.tenant,
      name: "acme-public-token",
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.tag,
      salt: encrypted.salt,
      version: 1,
    });

    const kp = await generateKeyPair("RS256");
    agentPrivateKey = kp.privateKey;
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

    const { resetCheckpointSignerCache } = await import("../services/audit-checkpoint");
    resetCheckpointSignerCache();
    const { clearAgentJwksCacheForTests } = await import("../middleware/agent-jwt");
    clearAgentJwksCacheForTests();
    app = (await import("../app")).app as Hono<{ Variables: AppVariables }>;

    const proxy = await import("@stwd/proxy/src/handlers/proxy");
    ({ dispatchGovernedExecution } = await import("@stwd/proxy/src/handlers/governed-execution"));
    // The public-boundary proof owns authority, credential injection, and
    // dispatch behavior; Redis enforcement has separate fail-closed coverage.
    proxy.__setCheckProxyRateLimitForTests(async () => ({ allowed: true, resetMs: 0 }));
    proxy.__setResolveProxyHostForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
    proxy.__setForwardProxyRequestForTests(async (url, method, headers, body) => {
      const bytes = body
        ? new Uint8Array(await new Response(body).arrayBuffer())
        : new Uint8Array();
      capturedForward = {
        url: url.toString(),
        method,
        headers: Object.fromEntries(headers.entries()),
        body: new TextDecoder().decode(bytes),
      };
      return new Response('{"ticket":"T-201"}', { status: 201 });
    });
  });

  afterAll(async () => {
    const proxy = await import("@stwd/proxy/src/handlers/proxy");
    proxy.__resetProxyHandlerTestHooksForTests();
    await closeDb();
    await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
    for (const key of [
      "STEWARD_PGLITE_MEMORY",
      "STEWARD_AUDIT_HMAC_KEY",
      "STEWARD_EXECUTION_AUTH_SECRET",
      "STEWARD_MASTER_PASSWORD",
      "STEWARD_SECRET_ROUTE_ALLOWED_HOSTS",
      "STEWARD_PROXY_ALLOWED_HOSTS",
      "STEWARD_JWT_SECRET",
      "STEWARD_AUDIT_SIGNING_KEY",
      "ELIZA_CLOUD_JWKS_URL",
    ]) {
      delete process.env[key];
    }
  });

  test("authors, invokes, approves, executes, dispatches, and exports evidence through public routes", async () => {
    const workspaceResponse = await ownerJson(
      "/v2/workspaces",
      {
        key: "generic-public",
        name: "Generic public workspace",
        environment: "production",
        expectedRevision: 0,
        reason: "public E2E workspace",
      },
      "generic-public-workspace",
    );
    await expectCreated(workspaceResponse, "workspace authoring");
    const workspace = (
      (await workspaceResponse.json()) as { data: { id: string; revision: number } }
    ).data;

    const routeResponse = await ownerJson(
      "/secrets/routes",
      {
        secretId: F.secret,
        agentId: F.agent,
        hostPattern: "api.example.com",
        pathPattern: "/v1/tickets",
        method: "POST",
        injectAs: "header",
        injectKey: "authorization",
      },
      "generic-public-route",
    );
    await expectCreated(routeResponse, "secret route authoring");
    const route = ((await routeResponse.json()) as { data: { id: string } }).data;

    const accountResponse = await ownerJson(
      "/v2/provider-accounts",
      {
        workspaceId: workspace.id,
        adapterKey: "generic-http",
        externalRef: "acme-public",
        displayName: "Acme public",
        credentialSecretId: F.secret,
        credentialVersion: 1,
        expectedRevision: workspace.revision,
        reason: "public E2E account",
      },
      "generic-public-account",
    );
    await expectCreated(accountResponse, "provider account authoring");
    const account = ((await accountResponse.json()) as { data: { id: string; revision: number } })
      .data;

    const operationResponse = await ownerJson(
      `/v2/provider-accounts/${account.id}/operations`,
      {
        operationKey: F.operationKey,
        riskClass: "write",
        secretRouteId: route.id,
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            origin: "https://api.example.com",
            methods: ["POST"],
            pathTemplate: [{ literal: "v1" }, { literal: "tickets" }],
            body: {
              contentType: "application/json",
              fields: [{ name: "title", type: "string", pattern: "^.{1,200}$", maxBytes: 4096 }],
            },
            projection: { policyArgs: [], safeSummary: ["title"] },
          },
          policyRules: [
            {
              id: "11111111-1111-4111-8111-111111111111",
              type: "capability-intent",
              enabled: true,
              config: { capabilities: [F.operationKey], effect: "allow" },
            },
            {
              id: "22222222-2222-4222-8222-222222222222",
              type: "capability-intent",
              enabled: true,
              config: { capabilities: [F.operationKey], effect: "require-approval" },
            },
          ],
        },
        expectedRevision: account.revision,
        reason: "public E2E operation",
      },
      "generic-public-operation",
    );
    await expectCreated(operationResponse, "operation authoring");
    const operation = ((await operationResponse.json()) as { data: { id: string } }).data;

    // Account creation advanced the workspace revision from 1 to 2. The role
    // binding advances it to 3, then the grant advances it to 4.
    const roleResponse = await ownerJson(
      "/v2/provider-role-bindings",
      {
        workspaceId: workspace.id,
        principalType: "human",
        principalId: F.approver,
        roleKey: "workspace_approver",
        operationKeys: [F.operationKey],
        environment: "production",
        expectedRevision: 2,
        reason: "public E2E approver",
      },
      "generic-public-role",
    );
    await expectCreated(roleResponse, "approver role authoring");

    const grantResponse = await ownerJson(
      "/v2/provider-grants",
      {
        workspaceId: workspace.id,
        providerAccountId: account.id,
        agentId: F.agent,
        operationKeys: [F.operationKey],
        environment: "production",
        expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
        expectedRevision: 3,
        reason: "public E2E agent grant",
      },
      "generic-public-grant",
    );
    await expectCreated(grantResponse, "agent grant authoring");

    const token = await agentToken();
    const actionResponse = await app.request("/v2/provider-actions", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "x-steward-tenant": F.tenant,
      },
      body: JSON.stringify({
        workspaceId: workspace.id,
        providerAccountId: account.id,
        operationKey: F.operationKey,
        method: "POST",
        arguments: { title: "public boundary ticket" },
        idempotencyKey: "generic-public-action-201",
      }),
    });
    expect(actionResponse.status).toBe(202);
    const action = (await actionResponse.json()) as {
      id: string;
      status: string;
      requestHash: string;
      actionDigest: string;
    };
    expect(action.status).toBe("pending_approval");

    const statusResponse = await app.request(`/v2/provider-actions/${action.id}`, {
      headers: { authorization: `Bearer ${token}`, "x-steward-tenant": F.tenant },
    });
    expect(statusResponse.status).toBe(200);
    expect(await statusResponse.json()).toMatchObject({
      ok: true,
      data: { id: action.id, status: "pending_approval", operationId: operation.id },
    });

    const approver = await sessionToken(F.approver);
    const approvalResponse = await app.request(`/v2/provider-actions/${action.id}/approval`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${approver}`,
        "content-type": "application/json",
        "x-steward-tenant": F.tenant,
      },
      body: JSON.stringify({
        decision: "approve",
        expectedVersion: 1,
        expectedRequestHash: action.requestHash,
        expectedActionDigest: action.actionDigest,
        idempotencyKey: "generic-public-approval-201",
      }),
    });
    expect(approvalResponse.status).toBe(200);
    expect(await approvalResponse.json()).toMatchObject({ status: "approved", version: 2 });

    const executeResponse = await app.request(`/v2/provider-actions/${action.id}/execute`, {
      method: "POST",
      headers: { authorization: `Bearer ${approver}`, "x-steward-tenant": F.tenant },
    });
    expect(executeResponse.status).toBe(200);
    expect(await executeResponse.json()).toMatchObject({ status: "execution_ready" });

    const dispatched = await dispatchGovernedExecution(action.id, F.tenant);
    expect(dispatched).toMatchObject({ ok: true, dispatchState: "succeeded" });
    expect(capturedForward).toMatchObject({
      url: "https://api.example.com/v1/tickets",
      method: "POST",
      headers: { authorization: CREDENTIAL },
      body: '{"title":"public boundary ticket"}',
    });
    expect(JSON.stringify(dispatched)).not.toContain(CREDENTIAL);

    const owner = await sessionToken(F.owner);
    const humanHeaders = { authorization: `Bearer ${owner}`, "x-steward-tenant": F.tenant };
    const caseResponse = await app.request(`/v2/provider-actions/${action.id}/case`, {
      headers: humanHeaders,
    });
    expect(caseResponse.status).toBe(200);
    expect(await caseResponse.json()).toMatchObject({
      caseId: action.id,
      terminalState: "succeeded",
    });

    const evidenceResponse = await app.request(`/v2/provider-actions/${action.id}/evidence`, {
      headers: humanHeaders,
    });
    expect(evidenceResponse.status).toBe(200);
    const evidence = (await evidenceResponse.json()) as {
      manifest: { caseId: string; terminalState: string; completeness: string };
      bundle: { events: unknown[] };
    };
    expect(evidence.manifest).toMatchObject({
      caseId: action.id,
      terminalState: "succeeded",
      completeness: "complete",
    });
    expect(evidence.bundle.events.length).toBeGreaterThan(0);
    const serializedEvidence = JSON.stringify(evidence);
    expect(serializedEvidence).not.toContain(CREDENTIAL);
  });
});

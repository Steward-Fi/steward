/**
 * #201 generic-http governed provider-action E2E (config-driven profile).
 *
 * Proves the FULL governed chain for an operator-authored generic-http operation
 * over the REAL provider-action service + approval state machine against PGLite,
 * exactly as the github/x wiring is proven:
 *
 *   seed a generic-http provider account + operation whose request_profile carries
 *   the operator-authored operation descriptor (origin/method/path template/query/
 *   body) + policyRules -> agent proposes with a DEFERRED build (method + args) ->
 *   the service loads + strictly validates the descriptor after scope resolution
 *   -> canonicalizes -> access allows -> policy composes to approval_required ->
 *   human approves (binding) -> safe resume -> execution_ready, with the binding
 *   committing canonical_profile = 'generic-http.provider-action.v1'.
 *
 * Plus fail-closed E2Es:
 *   - a request whose args build a governed action against a DISALLOWED origin can
 *     never be authored: an IP/non-https descriptor origin is rejected at propose
 *     time (descriptor validation) so no binding persists.
 *   - a malformed stored descriptor => propose fails closed (CANON_PROFILE_UNSUPPORTED),
 *     no intent/binding.
 *   - the read path (allow-only, no approval) reaches the in-process stub.
 *   - an M-of-N quorum composes for free on a generic-http action (rides
 *     request_profile.approvalRequirements.quorum, same as github/x).
 */

import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  setDefaultTimeout,
  test,
} from "bun:test";
import {
  agents,
  approvalQueue,
  auditEvents,
  closeDb,
  executionAuthorizationNonces,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  proxyAuditLog,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  withTenantAuditedTransaction,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { GENERIC_HTTP_PROVIDER_ACTION_PROFILE } from "@stwd/shared";
import { KeyStore } from "@stwd/vault";
import { desc, eq } from "drizzle-orm";
import { Hono } from "hono";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerAuthorityRoutes } from "../routes/provider-authority";
import type { AppVariables } from "../services/context";
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";
import {
  ProviderAuthorityStore,
  providerAuthorityStore,
} from "../services/provider-authority-store";

setDefaultTimeout(120_000);

const G = {
  TENANT: "tenant-gh201",
  AGENT: "agent-gh201",
  WORKSPACE: "22000000-0000-4000-8000-000000000001",
  ACCOUNT: "32000000-0000-4000-8000-000000000001",
  OP_LIST: "42000000-0000-4000-8000-000000000001",
  OP_CREATE: "42000000-0000-4000-8000-000000000002",
  OP_QUORUM: "42000000-0000-4000-8000-000000000003",
  SECRET: "52000000-0000-4000-8000-000000000001",
  ROUTE_LIST: "62000000-0000-4000-8000-000000000001",
  ROUTE_CREATE: "62000000-0000-4000-8000-000000000002",
  ROUTE_QUORUM: "62000000-0000-4000-8000-000000000003",
  ROUTE_AUTHORED: "62000000-0000-4000-8000-000000000004",
  GRANTOR: "12000000-0000-4000-8000-000000000001",
  APPROVER: "82000000-0000-4000-8000-000000000001",
  APPROVER2: "82000000-0000-4000-8000-000000000002",
  APPROVER_BINDING: "92000000-0000-4000-8000-000000000001",
  APPROVER2_BINDING: "92000000-0000-4000-8000-000000000002",
  ADMIN_BINDING: "92000000-0000-4000-8000-000000000003",
  GRANT: "a2000000-0000-4000-8000-000000000001",
} as const;

const OP_LIST_KEY = "acme.item.list";
const OP_CREATE_KEY = "acme.item.create";
const OP_QUORUM_KEY = "acme.item.quorum";
const OP_AUTHORED_KEY = "acme.item.authored";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);
const GENERIC_TOKEN_SENTINEL = "generic_secret_canary_0123456789";
let dispatchGovernedExecution: typeof import("@stwd/proxy/src/handlers/governed-execution")["dispatchGovernedExecution"];
let resetProxyHooks:
  | typeof import("@stwd/proxy/src/handlers/proxy")["__resetProxyHandlerTestHooksForTests"]
  | undefined;
let proxyRateLimitChecks = 0;
const ENV_KEYS = [
  "NODE_ENV",
  "STEWARD_PGLITE_MEMORY",
  "STEWARD_AUDIT_HMAC_KEY",
  "STEWARD_EXECUTION_AUTH_SECRET",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_SECRET_ROUTE_ALLOWED_HOSTS",
  "STEWARD_PROXY_ALLOWED_HOSTS",
  "STEWARD_PROXY_DEV_MODE",
] as const;
const originalEnv = new Map<string, string | undefined>();
let capturedForward:
  | { url: string; method: string; headers: Record<string, string>; body: string }
  | undefined;

function principal(): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId: G.AGENT,
    tenantId: G.TENANT,
    platformId: null,
    issuer: "eliza-cloud",
    subject: `agent:${G.AGENT}`,
    tokenId: null,
    scopes: [],
    authenticatedAt: new Date().toISOString(),
    expiresAt: null,
    authnMethod: "agent-jwt-rs256",
  };
}

function authorityApp(userId: string, tenantRole: string) {
  const app = new Hono<{ Variables: AppVariables }>();
  app.use("*", async (c, next) => {
    c.set("tenantId", G.TENANT);
    c.set("tenantRole", tenantRole);
    c.set("userId", userId);
    c.set("authType", "session-jwt");
    c.set("sessionMfaVerifiedAt", Date.now());
    c.set("requestId", "generic-authority-contract");
    await next();
  });
  app.route("/v2", providerAuthorityRoutes);
  return app;
}

function approvalRules(opKey: string) {
  return [
    {
      id: "11111111-1111-4111-8111-1111111111a1",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "allow" },
    },
    {
      id: "22222222-2222-4222-8222-2222222222a2",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "require-approval" },
    },
  ];
}

function allowRules(opKey: string) {
  return [
    {
      id: "33333333-3333-4333-8333-3333333333a3",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "allow" },
    },
  ];
}

/** GET list descriptor (typed uuid segment + typed query). */
const LIST_DESCRIPTOR = {
  profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  origin: "https://api.example.com",
  methods: ["GET"],
  pathTemplate: [
    { literal: "v1" },
    { literal: "projects" },
    { param: { name: "projectId", type: "uuid" } },
    { literal: "items" },
  ],
  query: [{ name: "state", type: "string", pattern: "^(open|closed|all)$" }],
  headers: [{ name: "accept", value: "application/json" }],
  projection: { policyArgs: ["projectId", "state"], safeSummary: ["projectId"] },
};

/** POST create descriptor (JSON body). */
const CREATE_DESCRIPTOR = {
  profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
  origin: "https://api.example.com",
  methods: ["POST"],
  pathTemplate: [{ literal: "v1" }, { literal: "items" }],
  body: {
    contentType: "application/json",
    fields: [
      { name: "title", type: "string", pattern: "^.{1,200}$", maxBytes: 4096 },
      { name: "priority", type: "int", min: 1, max: 5 },
    ],
  },
  projection: { policyArgs: ["priority"], safeSummary: ["title", "priority"] },
};
const AUTHORED_DESCRIPTOR = {
  ...CREATE_DESCRIPTOR,
  pathTemplate: [{ literal: "v1" }, { literal: "authored-items" }],
};

function route(id: string, path: string, method: string) {
  return {
    id,
    tenantId: G.TENANT,
    secretId: G.SECRET,
    hostPattern: "api.example.com",
    pathPattern: path,
    method,
    injectAs: "header" as const,
    injectKey: "authorization",
    agentId: G.AGENT,
  };
}

async function seedGeneric() {
  const db = getDb();
  const keyStore = new KeyStore(
    process.env.STEWARD_MASTER_PASSWORD ?? "generic-http-test-master",
    undefined,
    "secret-vault",
  );
  const encrypted = keyStore.encrypt(GENERIC_TOKEN_SENTINEL, {
    tenantId: G.TENANT,
    name: "acme-api-key",
    version: 1,
  });
  await db.insert(tenants).values([{ id: G.TENANT, name: "G", apiKeyHash: "hg" }]);
  await db.insert(users).values([
    { id: G.GRANTOR, email: "gg@t.test" },
    { id: G.APPROVER, email: "approverg@t.test" },
    { id: G.APPROVER2, email: "approverg2@t.test" },
  ]);
  await db.insert(userTenants).values([
    { userId: G.GRANTOR, tenantId: G.TENANT, role: "owner" },
    { userId: G.APPROVER, tenantId: G.TENANT, role: "member" },
    { userId: G.APPROVER2, tenantId: G.TENANT, role: "member" },
  ]);
  await db
    .insert(agents)
    .values([
      { id: G.AGENT, tenantId: G.TENANT, name: "AG", walletAddress: "0x1", ownerUserId: null },
    ]);
  await db.insert(secrets).values([
    {
      id: G.SECRET,
      tenantId: G.TENANT,
      name: "acme-api-key",
      ciphertext: encrypted.ciphertext,
      iv: encrypted.iv,
      authTag: encrypted.tag,
      salt: encrypted.salt,
      version: 1,
    },
  ]);
  await db
    .insert(secretRoutes)
    .values([
      route(G.ROUTE_LIST, "/v1/projects", "GET"),
      route(G.ROUTE_CREATE, "/v1/items", "POST"),
      route(G.ROUTE_QUORUM, "/v1/items", "POST"),
      route(G.ROUTE_AUTHORED, "/v1/authored-items", "POST"),
    ]);
  await db.insert(workspaces).values([
    {
      id: G.WORKSPACE,
      tenantId: G.TENANT,
      key: "g-client",
      name: "GC",
      environment: "production",
      createdBy: G.GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: G.ACCOUNT,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      adapterKey: "generic-http",
      externalRef: "acme",
      displayName: "Acme",
      credentialSecretId: G.SECRET,
      credentialVersion: 1,
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: G.OP_LIST,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      providerAccountId: G.ACCOUNT,
      operationKey: OP_LIST_KEY,
      riskClass: "read",
      secretRouteId: G.ROUTE_LIST,
      requestProfile: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        operationDescriptor: LIST_DESCRIPTOR,
        policyRules: allowRules(OP_LIST_KEY),
      },
    },
    {
      id: G.OP_CREATE,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      providerAccountId: G.ACCOUNT,
      operationKey: OP_CREATE_KEY,
      riskClass: "write",
      secretRouteId: G.ROUTE_CREATE,
      requestProfile: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        operationDescriptor: CREATE_DESCRIPTOR,
        policyRules: approvalRules(OP_CREATE_KEY),
      },
    },
    {
      id: G.OP_QUORUM,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      providerAccountId: G.ACCOUNT,
      operationKey: OP_QUORUM_KEY,
      riskClass: "write",
      secretRouteId: G.ROUTE_QUORUM,
      requestProfile: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        operationDescriptor: CREATE_DESCRIPTOR,
        policyRules: approvalRules(OP_QUORUM_KEY),
        approvalRequirements: {
          quorum: { threshold: 2, eligibleApproverUserIds: [G.APPROVER, G.APPROVER2] },
        },
      },
    },
  ]);
  for (const [routeId, operationId, pathPattern] of [
    [G.ROUTE_LIST, G.OP_LIST, "/v1/projects/*"],
    [G.ROUTE_CREATE, G.OP_CREATE, "/v1/items"],
    [G.ROUTE_QUORUM, G.OP_QUORUM, "/v1/items"],
  ] as const) {
    await db
      .update(secretRoutes)
      .set({ authorityMode: "governed_v2", providerOperationId: operationId, pathPattern })
      .where(eq(secretRoutes.id, routeId));
  }
  await db.insert(providerGrants).values([
    {
      id: G.GRANT,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      providerAccountId: G.ACCOUNT,
      agentId: G.AGENT,
      operationKeys: [OP_LIST_KEY, OP_CREATE_KEY, OP_QUORUM_KEY],
      environment: "production",
      expiresAt: FUTURE,
      grantedByUserId: G.GRANTOR,
      reason: "test",
    },
  ]);
  await db.insert(providerRoleBindings).values([
    {
      id: G.ADMIN_BINDING,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      principalType: "human",
      principalId: G.GRANTOR,
      roleKey: "workspace_admin",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: G.GRANTOR,
      reason: "admin",
    },
    {
      id: G.APPROVER_BINDING,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      principalType: "human",
      principalId: G.APPROVER,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: G.GRANTOR,
      reason: "approver",
    },
    {
      id: G.APPROVER2_BINDING,
      tenantId: G.TENANT,
      workspaceId: G.WORKSPACE,
      principalType: "human",
      principalId: G.APPROVER2,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: G.GRANTOR,
      reason: "approver",
    },
  ]);
}

function idemHash(seed: string): string {
  return `sha256:${Buffer.from(seed.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

/** Propose via a DEFERRED generic build (the service finalizes it). */
async function propose(
  opKey: string,
  method: string | undefined,
  args: unknown,
  seed: string,
  overrideOpKey?: string,
) {
  const now = new Date();
  return providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: G.WORKSPACE,
    providerAccountId: G.ACCOUNT,
    operationKey: overrideOpKey ?? opKey,
    build: { kind: "deferred-generic", operationKey: overrideOpKey ?? opKey, method, args },
    idempotencyKeyHash: idemHash(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
}

function freshMfa(): number {
  return Date.now() - 1000;
}

function decideInput(
  intentId: string,
  requestHash: string,
  actionDigest: string,
  userId: string,
  idem: string,
) {
  return {
    intentId,
    tenantId: G.TENANT,
    authenticatedUserId: userId,
    sessionMfaVerifiedAt: freshMfa(),
    decision: "approve" as const,
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey: idem,
  };
}

async function bindingRow(intentId: string) {
  const [b] = await getDb()
    .select()
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId));
  return b;
}

async function wipe() {
  const db = getDb();
  await db.delete(providerActionAuditOutbox);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  await db.delete(providerGrants);
  await db.delete(providerRoleBindings);
  await db.update(secretRoutes).set({ authorityMode: "legacy", providerOperationId: null });
  await db.delete(providerOperations);
  await db.delete(providerAccounts);
  await db.delete(secretRoutes);
  await db.delete(secrets);
  await db.delete(workspaces);
  await db.delete(userTenants);
  await db.delete(agents);
  await db.delete(users);
  await db.delete(tenants);
}

describe("#201 generic-http governed provider-action E2E", () => {
  beforeAll(async () => {
    for (const key of ENV_KEYS) originalEnv.set(key, process.env[key]);
    process.env.NODE_ENV = "test";
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY = "0".repeat(64);
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "1".repeat(64);
    process.env.STEWARD_MASTER_PASSWORD = "generic-http-test-master";
    process.env.STEWARD_SECRET_ROUTE_ALLOWED_HOSTS = "api.example.com";
    process.env.STEWARD_PROXY_ALLOWED_HOSTS = "api.example.com";
    process.env.STEWARD_PROXY_DEV_MODE = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    const proxy = await import("@stwd/proxy/src/handlers/proxy");
    resetProxyHooks = proxy.__resetProxyHandlerTestHooksForTests;
    proxy.__setCheckProxyRateLimitForTests(async () => {
      proxyRateLimitChecks += 1;
      return { allowed: true, remaining: 999, resetMs: 0 };
    });
    ({ dispatchGovernedExecution } = await import("@stwd/proxy/src/handlers/governed-execution"));
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
      return new Response('{"ok":true}', { status: 200 });
    });
  });
  afterAll(async () => {
    let cleanupError: unknown;
    try {
      resetProxyHooks?.();
    } catch (error) {
      cleanupError = error;
    }
    try {
      await closeDb();
    } catch (error) {
      cleanupError ??= error;
    }
    for (const key of ENV_KEYS) {
      const value = originalEnv.get(key);
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    if (cleanupError) throw cleanupError;
  });
  beforeEach(async () => {
    capturedForward = undefined;
    proxyRateLimitChecks = 0;
    await wipe();
    await seedGeneric();
  });

  test("E2E happy path: propose -> policy -> approval_required -> approve -> resume", async () => {
    const out = await propose(
      OP_CREATE_KEY,
      "POST",
      { title: "governed ticket", priority: 3 },
      "ghcreate1",
    );
    expect(out.kind).toBe("approval_required");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);

    const b = await bindingRow(out.intentId);
    expect(b.status).toBe("pending_approval");
    expect(b.canonicalProfile).toBe(GENERIC_HTTP_PROVIDER_ACTION_PROFILE);
    expect(b.approvalCommitmentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    // The safe summary is projected from validated scalars only.
    expect(b.safeSummary).toMatchObject({ operation: OP_CREATE_KEY, priority: 3 });

    const dec = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest, G.APPROVER, "gh-dec-0001"),
    );
    expect(dec.ok).toBe(true);
    if (!dec.ok) throw new Error("unreachable");
    expect(dec.status).toBe("approved");

    const res = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: G.TENANT,
      caller: { agentId: G.AGENT },
    });
    if (!res.ok) throw new Error(`resume failed: ${JSON.stringify(res)}`);
    expect(res.ok).toBe(true);
    expect(res.status).toBe("execution_ready");

    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("execution_ready");
  });

  test("execute-time descriptor drift denies before mint and records the exact reason", async () => {
    const out = await propose(
      OP_CREATE_KEY,
      "POST",
      { title: "approved bytes", priority: 3 },
      "ghdrift01",
    );
    expect(out.kind).toBe("approval_required");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);
    const approved = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest, G.APPROVER, "gh-drift-decide"),
    );
    expect(approved.ok).toBe(true);

    // Simulate out-of-band descriptor corruption after the human approved the
    // old bytes. The current production builder must reconstruct from the
    // current descriptor, compare exact JCS bytes, and stop before nonce mint.
    await getDb()
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: { ...CREATE_DESCRIPTOR, origin: "https://changed.example.com" },
          policyRules: approvalRules(OP_CREATE_KEY),
        },
      })
      .where(eq(providerOperations.id, G.OP_CREATE));

    const resumed = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: G.TENANT,
      caller: { agentId: G.AGENT },
    });
    expect(resumed).toMatchObject({
      ok: false,
      code: "APPROVAL_ACTION_INTEGRITY_FAILED",
      httpStatus: 409,
    });
    expect(
      await getDb()
        .select()
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.intentId, out.intentId)),
    ).toHaveLength(0);
    const denialEvidence = await getDb()
      .select({ action: auditEvents.action, metadata: auditEvents.metadata })
      .from(auditEvents)
      .where(eq(auditEvents.resourceId, out.intentId));
    expect(denialEvidence).toContainEqual({
      action: "provider.resume.policy_denied",
      metadata: expect.objectContaining({ reasonCode: "APPROVAL_ACTION_INTEGRITY_FAILED" }),
    });
  });

  test("operator path: register a validated generic operation, then invoke it", async () => {
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", G.TENANT);
      c.set("tenantRole", "owner");
      c.set("userId", G.GRANTOR);
      c.set("authType", "session-jwt");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", "generic-public-authoring");
      await next();
    });
    app.route("/v2", providerAuthorityRoutes);
    const response = await app.request(`/v2/provider-accounts/${G.ACCOUNT}/operations`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "generic-author-op-1" },
      body: JSON.stringify({
        operationKey: OP_AUTHORED_KEY,
        riskClass: "write",
        secretRouteId: G.ROUTE_AUTHORED,
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: AUTHORED_DESCRIPTOR,
          policyRules: approvalRules(OP_AUTHORED_KEY),
        },
        expectedRevision: 1,
        reason: "register governed Acme write",
      }),
    });
    expect(response.status).toBe(201);
    const operation = (await response.json()).data;
    expect(operation.operationKey).toBe(OP_AUTHORED_KEY);
    const [boundRoute] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, G.ROUTE_AUTHORED));
    expect(boundRoute).toMatchObject({
      authorityMode: "governed_v2",
      providerOperationId: operation.id,
      pathPattern: "/v1/authored-items",
      agentId: G.AGENT,
    });

    await getDb()
      .update(providerGrants)
      .set({
        operationKeys: [OP_LIST_KEY, OP_CREATE_KEY, OP_QUORUM_KEY, OP_AUTHORED_KEY],
        revision: 2,
      })
      .where(eq(providerGrants.id, G.GRANT));

    const out = await propose(
      OP_AUTHORED_KEY,
      "POST",
      { title: "operator-authored ticket", priority: 2 },
      "ghauthor01",
    );
    expect(out.kind).toBe("approval_required");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);
    const approved = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest, G.APPROVER, "public-op-decide"),
    );
    expect(approved.ok).toBe(true);
    const resumed = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: G.TENANT,
      caller: { agentId: G.AGENT },
    });
    expect(resumed.ok).toBe(true);
    const dispatched = await dispatchGovernedExecution(out.intentId, G.TENANT);
    if (!dispatched.ok) {
      const diagnostics = await getDb()
        .select({ reason: proxyAuditLog.reason, statusCode: proxyAuditLog.statusCode })
        .from(proxyAuditLog)
        .orderBy(desc(proxyAuditLog.createdAt))
        .limit(3);
      const [liveRoute] = await getDb()
        .select()
        .from(secretRoutes)
        .where(eq(secretRoutes.id, G.ROUTE_AUTHORED));
      const [nonce] = await getDb()
        .select()
        .from(executionAuthorizationNonces)
        .where(eq(executionAuthorizationNonces.intentId, out.intentId));
      throw new Error(JSON.stringify({ dispatched, diagnostics, liveRoute, nonce }));
    }
    expect(dispatched).toMatchObject({ ok: true, dispatchState: "succeeded" });
    expect(proxyRateLimitChecks).toBe(1);
    expect(capturedForward).toMatchObject({
      url: "https://api.example.com/v1/authored-items",
      method: "POST",
      headers: { authorization: GENERIC_TOKEN_SENTINEL },
    });
    expect(capturedForward?.body).toBe('{"priority":2,"title":"operator-authored ticket"}');
    expect(JSON.stringify(dispatched)).not.toContain(GENERIC_TOKEN_SENTINEL);
  });

  test("HTTP authoring permits the tenant owner but hides resources from an unauthorized member", async () => {
    await getDb().delete(providerRoleBindings).where(eq(providerRoleBindings.id, G.ADMIN_BINDING));
    const requestBody = {
      operationKey: OP_AUTHORED_KEY,
      riskClass: "write",
      secretRouteId: G.ROUTE_AUTHORED,
      requestProfile: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        operationDescriptor: AUTHORED_DESCRIPTOR,
      },
      expectedRevision: 1,
      reason: "tenant owner authors governed operation",
    };
    const owner = await authorityApp(G.GRANTOR, "owner").request(
      `/v2/provider-accounts/${G.ACCOUNT}/operations`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "owner-author-0001" },
        body: JSON.stringify(requestBody),
      },
    );
    expect(owner.status).toBe(201);

    const unauthorized = await authorityApp(G.APPROVER, "member").request(
      `/v2/provider-accounts/${G.ACCOUNT}/operations`,
      {
        method: "POST",
        headers: { "content-type": "application/json", "idempotency-key": "member-author-01" },
        body: JSON.stringify({ ...requestBody, expectedRevision: 2 }),
      },
    );
    expect(unauthorized.status).toBe(404);
  });

  test("HTTP authoring rejects an unbound or multi-method generic operation", async () => {
    const app = authorityApp(G.GRANTOR, "owner");
    const base = {
      operationKey: OP_AUTHORED_KEY,
      riskClass: "write",
      requestProfile: {
        profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
        operationDescriptor: AUTHORED_DESCRIPTOR,
      },
      expectedRevision: 1,
      reason: "negative authority contract",
    };
    const unbound = await app.request(`/v2/provider-accounts/${G.ACCOUNT}/operations`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "unbound-author-1" },
      body: JSON.stringify(base),
    });
    expect(unbound.status).toBe(403);

    const multiMethod = await app.request(`/v2/provider-accounts/${G.ACCOUNT}/operations`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "multi-method-001" },
      body: JSON.stringify({
        ...base,
        secretRouteId: G.ROUTE_AUTHORED,
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: { ...AUTHORED_DESCRIPTOR, methods: ["POST", "PATCH"] },
        },
      }),
    });
    expect(multiMethod.status).toBe(400);
  });

  test("operator path rejects malformed descriptors and widening credential routes before commit", async () => {
    const baseContext = {
      tenantId: G.TENANT,
      actorUserId: G.GRANTOR,
      tenantRole: "owner",
      mfaVerifiedAt: Date.now(),
      idempotencyKey: "generic-author-operation-2",
      expectedRevision: 1,
      reason: "negative authoring proof",
      audit: async () => {},
    };
    await expect(
      providerAuthorityStore.registerOperation(baseContext, G.ACCOUNT, {
        operationKey: OP_AUTHORED_KEY,
        riskClass: "write",
        secretRouteId: G.ROUTE_AUTHORED,
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: { ...AUTHORED_DESCRIPTOR, origin: "https://169.254.169.254" },
        },
      }),
    ).rejects.toMatchObject({ code: "bad_request", status: 400 });

    await expect(
      providerAuthorityStore.registerOperation(
        { ...baseContext, idempotencyKey: "generic-author-operation-3" },
        G.ACCOUNT,
        {
          operationKey: OP_AUTHORED_KEY,
          riskClass: "write",
          secretRouteId: G.ROUTE_LIST,
          requestProfile: {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            operationDescriptor: CREATE_DESCRIPTOR,
          },
        },
      ),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    await getDb()
      .update(secretRoutes)
      .set({ pathPattern: "/v1/items" })
      .where(eq(secretRoutes.id, G.ROUTE_AUTHORED));
    await expect(
      providerAuthorityStore.registerOperation(
        { ...baseContext, idempotencyKey: "generic-author-operation-4" },
        G.ACCOUNT,
        {
          operationKey: OP_AUTHORED_KEY,
          riskClass: "write",
          secretRouteId: G.ROUTE_AUTHORED,
          requestProfile: {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            operationDescriptor: CREATE_DESCRIPTOR,
          },
        },
      ),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    const rows = await getDb()
      .select()
      .from(providerOperations)
      .where(eq(providerOperations.operationKey, OP_AUTHORED_KEY));
    expect(rows).toHaveLength(0);
  });

  test("required final audit failure rolls back provider operation registration and route promotion", async () => {
    const store = new ProviderAuthorityStore((tenantId, fn) =>
      withTenantAuditedTransaction(tenantId, (tx) =>
        fn(tx, async () => {
          throw new Error("injected required audit failure");
        }),
      ),
    );

    await expect(
      store.registerOperation(
        {
          tenantId: G.TENANT,
          actorUserId: G.GRANTOR,
          tenantRole: "owner",
          mfaVerifiedAt: Date.now(),
          idempotencyKey: "generic-author-audit-failure",
          expectedRevision: 1,
          reason: "prove final audit rollback",
          audit: async () => {},
        },
        G.ACCOUNT,
        {
          operationKey: OP_AUTHORED_KEY,
          riskClass: "write",
          secretRouteId: G.ROUTE_AUTHORED,
          requestProfile: {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            operationDescriptor: AUTHORED_DESCRIPTOR,
          },
        },
      ),
    ).rejects.toThrow("injected required audit failure");

    const [account] = await getDb()
      .select({ revision: providerAccounts.revision })
      .from(providerAccounts)
      .where(eq(providerAccounts.id, G.ACCOUNT));
    const operations = await getDb()
      .select()
      .from(providerOperations)
      .where(eq(providerOperations.operationKey, OP_AUTHORED_KEY));
    const [routeAfter] = await getDb()
      .select()
      .from(secretRoutes)
      .where(eq(secretRoutes.id, G.ROUTE_AUTHORED));

    expect(account?.revision).toBe(1);
    expect(operations).toHaveLength(0);
    expect(routeAfter).toMatchObject({
      authorityMode: "legacy",
      providerOperationId: null,
      pathPattern: "/v1/authored-items",
    });
  });

  test("E2E read path: allow-only reaches the in-process stub with no approval", async () => {
    const out = await propose(
      OP_LIST_KEY,
      "GET",
      { projectId: "11111111-1111-4111-8111-111111111111", state: "open" },
      "ghlist001",
    );
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error(`got ${out.kind}`);
    expect(out.stub.status).toBe("stub_succeeded");
    const b = await bindingRow(out.intentId);
    expect(b.canonicalProfile).toBe(GENERIC_HTTP_PROVIDER_ACTION_PROFILE);
    expect(b.status).toBe("stub_succeeded");
  });

  test("E2E quorum: 2-of-2 quorum composes on a generic-http action", async () => {
    const out = await propose(
      OP_QUORUM_KEY,
      "POST",
      { title: "quorum ticket", priority: 4 },
      "ghquorum1",
    );
    expect(out.kind).toBe("approval_required");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);

    // First approve: partial quorum (still pending).
    const d1 = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest, G.APPROVER, "gh-q-0001"),
    );
    expect(d1.ok).toBe(true);
    if (!d1.ok) throw new Error("unreachable");
    // Partial quorum: still awaiting the second distinct approval.
    expect(d1.status).toBe("pending_approval");

    // Second DISTINCT approve: satisfies quorum.
    const d2 = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest, G.APPROVER2, "gh-q-0002"),
    );
    expect(d2.ok).toBe(true);
    if (!d2.ok) throw new Error("unreachable");
    expect(d2.status).toBe("approved");
  });

  test("E2E deny: a descriptor with a disallowed (IP) origin is rejected at propose", async () => {
    // Rewrite the operation descriptor to a private/IP origin (SSRF-adjacent).
    await getDb()
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          operationDescriptor: { ...CREATE_DESCRIPTOR, origin: "https://169.254.169.254" },
          policyRules: approvalRules(OP_CREATE_KEY),
        },
      })
      .where(eq(providerOperations.id, G.OP_CREATE));

    let code = "";
    try {
      await propose(OP_CREATE_KEY, "POST", { title: "x", priority: 1 }, "ghdeny001");
    } catch (e) {
      code = (e as { code?: string }).code ?? "";
    }
    expect(code).toBe("CANON_PROFILE_UNSUPPORTED");
    // No binding persisted for this intent.
    const rows = await getDb().select().from(providerActionBindings);
    expect(rows).toHaveLength(0);
  });

  test("E2E reject: a malformed stored descriptor fails closed at propose", async () => {
    await getDb()
      .update(providerOperations)
      .set({
        requestProfile: {
          profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
          // Missing pathTemplate -> descriptor validation rejects.
          operationDescriptor: {
            profile: GENERIC_HTTP_PROVIDER_ACTION_PROFILE,
            origin: "https://api.example.com",
            methods: ["POST"],
            projection: { policyArgs: [], safeSummary: [] },
          },
          policyRules: approvalRules(OP_CREATE_KEY),
        },
      })
      .where(eq(providerOperations.id, G.OP_CREATE));

    let code = "";
    try {
      await propose(OP_CREATE_KEY, "POST", { title: "x", priority: 1 }, "ghrej0001");
    } catch (e) {
      code = (e as { code?: string }).code ?? "";
    }
    expect(code).toBe("CANON_PROFILE_UNSUPPORTED");
    const rows = await getDb().select().from(providerActionBindings);
    expect(rows).toHaveLength(0);
  });

  test("E2E arg reject: an out-of-descriptor argument is denied at propose", async () => {
    let code = "";
    try {
      await propose(OP_CREATE_KEY, "POST", { title: "x", priority: 1, surprise: "y" }, "gharg0001");
    } catch (e) {
      code = (e as { code?: string }).code ?? "";
    }
    expect(code).toBe("CANON_UNKNOWN_FIELD");
  });
});

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
  closeDb,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { GENERIC_HTTP_PROVIDER_ACTION_PROFILE } from "@stwd/shared";
import { eq } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";

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
  GRANTOR: "12000000-0000-4000-8000-000000000001",
  APPROVER: "82000000-0000-4000-8000-000000000001",
  APPROVER2: "82000000-0000-4000-8000-000000000002",
  APPROVER_BINDING: "92000000-0000-4000-8000-000000000001",
  APPROVER2_BINDING: "92000000-0000-4000-8000-000000000002",
  GRANT: "a2000000-0000-4000-8000-000000000001",
} as const;

const OP_LIST_KEY = "acme.item.list";
const OP_CREATE_KEY = "acme.item.create";
const OP_QUORUM_KEY = "acme.item.quorum";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

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
  };
}

async function seedGeneric() {
  const db = getDb();
  await db.insert(tenants).values([{ id: G.TENANT, name: "G", apiKeyHash: "hg" }]);
  await db.insert(users).values([
    { id: G.GRANTOR, email: "gg@t.test" },
    { id: G.APPROVER, email: "approverg@t.test" },
    { id: G.APPROVER2, email: "approverg2@t.test" },
  ]);
  await db.insert(userTenants).values([
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
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
      version: 1,
    },
  ]);
  await db
    .insert(secretRoutes)
    .values([
      route(G.ROUTE_LIST, "/v1/projects", "GET"),
      route(G.ROUTE_CREATE, "/v1/items", "POST"),
      route(G.ROUTE_QUORUM, "/v1/items", "POST"),
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
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });
  beforeEach(async () => {
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
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.status).toBe("execution_ready");

    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("execution_ready");
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

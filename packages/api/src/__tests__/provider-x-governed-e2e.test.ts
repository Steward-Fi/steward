/**
 * X governed provider-action authority-plane E2E.
 *
 * This file has three kinds of coverage:
 *
 *   1. Profile-CHECK allowlist coverage (`describe("0082 profile-CHECK
 *      widening …")`): migration 0082 widens the provider discriminator
 *      `provider_action_bindings_profile_chk` to admit 'x.provider-action.v1'.
 *      These tests prove BOTH profiles now persist AND that an unknown profile is
 *      still rejected by the same named CHECK.
 *
 *   2. Pure policy-composition unit (`describe("X policy composition …")`):
 *      no DB. Proves the X operation's capability-intent rules compose to
 *      `approval_required` (write) / `allow` (read) via the same
 *      `composeProviderActionPolicyDecision` the service calls, with mutation
 *      proof that dropping the require-approval rule flips the write path to
 *      `allow` (i.e. the approval is genuinely load-bearing, not incidental).
 *
 *   3. Full-chain E2E (`describe("X governed provider-action E2E …")`):
 *      the end-to-end tests require a persisted `provider_action_bindings` row
 *      with `canonical_profile = 'x.provider-action.v1'`.
 *
 * The FULL X governed chain over the real provider-action service + approval
 * state machine runs against PGLite:
 *
 *   connect (seed X vault secret + provider_accounts row directly) -> agent proposes
 *   x.tweet.create via the service
 *   -> access allows -> policy composes to approval_required -> human approves
 *   (binding) -> safe resume -> execution_ready, with a full audit chain.
 *
 * Read-path: x.user.me.read defaults to allow (no approval) and reaches the
 * in-process stub. The real byte-level Bearer
 * injection is proven separately on the proxy plane in
 * packages/proxy/src/__tests__/x-credential-route.test.ts).
 *
 * Negatives (fail-closed):
 *   - tampered canonical action bytes after approval => digest mismatch, stales.
 *   - expired approval => APPROVAL_EXPIRED, no execution.
 *   - credential VERSION DRIFT: a refresh bumps provider_accounts.credential_version
 *     between approval and resume => APPROVAL_CREDENTIAL_STALE (fail-closed). The
 *     stale token is NEVER silently used. This is the documented drift behavior;
 *     it reuses the approval commitment executionDependencies.secretVersion binding
 *     (packages/api/src/services/provider-approval.ts revalidateDependencies).
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
import {
  composeProviderActionPolicyDecision,
  PROVIDER_POLICY_REASON,
  type ProviderPolicyContext,
  type ProviderPolicyRule,
} from "@stwd/policy-engine";
import { buildXAction } from "@stwd/provider-x";
import { X_PROVIDER_ACTION_PROFILE } from "@stwd/shared";
import { eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";

setDefaultTimeout(120_000);

// ─── Fixture ids (X provider account) ─────────────────────────────────────────

const X = {
  TENANT: "tenant-x",
  AGENT: "agent-x",
  WORKSPACE: "21000000-0000-4000-8000-000000000001",
  ACCOUNT: "31000000-0000-4000-8000-000000000001",
  OP_TWEET: "41000000-0000-4000-8000-000000000001",
  OP_READ: "41000000-0000-4000-8000-000000000002",
  OP_DELETE: "41000000-0000-4000-8000-000000000003",
  SECRET: "51000000-0000-4000-8000-000000000001",
  ROUTE_TWEET: "61000000-0000-4000-8000-000000000001",
  ROUTE_READ: "61000000-0000-4000-8000-000000000002",
  ROUTE_DELETE: "61000000-0000-4000-8000-000000000003",
  GRANTOR: "11000000-0000-4000-8000-000000000001",
  APPROVER: "81000000-0000-4000-8000-000000000001",
  APPROVER_BINDING: "91000000-0000-4000-8000-000000000001",
  GRANT: "a1000000-0000-4000-8000-000000000001",
} as const;

const OP_TWEET_KEY = "x.tweet.create";
const OP_READ_KEY = "x.user.me.read";
const OP_DELETE_KEY = "x.tweet.delete";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

function principal(agentId = X.AGENT, tenantId = X.TENANT): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId,
    tenantId,
    platformId: null,
    issuer: "eliza-cloud",
    subject: `agent:${agentId}`,
    tokenId: null,
    scopes: [],
    authenticatedAt: new Date().toISOString(),
    expiresAt: null,
    authnMethod: "agent-jwt-rs256",
  };
}

/** allow + require-approval => approval_required (write path). */
function approvalRules(opKey: string) {
  return [
    {
      id: "11111111-1111-4111-8111-1111111111f1",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "allow" },
    },
    {
      id: "22222222-2222-4222-8222-2222222222f2",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "require-approval" },
    },
  ];
}

/** allow-only => no approval (read path). */
function allowRules(opKey: string) {
  return [
    {
      id: "33333333-3333-4333-8333-3333333333f3",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [opKey], effect: "allow" },
    },
  ];
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
  await db.delete(users);
  await db.delete(tenants);
}

/**
 * Seed an X provider account connected (as #197's connect would leave it):
 * a versioned vault secret holding the OAuth tokens (payload contents are
 * opaque here — we only assert version binding), a provider_accounts row with
 * credential_secret_id/credential_version, three governed operations with their
 * strict secret_routes, an agent grant, and a human workspace_approver.
 */
async function seedX() {
  const db = getDb();
  await db.insert(tenants).values([{ id: X.TENANT, name: "X", apiKeyHash: "hx" }]);
  await db.insert(users).values([
    { id: X.GRANTOR, email: "gx@t.test" },
    { id: X.APPROVER, email: "approverx@t.test" },
  ]);
  await db.insert(userTenants).values([{ userId: X.APPROVER, tenantId: X.TENANT, role: "member" }]);
  await db
    .insert(agents)
    .values([
      { id: X.AGENT, tenantId: X.TENANT, name: "AX", walletAddress: "0x1", ownerUserId: null },
    ]);
  // Versioned vault secret (v1). The connect flow stores the serialized OAuth
  // token payload here; the E2E cares only that credential_version binds it.
  await db.insert(secrets).values([
    {
      id: X.SECRET,
      tenantId: X.TENANT,
      name: "x-oauth",
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
      version: 1,
    },
  ]);
  await db.insert(secretRoutes).values([
    {
      id: X.ROUTE_TWEET,
      tenantId: X.TENANT,
      secretId: X.SECRET,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
    },
    {
      id: X.ROUTE_READ,
      tenantId: X.TENANT,
      secretId: X.SECRET,
      hostPattern: "api.x.com",
      pathPattern: "/2/users/me",
      method: "GET",
      injectAs: "header",
      injectKey: "authorization",
    },
    {
      id: X.ROUTE_DELETE,
      tenantId: X.TENANT,
      secretId: X.SECRET,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets/1234567890",
      method: "DELETE",
      injectAs: "header",
      injectKey: "authorization",
    },
  ]);
  await db.insert(workspaces).values([
    {
      id: X.WORKSPACE,
      tenantId: X.TENANT,
      key: "x-client",
      name: "XC",
      environment: "production",
      createdBy: X.GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: X.ACCOUNT,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      adapterKey: "x",
      externalRef: "9999",
      displayName: "@sol",
      credentialSecretId: X.SECRET,
      credentialVersion: 1,
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: X.OP_TWEET,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      providerAccountId: X.ACCOUNT,
      operationKey: OP_TWEET_KEY,
      riskClass: "write",
      secretRouteId: X.ROUTE_TWEET,
      requestProfile: { policyRules: approvalRules(OP_TWEET_KEY) },
    },
    {
      id: X.OP_READ,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      providerAccountId: X.ACCOUNT,
      operationKey: OP_READ_KEY,
      riskClass: "read",
      secretRouteId: X.ROUTE_READ,
      requestProfile: { policyRules: allowRules(OP_READ_KEY) },
    },
    {
      id: X.OP_DELETE,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      providerAccountId: X.ACCOUNT,
      operationKey: OP_DELETE_KEY,
      riskClass: "write",
      secretRouteId: X.ROUTE_DELETE,
      requestProfile: { policyRules: approvalRules(OP_DELETE_KEY) },
    },
  ]);
  await db.insert(providerGrants).values([
    {
      id: X.GRANT,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      providerAccountId: X.ACCOUNT,
      agentId: X.AGENT,
      operationKeys: [OP_TWEET_KEY, OP_READ_KEY, OP_DELETE_KEY],
      environment: "production",
      expiresAt: FUTURE,
      grantedByUserId: X.GRANTOR,
      reason: "test",
    },
  ]);
  await db.insert(providerRoleBindings).values([
    {
      id: X.APPROVER_BINDING,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      principalType: "human",
      principalId: X.APPROVER,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: X.GRANTOR,
      reason: "approver",
    },
  ]);
}

function idemHash(seed: string): string {
  return `sha256:${Buffer.from(seed.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

async function propose(opKey: string, args: unknown, seed: string) {
  const now = new Date();
  return providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: X.WORKSPACE,
    providerAccountId: X.ACCOUNT,
    operationKey: opKey,
    build: buildXAction(opKey as never, args),
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

function decideInput(intentId: string, requestHash: string, actionDigest: string) {
  return {
    intentId,
    tenantId: X.TENANT,
    authenticatedUserId: X.APPROVER,
    sessionMfaVerifiedAt: freshMfa(),
    decision: "approve" as const,
    expectedVersion: 1,
    expectedRequestHash: requestHash,
    expectedActionDigest: actionDigest,
    reasonCode: null,
    reason: null,
    idempotencyKey: "x-decide-key-0001",
  };
}

async function bindingRow(intentId: string) {
  const [b] = await getDb()
    .select()
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId));
  return b;
}

async function queueRow(intentId: string) {
  const [q] = await getDb()
    .select()
    .from(approvalQueue)
    .where(eq(approvalQueue.intentId, intentId));
  return q;
}

// ─────────────────────────────────────────────────────────────────────────────
// ACTIVE — pure policy composition (no DB). Proves the X operation policy rules
// genuinely compose to approval_required / allow via the SAME composer the
// service invokes, and that the require-approval rule is load-bearing.
// ─────────────────────────────────────────────────────────────────────────────

/** Minimal X-shaped policy context the composer reads (host is carried-only). */
function xPolicyContext(
  opKey: string,
  overrides: Partial<ProviderPolicyContext> = {},
): ProviderPolicyContext {
  const build = buildXAction(
    opKey as never,
    opKey === OP_TWEET_KEY
      ? { text: "gm from a governed agent" }
      : opKey === OP_DELETE_KEY
        ? { tweetId: "1234567890" }
        : {},
  );
  return {
    operationKey: opKey,
    args: build.policyArgs,
    method: build.method,
    host: "api.x.com",
    path: build.action.normalizedPath,
    invokeCount1h: 0,
    ...overrides,
  };
}

describe("X policy composition (authority plane, no DB)", () => {
  test("x.tweet.create: allow + require-approval composes to approval_required", () => {
    const rules = approvalRules(OP_TWEET_KEY) as unknown as ProviderPolicyRule[];
    const out = composeProviderActionPolicyDecision(rules, xPolicyContext(OP_TWEET_KEY));
    expect(out.effect).toBe("approval_required");
    expect(out.reasonCodes).toContain(PROVIDER_POLICY_REASON.APPROVAL_REQUIRED);
  });

  test("MUTATION: dropping the require-approval rule flips x.tweet.create to allow (approval is load-bearing)", () => {
    const rules = allowRules(OP_TWEET_KEY) as unknown as ProviderPolicyRule[];
    const out = composeProviderActionPolicyDecision(rules, xPolicyContext(OP_TWEET_KEY));
    // With ONLY the allow rule, the composed effect is a passing allow — proving
    // the approval_required in the write path above is produced by the
    // require-approval rule, not incidental to the X wiring.
    expect(out.effect).toBe("allow");
    expect(out.reasonCodes).not.toContain(PROVIDER_POLICY_REASON.APPROVAL_REQUIRED);
  });

  test("x.user.me.read: allow-only composes to allow (no approval on the read path)", () => {
    const rules = allowRules(OP_READ_KEY) as unknown as ProviderPolicyRule[];
    const out = composeProviderActionPolicyDecision(rules, xPolicyContext(OP_READ_KEY));
    expect(out.effect).toBe("allow");
    expect(out.reasonCodes).not.toContain(PROVIDER_POLICY_REASON.APPROVAL_REQUIRED);
  });

  test("empty governing rule set fails closed (default-deny), never approval or allow", () => {
    const out = composeProviderActionPolicyDecision([], xPolicyContext(OP_TWEET_KEY));
    expect(out.effect).toBe("hard_deny");
    expect(out.reasonCodes).toContain(PROVIDER_POLICY_REASON.NO_GOVERNING_ALLOW);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Migration 0082 admits the X profile alongside GitHub while keeping the named
// profile CHECK fail-closed for unknown values. The full governed E2E chain below
// proves the complete authority path.
// ─────────────────────────────────────────────────────────────────────────────

describe("0082 profile-CHECK widening: X admitted, unknown profiles still rejected", () => {
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
    await seedX();
  });

  // A minimal, fully-valid DENIED binding shape (access deny -> policy
  // not_evaluated -> status denied). This satisfies every OTHER binding CHECK
  // (state-machine, policy-shape, digest regexes, byte-size) with NO approval
  // columns required, so the profile literal is the ONLY variable under test.
  // Each attempt seeds its own intents row (the binding's intent_fk parent).
  async function bindingValues(profile: string) {
    const db = getDb();
    const h = "sha256:" + "a".repeat(64);
    const idem = `sha256:${crypto.randomUUID().replace(/-/g, "").padEnd(64, "0").slice(0, 64)}`;
    const intentId = crypto.randomUUID();
    await db.insert(intents).values({
      id: intentId,
      tenantId: X.TENANT,
      agentId: X.AGENT,
      intentType: "provider-action",
      status: "rejected",
    });
    return {
      intentId,
      tenantId: X.TENANT,
      workspaceId: X.WORKSPACE,
      actorAgentId: X.AGENT,
      providerAccountId: X.ACCOUNT,
      operationId: X.OP_TWEET,
      operationRevision: 1,
      canonicalProfile: profile,
      canonicalActionBytes: Buffer.from("{}", "utf8"),
      actionDigest: h,
      requestEnvelope: {} as Record<string, unknown>,
      requestHash: idem,
      idempotencyKeyHash: idem,
      safeSummary: {} as Record<string, unknown>,
      accessDecisionId: crypto.randomUUID(),
      accessEffect: "deny" as const,
      accessReasonCode: "ACCESS_DENIED",
      matchedBindingIds: [] as string[],
      matchedGrantIds: [] as string[],
      dependencyRevisions: {} as Record<string, unknown>,
      accessDecision: {} as Record<string, unknown>,
      accessDecisionHash: h,
      policyDecisionId: null,
      policyEffect: "not_evaluated" as const,
      policyReasonCodes: [] as string[],
      policyResults: [] as Array<Record<string, unknown>>,
      policyRevisionHash: null,
      policyDecision: null,
      policyDecisionHash: null,
      status: "denied",
    };
  }

  test("both github and x profiles persist under the widened CHECK", async () => {
    const db = getDb();
    await db
      .insert(providerActionBindings)
      .values(await bindingValues("github.provider-action.v1"));
    await db.insert(providerActionBindings).values(await bindingValues(X_PROVIDER_ACTION_PROFILE));
    const rows = await db.select().from(providerActionBindings);
    expect(rows.length).toBe(2);
    const profiles = rows.map((r) => r.canonicalProfile).sort();
    expect(profiles).toEqual(["github.provider-action.v1", "x.provider-action.v1"]);
  });

  test("an unknown profile is STILL rejected by provider_action_bindings_profile_chk (exact allowlist)", async () => {
    // Prove 0082 widened the allowlist EXACTLY (added the X literal) rather than
    // relaxing the constraint wholesale: a profile outside the {github, x} set is
    // still rejected by the SAME named CHECK with SQLSTATE 23514.
    const db = getDb();
    let caught: unknown;
    try {
      await db
        .insert(providerActionBindings)
        .values(await bindingValues("evil.provider-action.v1"));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    const code =
      (caught as { code?: string })?.code ?? (caught as { cause?: { code?: string } })?.cause?.code;
    expect(code).toBe("23514");
    const constraintName =
      (caught as { constraint?: string })?.constraint ??
      (caught as { cause?: { constraint?: string } })?.cause?.constraint;
    expect(constraintName).toBe("provider_action_bindings_profile_chk");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Full X governed E2E. Migration 0082 admits 'x.provider-action.v1' alongside
// the fixed provider profiles. These cases assert the approval chain end to end.
// ─────────────────────────────────────────────────────────────────────────────

describe("X governed provider-action E2E under the 0082 profile CHECK", () => {
  let priorExecutionAuthSecret: string | undefined;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    priorExecutionAuthSecret = process.env.STEWARD_EXECUTION_AUTH_SECRET;
    process.env.STEWARD_EXECUTION_AUTH_SECRET = "k1:x-governed-e2e-secret-with-enough-entropy";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    if (priorExecutionAuthSecret === undefined) {
      delete process.env.STEWARD_EXECUTION_AUTH_SECRET;
    } else {
      process.env.STEWARD_EXECUTION_AUTH_SECRET = priorExecutionAuthSecret;
    }
  });
  beforeEach(async () => {
    await wipe();
    await seedX();
  });

  test("x.tweet.create: propose -> policy -> approval_required -> approve -> resume", async () => {
    const out = await propose(OP_TWEET_KEY, { text: "gm from a governed agent" }, "twcreate1");
    expect(out.kind).toBe("approval_required");
    if (out.kind !== "approval_required") throw new Error("unreachable");

    // Binding committed the X profile + a real approval commitment.
    const b = await bindingRow(out.intentId);
    expect(b.status).toBe("pending_approval");
    expect(b.canonicalProfile).toBe(X_PROVIDER_ACTION_PROFILE);
    expect(b.approvalCommitmentHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    const q = await queueRow(out.intentId);
    // The commitment binds the X profile + the credential VERSION (drift guard).
    const commitment = q.approvalCommitment as {
      operation: { canonicalProfile: string };
      executionDependencies: { secretId: string; secretVersion: number };
    };
    expect(commitment.operation.canonicalProfile).toBe(X_PROVIDER_ACTION_PROFILE);
    expect(commitment.executionDependencies.secretId).toBe(X.SECRET);
    expect(commitment.executionDependencies.secretVersion).toBe(1);

    // Human approves.
    const dec = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest),
    );
    expect(dec.ok).toBe(true);
    if (!dec.ok) throw new Error("unreachable");
    expect(dec.status).toBe("approved");

    // Safe resume -> execution_ready (no execution, no credential decrypt here).
    const res = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: X.TENANT,
      caller: { agentId: X.AGENT },
    });
    expect(res.ok).toBe(true);
    if (!res.ok) throw new Error("unreachable");
    expect(res.status).toBe("execution_ready");
    expect(res.resumeAttemptId).toBeTruthy();

    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("execution_ready");
  });

  test("x.user.me.read: allow read path reaches the stub with no approval", async () => {
    const out = await propose(OP_READ_KEY, {}, "read0001");
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error(`got ${out.kind}`);
    expect(out.stub.status).toBe("stub_succeeded");
    const b = await bindingRow(out.intentId);
    expect(b.canonicalProfile).toBe(X_PROVIDER_ACTION_PROFILE);
    expect(b.status).toBe("stub_succeeded");
  });

  test("NEGATIVE: tampered canonical action bytes after approval => digest mismatch, stales", async () => {
    const out = await propose(OP_TWEET_KEY, { text: "original text" }, "tamper01");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);
    const dec = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest),
    );
    expect(dec.ok).toBe(true);

    // Tamper the stored canonical action bytes AFTER approval (attacker swaps the
    // body between approval and execution). Integrity re-hash at resume must
    // catch it and fail closed (stale), never resume.
    const b = await bindingRow(out.intentId);
    const tampered = Buffer.from(
      (b.canonicalActionBytes as Uint8Array as Buffer)
        .toString("utf8")
        .replace("original text", "attacker text"),
      "utf8",
    );
    // governed-execution's immutability trigger (steward_provider_action_binding_guard) freezes
    // canonical_action_bytes at the DB layer, so an attacker's raw column write is
    // already rejected there. That trigger is defense-in-depth; the AUTHORITY check
    // under test is the service's integrity re-hash at resume. Disable the trigger
    // for the tamper so the mutated bytes reach resume and the recompute (not the
    // trigger) is what fails closed — mirrors the github N24 negative test.
    await getDb().execute(
      sql`ALTER TABLE provider_action_bindings DISABLE TRIGGER provider_action_bindings_immutable`,
    );
    await getDb()
      .update(providerActionBindings)
      .set({ canonicalActionBytes: tampered })
      .where(eq(providerActionBindings.intentId, out.intentId));
    await getDb().execute(
      sql`ALTER TABLE provider_action_bindings ENABLE TRIGGER provider_action_bindings_immutable`,
    );

    const res = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: X.TENANT,
      caller: { agentId: X.AGENT },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.code).toBe("APPROVAL_COMMITMENT_INTEGRITY_MISMATCH");
    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("approval_stale");
  });

  test("NEGATIVE: expired approval => APPROVAL_EXPIRED, no execution", async () => {
    const out = await propose(OP_TWEET_KEY, { text: "will expire" }, "expire01");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);
    const dec = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest),
    );
    expect(dec.ok).toBe(true);

    // Force the queue row past its expiry, then resume: expiry wins fail-closed.
    await getDb()
      .update(approvalQueue)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(approvalQueue.intentId, out.intentId));

    const res = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: X.TENANT,
      caller: { agentId: X.AGENT },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.code).toBe("APPROVAL_EXPIRED");
    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("approval_expired");
  });

  test("NEGATIVE: credential version drift between approval and resume => APPROVAL_CREDENTIAL_STALE", async () => {
    const out = await propose(OP_TWEET_KEY, { text: "drift me" }, "drift001");
    if (out.kind !== "approval_required") throw new Error(`got ${out.kind}`);
    const dec = await providerApprovalService.decide(
      decideInput(out.intentId, out.requestHash, out.actionDigest),
    );
    expect(dec.ok).toBe(true);

    // Simulate #197's token refresh landing BETWEEN approval and execution: a
    // new secret version is written and provider_accounts.credential_version is
    // bumped to point at it. The commitment bound version 1; the drift must
    // surface as APPROVAL_CREDENTIAL_STALE and the action must NOT resume with
    // the new (unapproved) token.
    const db = getDb();
    await db.insert(secrets).values([
      {
        id: "52000000-0000-4000-8000-000000000002",
        tenantId: X.TENANT,
        name: "x-oauth",
        ciphertext: "y",
        iv: "y",
        authTag: "y",
        salt: "y",
        version: 2,
      },
    ]);
    await db
      .update(providerAccounts)
      .set({ credentialSecretId: "52000000-0000-4000-8000-000000000002", credentialVersion: 2 })
      .where(eq(providerAccounts.id, X.ACCOUNT));

    const res = await providerApprovalService.resume({
      intentId: out.intentId,
      tenantId: X.TENANT,
      caller: { agentId: X.AGENT },
    });
    expect(res.ok).toBe(false);
    if (res.ok) throw new Error("unreachable");
    expect(res.code).toBe("APPROVAL_CREDENTIAL_STALE");
    const bFinal = await bindingRow(out.intentId);
    expect(bFinal.status).toBe("approval_stale");
  });
});

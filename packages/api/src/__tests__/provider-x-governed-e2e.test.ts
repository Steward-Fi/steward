/**
 * X governed provider-action E2E (#195 workstream C, authority plane).
 *
 * ── State of this suite (READ THIS) ─────────────────────────────────────────
 * This file has THREE kinds of coverage:
 *
 *   1. ACTIVE full-chain-up-to-persist proof (`describe("X governed wiring …")`):
 *      proposes a real `x.tweet.create` through the real provider-action service
 *      against a fully-migrated PGLite. It proves the ENTIRE governed chain runs
 *      for X — access allow, policy composing an approval_required decision on the
 *      X profile, and the PR3 approval arm building — and that the ONLY thing that
 *      stops it is the persist of the `provider_action_bindings` row. It then
 *      isolates that persist failure to the EXACT database blocker
 *      (`provider_action_bindings_profile_chk`), proving it is the migration CHECK
 *      and not a wiring bug.
 *
 *   2. ACTIVE pure policy-composition unit (`describe("X policy composition …")`):
 *      no DB. Proves the X operation's capability-intent rules compose to
 *      `approval_required` (write) / `allow` (read) via the same
 *      `composeProviderActionPolicyDecision` the service calls, with mutation
 *      proof that dropping the require-approval rule flips the write path to
 *      `allow` (i.e. the approval is genuinely load-bearing, not incidental).
 *
 *   3. SKIPPED full-chain E2E (`describe.skip("X governed provider-action E2E …")`):
 *      the five end-to-end tests that require a `provider_action_bindings` row to
 *      PERSIST with `canonical_profile = 'x.provider-action.v1'`.
 *
 * ── Why the five E2E tests are skipped (the blocker) ────────────────────────
 * `packages/db/drizzle/0080_provider_action_bindings.sql` line 69:
 *
 *     CONSTRAINT "provider_action_bindings_profile_chk"
 *       CHECK ("canonical_profile" = 'github.provider-action.v1')
 *
 * The CHECK hardcodes the github profile literal, so NO X binding
 * (`canonical_profile = 'x.provider-action.v1'`) can be persisted yet. The
 * provider-action service builds the correct X binding and fails closed at the
 * INSERT (surfaced to the caller as `EVIDENCE_DECISION_PERSIST_FAILED`). This is
 * proven precisely by the ACTIVE suite below.
 *
 * The migration that widens this CHECK to admit `'x.provider-action.v1'` is NOT
 * taken in this PR: the next free migration journal slot is owned by the in-flight
 * PR4 (feat/execution-authorization-v2, migration 0082). Taking a competing
 * migration here would collide the journal. The follow-up is: AFTER PR4 lands,
 * the next free slot (0083+) widens the profile CHECK, and these five tests get
 * un-skipped in that same follow-up PR (no code change to the tests is needed —
 * they already assert the full X chain end to end).
 *
 * ── What the five (skipped) tests prove once unblocked ──────────────────────
 * The FULL X governed chain over the real provider-action service + approval
 * state machine against PGLite, exactly as the github wiring is proven:
 *
 *   connect (seed X vault secret + provider_accounts row directly — we do NOT
 *   re-test #197's OAuth dance) -> agent proposes x.tweet.create via the service
 *   -> access allows -> policy composes to approval_required -> human approves
 *   (binding) -> safe resume -> execution_ready, with a full audit chain.
 *
 * Read-path: x.user.me.read defaults to allow (no approval) and reaches the
 * in-process stub (the legacy pre-PR4 executor; the real byte-level Bearer
 * injection is proven separately on the proxy plane in
 * packages/proxy/src/__tests__/x-credential-route.test.ts).
 *
 * Negatives (fail-closed):
 *   - tampered canonical action bytes after approval => digest mismatch, stales.
 *   - expired approval => APPROVAL_EXPIRED, no execution.
 *   - credential VERSION DRIFT: a refresh bumps provider_accounts.credential_version
 *     between approval and resume => APPROVAL_CREDENTIAL_STALE (fail-closed). The
 *     stale token is NEVER silently used. This is the documented drift behavior;
 *     it reuses the PR3 commitment executionDependencies.secretVersion binding
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
import { eq } from "drizzle-orm";
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
// ACTIVE — full governed chain UP TO the constrained persist. Proves the entire
// X governed pipeline runs against a fully-migrated PGLite, and that the ONLY
// thing stopping it is the 0080 profile CHECK on provider_action_bindings — not a
// wiring bug. Runs the real provider-action service (access + policy + approval
// arm) and then isolates the persist failure to the exact DB constraint.
// ─────────────────────────────────────────────────────────────────────────────

describe("X governed wiring up to the 0080 profile-CHECK blocker", () => {
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

  test("x.tweet.create runs the whole chain and fails CLOSED only at the binding persist", async () => {
    // The whole governed pipeline runs: access allows (grant present), policy
    // composes approval_required (write rules), and the PR3 approval arm builds
    // — all BEFORE the provider_action_bindings insert. The insert carries
    // canonical_profile = 'x.provider-action.v1', which violates the 0080 CHECK,
    // so the create transaction rolls back and the service returns a fail-closed
    // evidence failure. No partial binding, no approval queue row, no stub call.
    const out = await propose(OP_TWEET_KEY, { text: "gm from a governed agent" }, "twcreate1");
    expect(out.kind).toBe("evidence_failure");
    if (out.kind !== "evidence_failure") throw new Error("unreachable");
    expect(out.code).toBe("EVIDENCE_DECISION_PERSIST_FAILED");

    // Transaction rolled back cleanly: nothing persisted for this intent.
    const bindings = await getDb().select().from(providerActionBindings);
    expect(bindings.length).toBe(0);
    const queue = await getDb().select().from(approvalQueue);
    expect(queue.length).toBe(0);
  });

  test("BLOCKER ISOLATION: the persist failure is PRECISELY the 0080 profile CHECK, not a wiring bug", async () => {
    // Prove the exact database constraint that blocks X. Attempt the minimal
    // provider_action_bindings insert that differs from a github binding ONLY in
    // the profile literal, against the fully-migrated schema. The X profile is
    // rejected by name; the github profile inserts fine. This pins the blocker to
    // provider_action_bindings_profile_chk (0080 line 69) and nothing else.
    const db = getDb();

    // A minimal, fully-valid DENIED binding shape (access deny -> policy
    // not_evaluated -> status denied). This satisfies every OTHER 0080 CHECK
    // (state-machine, policy-shape, digest regexes, byte-size) with NO approval
    // columns required, so the profile literal is the ONLY variable under test.
    // Each attempt seeds its own intents row (the binding's intent_fk parent).
    async function bindingValues(profile: string) {
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

    // CONTROL FIRST: the SAME row shape with the github profile literal persists
    // cleanly. This proves the row satisfies EVERY other binding constraint
    // (all NOT NULLs, every format/state CHECK, all FKs) — so the row is complete
    // and valid in every dimension except the profile literal.
    await db
      .insert(providerActionBindings)
      .values(await bindingValues("github.provider-action.v1"));
    const control = await db.select().from(providerActionBindings);
    expect(control.length).toBe(1);
    expect(control[0]?.canonicalProfile).toBe("github.provider-action.v1");

    // Now the X row: byte-identical shape, ONLY canonical_profile swapped to
    // 'x.provider-action.v1'. Since the control proved the shape is otherwise
    // valid, the sole thing that can reject it is the profile CHECK
    // (provider_action_bindings_profile_chk, 0080 line 69). Assert it throws a
    // check_violation (SQLSTATE 23514) — not a null/FK/format error, and not a
    // wiring defect.
    let caught: unknown;
    try {
      await db
        .insert(providerActionBindings)
        .values(await bindingValues(X_PROVIDER_ACTION_PROFILE));
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    const code =
      (caught as { code?: string })?.code ?? (caught as { cause?: { code?: string } })?.cause?.code;
    expect(code).toBe("23514");
    // The underlying PG error names the exact constraint: this pins the blocker
    // to 0080's profile CHECK by NAME, not merely to "some check failed".
    const constraintName =
      (caught as { constraint?: string })?.constraint ??
      (caught as { cause?: { constraint?: string } })?.cause?.constraint;
    expect(constraintName).toBe("provider_action_bindings_profile_chk");

    // And the X row did NOT persist: the table still holds only the github control.
    const after = await db.select().from(providerActionBindings);
    expect(after.length).toBe(1);
    expect(after[0]?.canonicalProfile).toBe("github.provider-action.v1");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SKIPPED — full X governed E2E. Blocked by 0080 provider_action_bindings_profile_chk
// (see the file header). Un-skip in the post-PR4 follow-up PR that widens the
// CHECK to admit 'x.provider-action.v1'. No test change is needed at that point —
// these assert the full chain end to end and will pass once the binding persists.
// ─────────────────────────────────────────────────────────────────────────────

describe.skip("X governed provider-action E2E (unblock after 0080 CHECK widened, post-PR4)", () => {
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
    await getDb()
      .update(providerActionBindings)
      .set({ canonicalActionBytes: tampered })
      .where(eq(providerActionBindings.intentId, out.intentId));

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

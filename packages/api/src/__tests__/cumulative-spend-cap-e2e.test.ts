/**
 * cumulative-spend-cap-e2e.test.ts - #206 C-DRIFT-2 full-chain E2Es.
 *
 * These run through the REAL providerActionService against a REAL PGLite DB AND
 * a REAL Redis (the atomic cumulative-spend reservation store). No stubbed
 * aggregate: the trailing-window sum is materialized from actual reservations in
 * Redis, exactly as production would.
 *
 * The governed operation `x.tweet.create` is configured (in its request profile)
 * with an ALLOW rule carrying a `cumulativeSpend` cap denominated in "BYTES",
 * and a `spendDeclaration` pointing at the validated `textByteLength` policyArg.
 * Each governed invoke therefore "spends" its tweet's byte length; a SEQUENCE of
 * invokes accumulates until the trailing-window cap is crossed, at which point
 * the service denies with the structured reason POLICY_CUMULATIVE_SPEND_CAP_EXCEEDED.
 * (Bytes are a legitimate integer spend proxy here - the point is the real
 * aggregate wiring + atomic reservation + structured deny, not the currency.)
 *
 * E2E #1: a sequence of allow invokes crosses the agent-scoped cap; the crossing
 *         invoke denies with the structured reason; earlier invokes allowed.
 * E2E #2: the currency-mismatch + no-spend-field fail-closed reasons surface
 *         end-to-end (a cap in a different currency, and an op with no
 *         declaration, both deny through the real service).
 *
 * Requires a reachable Redis (REDIS_URL, default redis://localhost:6379). Gated
 * on STEWARD_REDIS_TESTS=1 so CI without Redis skips cleanly, matching the
 * spend-tracker suite convention.
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
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerActionReservationGenerations,
  providerAgentBudgets,
  providerGrants,
  providerOperations,
  providerRoleBindings,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  vaultSigningFreezes,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { PROVIDER_POLICY_REASON } from "@stwd/policy-engine";
import { buildXAction } from "@stwd/provider-x";
import {
  disconnectRedis,
  getCumulativeSpendSum,
  getRedis,
  reserveCumulativeSpend,
} from "@stwd/redis";
import { and, eq } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import {
  __setDecisionReservationCrashForTests,
  __setReservationReconciliationFaultForTests,
  providerActionService,
} from "../services/provider-action-service";
import { providerApprovalService } from "../services/provider-approval";

setDefaultTimeout(120_000);

const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;

// Unique agent per run so Redis reservation keys never collide across runs.
const RUN = Date.now().toString(36);
const CS = {
  TENANT: "tenant-cs",
  AGENT: `agent-cs-${RUN}`,
  WORKSPACE: "21000000-0000-4000-8000-0000000000c1",
  ACCOUNT: "31000000-0000-4000-8000-0000000000c1",
  OP_TWEET: "41000000-0000-4000-8000-0000000000c1",
  OP_NODECL: "41000000-0000-4000-8000-0000000000c2",
  SECRET: "51000000-0000-4000-8000-0000000000c1",
  ROUTE_TWEET: "61000000-0000-4000-8000-0000000000c1",
  ROUTE_NODECL: "61000000-0000-4000-8000-0000000000c2",
  GRANTOR: "11000000-0000-4000-8000-0000000000c1",
  GRANT: "a1000000-0000-4000-8000-0000000000c1",
  ROLE_BINDING: "b1000000-0000-4000-8000-0000000000c1",
} as const;

const OP_TWEET_KEY = "x.tweet.create";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

function principal(): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId: CS.AGENT,
    tenantId: CS.TENANT,
    platformId: null,
    issuer: "eliza-cloud",
    subject: `agent:${CS.AGENT}`,
    tokenId: null,
    scopes: [],
    authenticatedAt: new Date().toISOString(),
    expiresAt: null,
    authnMethod: "agent-jwt-rs256",
  };
}

/** allow rule + a cumulativeSpend cap over textByteLength in the given currency. */
function spendCapRules(opKey: string, maxBytes: number, currency = "BYTES") {
  return [
    {
      id: "c1111111-1111-4111-8111-1111111111f1",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [opKey],
        effect: "allow",
        constraints: {
          cumulativeSpend: {
            window: "PT24H",
            currency,
            max: maxBytes,
            aggregateOver: "agent",
          },
        },
      },
    },
  ];
}

/** allow rule + a GRANT-scoped cumulativeSpend cap. */
function grantScopedSpendRules(opKey: string, maxBytes: number) {
  return [
    {
      id: "c3333333-3333-4333-8333-3333333333f3",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [opKey],
        effect: "allow",
        constraints: {
          cumulativeSpend: {
            window: "PT24H",
            currency: "BYTES",
            max: maxBytes,
            aggregateOver: "grant",
          },
        },
      },
    },
  ];
}

/** allow rule + a configurable count cap (maxCalls + callWindow). */
function countCapRules(opKey: string, maxCalls: number, callWindow = "PT24H") {
  return [
    {
      id: "c2222222-2222-4222-8222-2222222222f2",
      type: "capability-intent",
      enabled: true,
      config: {
        capabilities: [opKey],
        effect: "allow",
        constraints: { maxCalls, callWindow },
      },
    },
  ];
}

async function cleanupRedis() {
  const redis = getRedis();
  for (const pattern of [`cumspend:${CS.AGENT}*`, `cumspend:v2:*${CS.AGENT}*`]) {
    let cursor = "0";
    do {
      const [next, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
      cursor = next;
      if (keys.length > 0) await redis.del(...keys);
    } while (cursor !== "0");
  }
}

async function wipe() {
  const db = getDb();
  await db.delete(providerActionAuditOutbox);
  await db.delete(vaultSigningFreezes);
  await db.delete(approvalQueue);
  await db.delete(providerActionBindings);
  await db.delete(intents);
  await db.delete(providerGrants);
  await db.delete(providerAgentBudgets);
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
 * Seed the account + operation. `spendField` present => the operation's request
 * profile declares { field, currency } so cumulativeSpend can price it. `maxBytes`
 * sets the cap; `currency` lets E2E #2 force a mismatch.
 */
async function seed(opts: {
  maxBytes: number;
  capCurrency?: string;
  declaredCurrency?: string;
  declareSpendField?: boolean;
  countCapMaxCalls?: number;
  combineCountAndSpend?: boolean;
  grantScoped?: boolean;
  accessViaRoleBindingNoGrant?: boolean;
  extraDenyRule?: boolean;
  requireApproval?: boolean;
}) {
  const db = getDb();
  await db.insert(tenants).values([{ id: CS.TENANT, name: "CS", apiKeyHash: "hcs" }]);
  await db.insert(users).values([{ id: CS.GRANTOR, email: "gcs@t.test" }]);
  await db
    .insert(agents)
    .values([
      { id: CS.AGENT, tenantId: CS.TENANT, name: "ACS", walletAddress: "0x1", ownerUserId: null },
    ]);
  await db.insert(secrets).values([
    {
      id: CS.SECRET,
      tenantId: CS.TENANT,
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
      id: CS.ROUTE_TWEET,
      tenantId: CS.TENANT,
      secretId: CS.SECRET,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
    },
  ]);
  await db.insert(workspaces).values([
    {
      id: CS.WORKSPACE,
      tenantId: CS.TENANT,
      key: "cs-client",
      name: "CSC",
      environment: "production",
      createdBy: CS.GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: CS.ACCOUNT,
      tenantId: CS.TENANT,
      workspaceId: CS.WORKSPACE,
      adapterKey: "x",
      // account provider handle reference - plain scalar.
      externalRef: "8888",
      displayName: "@cs",
      credentialSecretId: CS.SECRET,
      credentialVersion: 1,
    },
  ]);
  const requestProfile: Record<string, unknown> = {
    policyRules:
      opts.countCapMaxCalls !== undefined && !opts.combineCountAndSpend
        ? countCapRules(OP_TWEET_KEY, opts.countCapMaxCalls)
        : opts.grantScoped
          ? grantScopedSpendRules(OP_TWEET_KEY, opts.maxBytes)
          : spendCapRules(OP_TWEET_KEY, opts.maxBytes, opts.capCurrency ?? "BYTES"),
  };
  if (opts.combineCountAndSpend && opts.countCapMaxCalls !== undefined) {
    (requestProfile.policyRules as Array<Record<string, unknown>>).push(
      ...countCapRules(OP_TWEET_KEY, opts.countCapMaxCalls),
    );
  }
  if (opts.extraDenyRule) {
    (requestProfile.policyRules as Array<Record<string, unknown>>).push({
      id: "c4444444-4444-4444-8444-4444444444f4",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [OP_TWEET_KEY], effect: "deny" },
    });
  }
  if (opts.requireApproval) {
    (requestProfile.policyRules as Array<Record<string, unknown>>).push({
      id: "c5555555-5555-4555-8555-5555555555f5",
      type: "capability-intent",
      enabled: true,
      config: { capabilities: [OP_TWEET_KEY], effect: "require-approval" },
    });
  }
  if (
    (opts.countCapMaxCalls === undefined || opts.combineCountAndSpend) &&
    opts.declareSpendField !== false
  ) {
    requestProfile.spendDeclaration = {
      field: "textByteLength",
      currency: opts.declaredCurrency ?? "BYTES",
    };
  }
  await db.insert(providerOperations).values([
    {
      id: CS.OP_TWEET,
      tenantId: CS.TENANT,
      workspaceId: CS.WORKSPACE,
      providerAccountId: CS.ACCOUNT,
      operationKey: OP_TWEET_KEY,
      riskClass: "write",
      secretRouteId: CS.ROUTE_TWEET,
      requestProfile,
    },
  ]);
  if (opts.accessViaRoleBindingNoGrant) {
    // Access via a workspace_operator role binding, NO grant => matchedGrantIds
    // is empty. A grant-scoped cap then has no grant identity (codex P1).
    await db.insert(providerRoleBindings).values([
      {
        id: CS.ROLE_BINDING,
        tenantId: CS.TENANT,
        workspaceId: CS.WORKSPACE,
        principalType: "agent",
        principalId: CS.AGENT,
        roleKey: "workspace_operator",
        operationKeys: [OP_TWEET_KEY],
        environment: "production",
        status: "active",
        grantedByUserId: CS.GRANTOR,
        reason: "operator",
      },
    ]);
  } else {
    await db.insert(providerGrants).values([
      {
        id: CS.GRANT,
        tenantId: CS.TENANT,
        workspaceId: CS.WORKSPACE,
        providerAccountId: CS.ACCOUNT,
        agentId: CS.AGENT,
        operationKeys: [OP_TWEET_KEY],
        environment: "production",
        expiresAt: FUTURE,
        grantedByUserId: CS.GRANTOR,
        reason: "test",
      },
    ]);
  }
  if (opts.requireApproval) {
    await db
      .insert(userTenants)
      .values([{ userId: CS.GRANTOR, tenantId: CS.TENANT, role: "admin" }]);
    await db.insert(providerRoleBindings).values([
      {
        id: "71000000-0000-4000-8000-0000000000c1",
        tenantId: CS.TENANT,
        workspaceId: CS.WORKSPACE,
        principalType: "human",
        principalId: CS.GRANTOR,
        roleKey: "workspace_approver",
        operationKeys: [OP_TWEET_KEY],
        environment: "production",
        status: "active",
        grantedByUserId: CS.GRANTOR,
        reason: "approval test",
      },
    ]);
  }
}

function idemHash(seed: string): string {
  return `sha256:${Buffer.from(seed.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

/** Propose a tweet.create with the given text; textByteLength = the spend. */
async function proposeTweet(text: string, seed: string) {
  const now = new Date();
  return providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: CS.WORKSPACE,
    providerAccountId: CS.ACCOUNT,
    operationKey: OP_TWEET_KEY,
    build: buildXAction("x.tweet.create" as never, { text } as never),
    idempotencyKeyHash: idemHash(seed),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seed.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
}

describeRedis("#206 cumulativeSpend cap - full-chain E2E (real service + real Redis)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    process.env.REDIS_URL ||= "redis://localhost:6379";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
  });
  afterAll(async () => {
    await cleanupRedis();
    await closeDb();
    await disconnectRedis();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });
  beforeEach(async () => {
    __setDecisionReservationCrashForTests(false);
    __setReservationReconciliationFaultForTests(null);
    providerApprovalService.faultHooks = {};
    await wipe();
    await cleanupRedis();
  });

  test("v2 release rejects a handle whose Redis tenant namespace is foreign", async () => {
    await expect(
      providerActionService.releasePolicyReservationHandles(
        {
          schemaVersion: "steward.provider-policy-reservations.v2",
          generation: 1,
          phase: "decision",
          cumulativeSpend: [
            {
              stream: {
                tenantId: "foreign-tenant",
                agentId: CS.AGENT,
                scope: "agent",
                scopeKey: "",
                currency: "BYTES",
              },
              reservationId: "foreign-handle",
              amount: 1,
            },
          ],
          windowedInvoke: null,
        },
        CS.TENANT,
      ),
    ).rejects.toThrow("invalid persisted policy reservation handles");
  });

  test("E2E #1: a sequence of allow invokes crosses the agent cap; the crossing invoke denies", async () => {
    // Each "a" is 1 byte. Cap = 250 bytes over PT24H, agent-scoped.
    // tweet of 100 bytes, then 100 bytes (running 200 <= 250 => allow), then a
    // 100-byte tweet would make 300 > 250 => DENY.
    await seed({ maxBytes: 250 });

    const t1 = await proposeTweet("a".repeat(100), "cs-e2e-1a");
    expect(t1.kind).toBe("allowed"); // 0 + 100 = 100 <= 250

    const t2 = await proposeTweet("b".repeat(100), "cs-e2e-1b");
    expect(t2.kind).toBe("allowed"); // 100 + 100 = 200 <= 250

    const t3 = await proposeTweet("c".repeat(100), "cs-e2e-1c");
    expect(t3.kind).toBe("policy_denied"); // 200 + 100 = 300 > 250 => DENY
    if (t3.kind === "policy_denied") {
      expect(t3.code).toBe(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CAP_EXCEEDED);
    }
    const t3Replay = await proposeTweet("c".repeat(100), "cs-e2e-1c");
    expect(t3Replay).toMatchObject({
      kind: "policy_denied",
      code: PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CAP_EXCEEDED,
    });

    // A smaller tweet that still fits (200 + 40 = 240 <= 250) is admitted - the
    // denied invoke did NOT consume budget (its reservation was released).
    const t4 = await proposeTweet("d".repeat(40), "cs-e2e-1d");
    expect(t4.kind).toBe("allowed");
  });

  test("E2E #2a: currency mismatch denies end-to-end (no FX)", async () => {
    // Cap is in USD; the operation declares BYTES => mismatch => deny.
    await seed({ maxBytes: 1_000_000, capCurrency: "USD", declaredCurrency: "BYTES" });
    const t = await proposeTweet("hello world", "cs-e2e-2a");
    expect(t.kind).toBe("policy_denied");
    if (t.kind === "policy_denied") {
      expect(t.code).toBe(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CURRENCY_MISMATCH);
    }
  });

  test("E2E #2b: operation with no declared spend field denies end-to-end", async () => {
    // The operation carries a cumulativeSpend cap but NO spendDeclaration.
    await seed({ maxBytes: 1_000_000, declareSpendField: false });
    const t = await proposeTweet("hello world", "cs-e2e-2b");
    expect(t.kind).toBe("policy_denied");
    if (t.kind === "policy_denied") {
      expect(t.code).toBe(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_NO_SPEND_FIELD);
    }
  });

  test("E2E #3: configurable count cap (maxCalls+callWindow) denies the invoke past the cap", async () => {
    // maxCalls=2 over PT24H. Two allowed invokes record, the third denies with a
    // structured INPUT-independent cap reason (HARD_DENY). Proves the count cap
    // is WIRED end-to-end (read windowedInvokeCount + record on success).
    await seed({ maxBytes: 0, countCapMaxCalls: 2 });
    const c1 = await proposeTweet("one", "cs-e2e-3a");
    expect(c1.kind).toBe("allowed"); // count 0 < 2
    const c2 = await proposeTweet("two", "cs-e2e-3b");
    expect(c2.kind).toBe("allowed"); // count 1 < 2
    const c3 = await proposeTweet("three", "cs-e2e-3c");
    expect(c3.kind).toBe("policy_denied"); // count 2 >= 2 => deny
    if (c3.kind === "policy_denied") {
      expect(c3.code).toBe(PROVIDER_POLICY_REASON.HARD_DENY);
    }
  });

  test("E2E #4: a grant-scoped cap with NO grant (role-binding access) denies (codex P1)", async () => {
    // Access is granted via a workspace_operator role binding, so matchedGrantIds
    // is empty. A `grant`-scoped cumulativeSpend rule has no grant identity to
    // scope to => it must FAIL CLOSED, not pass under a shared empty bucket.
    await seed({ maxBytes: 1_000_000, grantScoped: true, accessViaRoleBindingNoGrant: true });
    const t = await proposeTweet("hello", "cs-e2e-4");
    expect(t.kind).toBe("policy_denied");
    if (t.kind === "policy_denied") {
      expect(t.code).toBe(PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CAP_EXCEEDED);
    }
  });

  test("#208 concurrent actions cannot cross a first-class count budget", async () => {
    await seed({ maxBytes: 1_000_000 });
    const [budget] = await getDb()
      .insert(providerAgentBudgets)
      .values({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        dimension: "count",
        windowSeconds: 86_400,
        max: 3,
        autoFreeze: true,
      })
      .returning({ id: providerAgentBudgets.id });
    if (!budget) throw new Error("expected seeded agent budget");

    // This assertion is deliberately load-bearing mutation proof: bypassing the
    // budget reservation admits all ten actions and changes the exact 3/7 split.
    const outcomes = await Promise.all(
      Array.from({ length: 10 }, (_, index) =>
        proposeTweet(`budget-${index}`, `cs-208-race-${index}`),
      ),
    );
    expect(outcomes.filter((outcome) => outcome.kind === "allowed")).toHaveLength(3);
    const denied = outcomes.filter((outcome) => outcome.kind === "policy_denied");
    expect(denied).toHaveLength(7);
    expect(denied.every((outcome) => outcome.code === "PROVIDER_AGENT_BUDGET_EXHAUSTED")).toBe(
      true,
    );

    const exhaustionEvents = await getDb()
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.action, "provider.budget.exhausted"));
    expect(exhaustionEvents).toHaveLength(7);
    expect(
      exhaustionEvents.every(
        (event) =>
          event.resourceType === "provider_action" &&
          typeof event.resourceId === "string" &&
          event.resourceId.length > 0,
      ),
    ).toBe(true);
    const freezes = await getDb()
      .select()
      .from(vaultSigningFreezes)
      .where(eq(vaultSigningFreezes.agentId, CS.AGENT));
    expect(freezes).toHaveLength(1);
    expect(freezes[0]?.liftedAt).toBeNull();
    expect(freezes[0]?.reason).toBe(`provider agent budget exhausted; budgetId=${budget.id}`);
  });

  test("#208 notional budgets debit the declared amount and denied reservations do not leak", async () => {
    await seed({ maxBytes: 1_000_000 });
    await getDb().insert(providerAgentBudgets).values({
      tenantId: CS.TENANT,
      workspaceId: CS.WORKSPACE,
      agentId: CS.AGENT,
      dimension: "notional",
      windowSeconds: 604_800,
      max: 10,
      currency: "BYTES",
    });

    expect((await proposeTweet("123456", "cs-208-notional-a")).kind).toBe("allowed");
    const crossing = await proposeTweet("12345", "cs-208-notional-b");
    expect(crossing.kind).toBe("policy_denied");
    if (crossing.kind === "policy_denied") {
      expect(crossing.code).toBe("PROVIDER_AGENT_BUDGET_EXHAUSTED");
    }
    // The rejected 5-byte reservation is removed atomically, leaving room for
    // the exact remaining four bytes.
    expect((await proposeTweet("1234", "cs-208-notional-c")).kind).toBe("allowed");
  });

  test("#208 direct retry adopts a Redis-before-PG orphan without double debit", async () => {
    await seed({ maxBytes: 1_000_000 });
    await getDb().insert(providerAgentBudgets).values({
      tenantId: CS.TENANT,
      agentId: CS.AGENT,
      dimension: "count",
      windowSeconds: 86_400,
      max: 1,
    });
    __setDecisionReservationCrashForTests(true);
    const crashed = await proposeTweet("direct-crash", "cs-208-direct-crash");
    expect(crashed).toMatchObject({
      kind: "evidence_failure",
      code: "EVIDENCE_DECISION_PERSIST_FAILED",
    });
    expect(await getDb().select().from(providerActionBindings)).toHaveLength(0);
    __setDecisionReservationCrashForTests(false);

    const retried = await proposeTweet("direct-crash", "cs-208-direct-crash");
    expect(retried.kind).toBe("allowed");
    if (retried.kind === "allowed") {
      expect(retried.intentId).toMatch(
        /^pa_[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
    }
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "budget:global:count",
        currency: "__agent_budget_count__",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 1 });
    expect(await getDb().select().from(providerActionBindings)).toHaveLength(1);
  });

  test("#208 approval resume re-debits the current budget before consumption", async () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET =
      "k1:issue-208-real-redis-test-secret-with-enough-entropy";
    await seed({ maxBytes: 1_000_000, requireApproval: true });
    await getDb().insert(providerAgentBudgets).values({
      tenantId: CS.TENANT,
      agentId: CS.AGENT,
      dimension: "count",
      windowSeconds: 86_400,
      max: 1,
    });
    const queued = await proposeTweet("queued-budget", "cs-208-queued");
    expect(queued.kind).toBe("approval_required");
    if (queued.kind !== "approval_required") throw new Error("expected approval");
    expect(
      (
        await providerApprovalService.decide({
          intentId: queued.intentId,
          tenantId: CS.TENANT,
          authenticatedUserId: CS.GRANTOR,
          sessionMfaVerifiedAt: Date.now(),
          decision: "approve",
          expectedVersion: 1,
          expectedRequestHash: queued.requestHash,
          expectedActionDigest: queued.actionDigest,
          reasonCode: null,
          reason: null,
          idempotencyKey: "cs-208-approve",
        })
      ).ok,
    ).toBe(true);

    // A different governed operation for this agent consumed the sole global
    // count slot while this action waited for its human approval.
    expect(
      await reserveCumulativeSpend({
        stream: {
          tenantId: CS.TENANT,
          agentId: CS.AGENT,
          scope: "agent",
          scopeKey: "budget:global:count",
          currency: "__agent_budget_count__",
        },
        caps: [{ windowSeconds: 86_400, max: 1 }],
        amount: 1,
        reservationId: `concurrent-budget-${RUN}`,
      }),
    ).toMatchObject({ ok: true });

    expect(
      await providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
    ).toEqual({
      ok: false,
      code: "PROVIDER_AGENT_BUDGET_EXHAUSTED",
      httpStatus: 403,
    });
    const [binding] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, queued.intentId));
    expect(binding.status).toBe("approved");
    expect(binding.executionPolicyDecision).toBeNull();
    // Resume denials are written by withTenantAuditedTransaction directly to
    // the canonical HMAC-chained audit log. The provider-action outbox is used
    // by the initial decision path and is not the resume audit sink.
    const events = await getDb()
      .select()
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, CS.TENANT),
          eq(auditEvents.resourceId, queued.intentId),
          eq(auditEvents.action, "provider.budget.exhausted"),
        ),
      );
    expect(events).toHaveLength(1);
    expect(events[0]?.metadata).toMatchObject({
      intentId: queued.intentId,
      reasonCode: "PROVIDER_AGENT_BUDGET_EXHAUSTED",
    });
  });

  test("#208 approval retry adopts an execution Redis orphan without double debit", async () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET =
      "k1:issue-208-crash-retry-test-secret-with-enough-entropy";
    await seed({ maxBytes: 1_000_000, requireApproval: true });
    await getDb().insert(providerAgentBudgets).values({
      tenantId: CS.TENANT,
      agentId: CS.AGENT,
      dimension: "count",
      windowSeconds: 86_400,
      max: 1,
    });
    const queued = await proposeTweet("approval-crash", "cs-208-approval-crash");
    if (queued.kind !== "approval_required") throw new Error("expected approval");
    const approved = await providerApprovalService.decide({
      intentId: queued.intentId,
      tenantId: CS.TENANT,
      authenticatedUserId: CS.GRANTOR,
      sessionMfaVerifiedAt: Date.now(),
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: queued.requestHash,
      expectedActionDigest: queued.actionDigest,
      reasonCode: null,
      reason: null,
      idempotencyKey: "cs-208-approval-crash-approve",
    });
    expect(approved.ok).toBe(true);

    providerApprovalService.faultHooks.afterPolicyReserveCrash = () => {
      throw new Error("simulated process death after execution reserve");
    };
    expect(
      await providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
    ).toEqual({ ok: false, code: "RESUME_PREPARATION_FAILED", httpStatus: 503 });
    providerApprovalService.faultHooks = {};
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "budget:global:count",
        currency: "__agent_budget_count__",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 1 });

    expect(
      await providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
    ).toMatchObject({ ok: true, status: "execution_ready" });
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "budget:global:count",
        currency: "__agent_budget_count__",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 1 });
  });

  test("#240 crash after terminal commit: C2 settles persisted handles exactly once under a worker race", async () => {
    await seed({ maxBytes: 250 });
    __setReservationReconciliationFaultForTests("before_apply");
    const out = await proposeTweet("settled-spend", "cs-240-settle");
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error("expected allowed");
    const [binding] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, out.intentId));
    expect(binding.status).toBe("stub_succeeded");
    const [crashed] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(crashed.state).toBe("pending");
    expect(crashed.attempts).toBe(1);
    expect(crashed.lastError).toContain("injected crash");
    expect(crashed.nextRetryAt).not.toBeNull();
    expect(crashed.handles).toMatchObject({
      schemaVersion: "steward.provider-policy-reservations.v2",
      generation: 1,
      phase: "decision",
      cumulativeSpend: [{ amount: 13 }],
    });
    expect(JSON.stringify(crashed.handles)).not.toContain("settled-spend");

    __setReservationReconciliationFaultForTests(null);
    // A scoped replay must honor persisted exponential backoff too. Make the
    // crash row due before racing two workers; exactly one SKIP LOCKED claim wins.
    await getDb()
      .update(providerActionReservationGenerations)
      .set({ nextRetryAt: new Date(0) })
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    const [a, b] = await Promise.all([
      providerActionService.reconcilePolicyReservations(CS.TENANT, out.intentId),
      providerActionService.reconcilePolicyReservations(CS.TENANT, out.intentId),
    ]);
    expect(a + b).toBe(1);
    const [done] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(done.state).toBe("settled");
    expect(done.reconciledAt).not.toBeNull();
  });

  test("#240 crash before release: C2 reclaims failed spend and maxCalls reservations", async () => {
    await seed({
      maxBytes: 250,
      extraDenyRule: true,
      countCapMaxCalls: 5,
      combineCountAndSpend: true,
    });
    __setReservationReconciliationFaultForTests("before_apply");
    const out = await proposeTweet("known-failure", "cs-240-release");
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error("expected denial");
    const [crashed] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(crashed.state).toBe("pending");
    expect(crashed.attempts).toBe(1);
    expect(crashed.handles).toMatchObject({
      cumulativeSpend: [{ amount: 13 }],
      windowedInvoke: { agentId: CS.AGENT, operationKey: OP_TWEET_KEY },
    });
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "BYTES",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 13 });

    __setReservationReconciliationFaultForTests(null);
    await getDb()
      .update(providerActionReservationGenerations)
      .set({ nextRetryAt: new Date(0) })
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(await providerActionService.recoverUnsignedIntents(CS.TENANT, out.intentId)).toBe(0);
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "BYTES",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 0 });
    const [done] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(done.state).toBe("released");
  });

  test("#240 crash after Redis release but before CAS is idempotently recovered", async () => {
    await seed({ maxBytes: 250, extraDenyRule: true });
    __setReservationReconciliationFaultForTests("after_apply");
    const out = await proposeTweet("released-once", "cs-240-after-redis");
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error("expected denial");
    const [crashed] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(crashed.state).toBe("pending");
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "BYTES",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 0 });

    __setReservationReconciliationFaultForTests(null);
    // The unscoped entry point is what the autonomous startup/periodic worker
    // invokes. Make the retry due, then prove it recovers across all tenants.
    await getDb()
      .update(providerActionReservationGenerations)
      .set({ nextRetryAt: new Date(0) })
      .where(eq(providerActionReservationGenerations.intentId, out.intentId));
    expect(await providerActionService.reconcilePolicyReservations()).toBe(1);
    expect(await providerActionService.reconcilePolicyReservations(CS.TENANT, out.intentId)).toBe(
      0,
    );
  });

  test("#239 execute-time cap crossing denies without consuming the approval", async () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET =
      "k1:issue-239-real-redis-test-secret-with-enough-entropy";
    await seed({ maxBytes: 100, requireApproval: true });
    const queued = await proposeTweet("q".repeat(60), "cs-239-queued");
    expect(queued.kind).toBe("approval_required");
    if (queued.kind !== "approval_required") throw new Error("expected approval");
    const approved = await providerApprovalService.decide({
      intentId: queued.intentId,
      tenantId: CS.TENANT,
      authenticatedUserId: CS.GRANTOR,
      sessionMfaVerifiedAt: Date.now(),
      decision: "approve",
      expectedVersion: 1,
      expectedRequestHash: queued.requestHash,
      expectedActionDigest: queued.actionDigest,
      reasonCode: null,
      reason: null,
      idempotencyKey: "cs-239-approve",
    });
    expect(approved.ok).toBe(true);

    // Another operation for this agent consumes 80/100 from the same global
    // agent stream while the queued action waits. Keep the approved operation's
    // revision unchanged so dependency revalidation succeeds and the test reaches
    // the execute-time cap gate rather than merely testing stale approval.
    expect(
      await reserveCumulativeSpend({
        stream: {
          tenantId: CS.TENANT,
          agentId: CS.AGENT,
          scope: "agent",
          scopeKey: "",
          currency: "BYTES",
        },
        caps: [{ windowSeconds: 86_400, max: 100 }],
        amount: 80,
        reservationId: `concurrent-${RUN}`,
      }),
    ).toMatchObject({ ok: true });

    const denied = await providerApprovalService.resume({
      intentId: queued.intentId,
      tenantId: CS.TENANT,
    });
    expect(denied).toEqual({
      ok: false,
      code: PROVIDER_POLICY_REASON.CUMULATIVE_SPEND_CAP_EXCEEDED,
      httpStatus: 403,
    });
    const [binding] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, queued.intentId));
    expect(binding.status).toBe("approved");
    expect(binding.executionPolicyDecision).toBeNull();
    const [queue] = await getDb()
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.intentId, queued.intentId));
    expect(queue.status).toBe("approved");
  });

  test("#239 execute reservation rollback is reclaimed and concurrent resumes create one generation", async () => {
    process.env.STEWARD_EXECUTION_AUTH_SECRET =
      "k1:issue-239-real-redis-test-secret-with-enough-entropy";
    await seed({
      maxBytes: 100,
      requireApproval: true,
      countCapMaxCalls: 2,
      combineCountAndSpend: true,
    });
    const queued = await proposeTweet("approved", "cs-239-race");
    expect(queued.kind).toBe("approval_required");
    if (queued.kind !== "approval_required") throw new Error("expected approval");
    expect(
      (
        await providerApprovalService.decide({
          intentId: queued.intentId,
          tenantId: CS.TENANT,
          authenticatedUserId: CS.GRANTOR,
          sessionMfaVerifiedAt: Date.now(),
          decision: "approve",
          expectedVersion: 1,
          expectedRequestHash: queued.requestHash,
          expectedActionDigest: queued.actionDigest,
          reasonCode: null,
          reason: null,
          idempotencyKey: "cs-239-race-approve",
        })
      ).ok,
    ).toBe(true);

    // Throw after Redis admission but before the audited PG transaction commits.
    // The outer compensation releases both spend and count handles, and no
    // append-only execution generation may leak from the rolled-back tx.
    providerApprovalService.faultHooks.afterPolicyReserve = () => {
      throw new Error("injected crash after execute reserve");
    };
    expect(
      await providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
    ).toEqual({ ok: false, code: "RESUME_PREPARATION_FAILED", httpStatus: 503 });
    providerApprovalService.faultHooks = {};
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "BYTES",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 0 });
    expect(
      (
        await getDb()
          .select()
          .from(providerActionReservationGenerations)
          .where(eq(providerActionReservationGenerations.intentId, queued.intentId))
      ).map((row) => row.generation),
    ).toEqual([1]);

    const [first, second] = await Promise.all([
      providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
      providerApprovalService.resume({ intentId: queued.intentId, tenantId: CS.TENANT }),
    ]);
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    const generations = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, queued.intentId));
    expect(generations.map((row) => [row.generation, row.phase])).toEqual([
      [1, "decision"],
      [2, "execution"],
    ]);
    expect(generations[1]?.state).toBe("pending");
    expect(
      await getCumulativeSpendSum({
        tenantId: CS.TENANT,
        agentId: CS.AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "BYTES",
        windowSeconds: 86_400,
      }),
    ).toEqual({ sum: 8 });
  });
});

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
import { PROVIDER_POLICY_REASON } from "@stwd/policy-engine";
import { buildXAction } from "@stwd/provider-x";
import { disconnectRedis, getRedis } from "@stwd/redis";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";

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
  let cursor = "0";
  do {
    const [next, keys] = await redis.scan(cursor, "MATCH", `cumspend:${CS.AGENT}*`, "COUNT", 100);
    cursor = next;
    if (keys.length > 0) await redis.del(...keys);
  } while (cursor !== "0");
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
      opts.countCapMaxCalls !== undefined
        ? countCapRules(OP_TWEET_KEY, opts.countCapMaxCalls)
        : spendCapRules(OP_TWEET_KEY, opts.maxBytes, opts.capCurrency ?? "BYTES"),
  };
  if (opts.countCapMaxCalls === undefined && opts.declareSpendField !== false) {
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
    await wipe();
    await cleanupRedis();
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
});

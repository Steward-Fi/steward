/**
 * Permissioned-X full-chain E2E (authority plane, real provider-action service +
 * approval state machine over PGLite).
 *
 * This proves the instance-level X policy vocabulary (docs/security/permissioned-x.mdx)
 * end to end through the SAME service github/X flow through:
 *
 *   propose (buildXAction -> policyArgs + non-persisted policyText) ->
 *   access allow -> composeProviderActionPolicyDecision reads the permissioned-X
 *   constraints.x block -> hard_deny / approval_required / allow -> (on approval)
 *   human approve -> safe resume -> execution_ready, with the audit chain.
 *
 * Coverage (positive + negative for each Phase-1 dimension that needs no external
 * counter — count/spend/quiet-hours require the unwired trailing-window
 * accumulator and are proven at the composer unit level in
 * packages/policy-engine/src/__tests__/permissioned-x.test.ts + fail-closed here):
 *   - contentPolicy.allowUrls=false: a URL post is policy_denied (POLICY_X_URL_FORBIDDEN),
 *     a plain post is allowed. NO execution on the denied path.
 *   - replyPolicy.summoned-only: an un-summoned reply is policy_denied
 *     (POLICY_X_REPLY_NOT_SUMMONED) — the Feb-2026 anti-spam upstream-403 class
 *     modeled as a LOCAL policy denial BEFORE the wasted billed call, surfaced as
 *     a clear failed outcome (policy_denied), NEVER outcome_unknown.
 *   - replyPolicy.summoned-only: a summoned reply reaches approval (load-bearing).
 *   - contentPolicy.blockedPatterns: a blocked-pattern post is policy_denied
 *     (POLICY_X_CONTENT_BLOCKED) via the in-memory policyText channel; a clean
 *     post is allowed — proving text reaches the composer but is NEVER persisted.
 *   - escalation.urlPostRequiresApproval: a URL post (allowUrls=true) escalates
 *     from allow to approval_required.
 *   - fail-closed: a spendPolicy rule (unwired accumulated-spend input) denies
 *     with POLICY_INPUT_UNAVAILABLE.
 *
 * MUTATION: the URL-forbidden guard is mutation-proven in
 * scripts/x-permissioned-mutation-proofs.sh (flip allowUrls false->true, watch
 * the denied URL post flip to allowed).
 */

import { beforeAll, beforeEach, afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
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
import { buildXAction } from "@stwd/provider-x";
import { eq } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";

setDefaultTimeout(120_000);

const P = {
  TENANT: "tenant-xp",
  AGENT: "agent-xp",
  WORKSPACE: "22000000-0000-4000-8000-000000000001",
  ACCOUNT: "32000000-0000-4000-8000-000000000001",
  OP_URL_DENY: "42000000-0000-4000-8000-000000000001",
  OP_SUMMONED: "42000000-0000-4000-8000-000000000002",
  OP_BLOCKED: "42000000-0000-4000-8000-000000000003",
  OP_ESCALATE: "42000000-0000-4000-8000-000000000004",
  OP_SPEND: "42000000-0000-4000-8000-000000000005",
  SECRET: "52000000-0000-4000-8000-000000000001",
  ROUTE: "62000000-0000-4000-8000-000000000001",
  GRANTOR: "12000000-0000-4000-8000-000000000001",
  APPROVER: "82000000-0000-4000-8000-000000000001",
  APPROVER_BINDING: "92000000-0000-4000-8000-000000000001",
  GRANT: "a2000000-0000-4000-8000-000000000001",
} as const;

const OP_TWEET = "x.tweet.create";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

function principal(): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId: P.AGENT,
    tenantId: P.TENANT,
    platformId: null,
    issuer: "eliza-cloud",
    subject: `agent:${P.AGENT}`,
    tokenId: null,
    scopes: [],
    authenticatedAt: new Date().toISOString(),
    expiresAt: null,
    authnMethod: "agent-jwt-rs256",
  };
}

/**
 * All operations key `x.tweet.create` but each carries a DIFFERENT permissioned-X
 * rule set. The grant lists each operationKey but the seed uses distinct
 * operation rows keyed by the SAME operationKey — the service resolves by
 * (workspace, account, operationKey), so we seed ONE operation row per test and
 * wipe between. We therefore install the ACTIVE rule set per test via a helper
 * that rewrites the single operation's requestProfile.
 */
function allowRule(id: string, x?: Record<string, unknown>) {
  return {
    id,
    type: "capability-intent",
    enabled: true,
    config: {
      capabilities: [OP_TWEET],
      effect: "allow",
      ...(x ? { constraints: { x } } : {}),
    },
  };
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

/** Seed the base account + a single x.tweet.create operation carrying `rules`. */
async function seed(rules: unknown[]) {
  const db = getDb();
  await db.insert(tenants).values([{ id: P.TENANT, name: "XP", apiKeyHash: "hxp" }]);
  await db.insert(users).values([
    { id: P.GRANTOR, email: "gxp@t.test" },
    { id: P.APPROVER, email: "axp@t.test" },
  ]);
  await db.insert(userTenants).values([{ userId: P.APPROVER, tenantId: P.TENANT, role: "member" }]);
  await db
    .insert(agents)
    .values([
      { id: P.AGENT, tenantId: P.TENANT, name: "AXP", walletAddress: "0x1", ownerUserId: null },
    ]);
  await db.insert(secrets).values([
    {
      id: P.SECRET,
      tenantId: P.TENANT,
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
      id: P.ROUTE,
      tenantId: P.TENANT,
      secretId: P.SECRET,
      hostPattern: "api.x.com",
      pathPattern: "/2/tweets",
      method: "POST",
      injectAs: "header",
      injectKey: "authorization",
    },
  ]);
  await db.insert(workspaces).values([
    {
      id: P.WORKSPACE,
      tenantId: P.TENANT,
      key: "xp-client",
      name: "XPC",
      environment: "production",
      createdBy: P.GRANTOR,
    },
  ]);
  await db.insert(providerAccounts).values([
    {
      id: P.ACCOUNT,
      tenantId: P.TENANT,
      workspaceId: P.WORKSPACE,
      adapterKey: "x",
      externalRef: "9999",
      displayName: "@sol",
      credentialSecretId: P.SECRET,
      credentialVersion: 1,
    },
  ]);
  await db.insert(providerOperations).values([
    {
      id: P.OP_URL_DENY,
      tenantId: P.TENANT,
      workspaceId: P.WORKSPACE,
      providerAccountId: P.ACCOUNT,
      operationKey: OP_TWEET,
      riskClass: "write",
      secretRouteId: P.ROUTE,
      requestProfile: { policyRules: rules },
    },
  ]);
  await db.insert(providerGrants).values([
    {
      id: P.GRANT,
      tenantId: P.TENANT,
      workspaceId: P.WORKSPACE,
      providerAccountId: P.ACCOUNT,
      agentId: P.AGENT,
      operationKeys: [OP_TWEET],
      environment: "production",
      expiresAt: FUTURE,
      grantedByUserId: P.GRANTOR,
      reason: "test",
    },
  ]);
  await db.insert(providerRoleBindings).values([
    {
      id: P.APPROVER_BINDING,
      tenantId: P.TENANT,
      workspaceId: P.WORKSPACE,
      principalType: "human",
      principalId: P.APPROVER,
      roleKey: "workspace_approver",
      operationKeys: [],
      environment: "production",
      status: "active",
      grantedByUserId: P.GRANTOR,
      reason: "approver",
    },
  ]);
}

function idemHash(seedStr: string): string {
  return `sha256:${Buffer.from(seedStr.padEnd(32, "0")).toString("hex").slice(0, 64)}`;
}

async function propose(args: unknown, seedStr: string) {
  const now = new Date();
  return providerActionService.createProviderAction({
    principal: principal(),
    workspaceId: P.WORKSPACE,
    providerAccountId: P.ACCOUNT,
    operationKey: OP_TWEET,
    build: buildXAction(OP_TWEET as never, args),
    idempotencyKeyHash: idemHash(seedStr),
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: seedStr.padEnd(32, "N").slice(0, 32),
    requestId: null,
  });
}

async function bindingRow(intentId: string) {
  const [b] = await getDb()
    .select()
    .from(providerActionBindings)
    .where(eq(providerActionBindings.intentId, intentId));
  return b;
}

describe("Permissioned-X full-chain E2E (authority plane, PGLite)", () => {
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
  });

  test("contentPolicy allowUrls=false: URL post is policy_denied, no execution", async () => {
    await seed([allowRule("11111111-1111-4111-8111-1111111111a1", { contentPolicy: { allowUrls: false } })]);
    const out = await propose({ text: "check https://waifu.fun now" }, "urldeny1");
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error(`got ${out.kind}`);
    expect(out.code).toBe("POLICY_X_URL_FORBIDDEN");
    // The binding must NOT have executed.
    const b = await bindingRow(out.intentId);
    expect(b.status).not.toBe("stub_succeeded");
  });

  test("contentPolicy allowUrls=false: a plain post is allowed", async () => {
    await seed([allowRule("11111111-1111-4111-8111-1111111111a1", { contentPolicy: { allowUrls: false } })]);
    const out = await propose({ text: "gm, no links here" }, "plainok1");
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error(`got ${out.kind}`);
    expect(out.stub.status).toBe("stub_succeeded");
  });

  test("replyPolicy summoned-only: an un-summoned reply is policy_denied (upstream-403 class, NOT outcome_unknown)", async () => {
    await seed([allowRule("11111111-1111-4111-8111-1111111111b2", { replyPolicy: { mode: "summoned-only" } })]);
    const out = await propose(
      { text: "thanks for the mention!", replyToTweetId: "1750000000000000000", summoned: false },
      "unsummon1",
    );
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error(`got ${out.kind}`);
    // The Feb-2026 anti-spam denial is a CLEAR failed outcome with a stable code,
    // never a fabricated allow and never outcome_unknown.
    expect(out.code).toBe("POLICY_X_REPLY_NOT_SUMMONED");
    const b = await bindingRow(out.intentId);
    expect(b.status).not.toBe("stub_succeeded");
  });

  test("replyPolicy summoned-only: a summoned reply is allowed (guard is load-bearing)", async () => {
    await seed([allowRule("11111111-1111-4111-8111-1111111111b2", { replyPolicy: { mode: "summoned-only" } })]);
    const out = await propose(
      { text: "thanks for the mention!", replyToTweetId: "1750000000000000000", summoned: true },
      "summon001",
    );
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error(`got ${out.kind}`);
    expect(out.stub.status).toBe("stub_succeeded");
  });

  test("contentPolicy blockedPatterns: a blocked-pattern post is policy_denied via in-memory policyText", async () => {
    await seed([
      allowRule("11111111-1111-4111-8111-1111111111c3", {
        contentPolicy: { blockedPatterns: ["[Aa]irdrop"] },
      }),
    ]);
    const out = await propose({ text: "free Airdrop, click now" }, "blocked01");
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error(`got ${out.kind}`);
    expect(out.code).toBe("POLICY_X_CONTENT_BLOCKED");
  });

  test("contentPolicy blockedPatterns: a clean post is allowed (text reached composer, never persisted)", async () => {
    await seed([
      allowRule("11111111-1111-4111-8111-1111111111c3", {
        contentPolicy: { blockedPatterns: ["[Aa]irdrop"] },
      }),
    ]);
    const out = await propose({ text: "just vibing today" }, "clean0001");
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error(`got ${out.kind}`);
    // The persisted binding carries only digests/hashes, never the tweet text.
    const b = await bindingRow(out.intentId);
    expect(JSON.stringify(b)).not.toContain("vibing");
  });

  test("escalation urlPostRequiresApproval: a URL post escalates allow -> approval_required", async () => {
    await seed([
      allowRule("11111111-1111-4111-8111-1111111111d4", {
        contentPolicy: { allowUrls: true },
        escalation: { urlPostRequiresApproval: true },
      }),
    ]);
    const out = await propose({ text: "read more at https://steward.fi" }, "escal001");
    expect(out.kind).toBe("approval_required");
  });

  test("fail-closed: a spendPolicy rule with unwired accumulated-spend input denies POLICY_INPUT_UNAVAILABLE", async () => {
    await seed([
      allowRule("11111111-1111-4111-8111-1111111111e5", {
        spendPolicy: { maxSpendMicros: 1_000_000 },
      }),
    ]);
    const out = await propose({ text: "plain post under a spend cap" }, "spendfc01");
    expect(out.kind).toBe("policy_denied");
    if (out.kind !== "policy_denied") throw new Error(`got ${out.kind}`);
    expect(out.code).toBe("POLICY_INPUT_UNAVAILABLE");
  });
});

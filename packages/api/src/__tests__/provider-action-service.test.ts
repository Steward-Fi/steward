/**
 * provider-action-service integration tests (PGLite).
 *
 * Exercises the full canonical-action authority pipeline through the real service against a
 * migrated PGLite database: scope resolution, access + policy separation,
 * transactional persistence, the required-audit outbox, idempotent replay,
 * client-B isolation, and the in-process stub boundary. Proves the spec §9
 * effectiveness claims that need a real DB.
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
  closeDb,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerGrants,
  providerOperations,
  secretRoutes,
  secrets,
  tenants,
  users,
  workspaces,
} from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { buildGithubAction } from "@stwd/provider-github";
import {
  __resetSecurityMetricsForTests,
  __setSecurityMetricsObserverFailureForTests,
  computeActionDigest,
  renderSecurityMetrics,
} from "@stwd/shared";
import { eq, sql } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import { providerActionService } from "../services/provider-action-service";

setDefaultTimeout(120_000);

const TENANT = "tenant-main";
const AGENT = "agent-x";
const AGENT_Y = "agent-y";
const WORKSPACE_A = "20000000-0000-4000-8000-000000000001";
const WORKSPACE_B = "20000000-0000-4000-8000-000000000002";
const ACCOUNT_A = "30000000-0000-4000-8000-000000000001";
const ACCOUNT_B = "30000000-0000-4000-8000-000000000002";
const OP_A_READ = "40000000-0000-4000-8000-000000000001";
const OP_A_WRITE = "40000000-0000-4000-8000-000000000002";
const OP_B_READ = "40000000-0000-4000-8000-000000000003";
const GRANTOR = "10000000-0000-4000-8000-000000000001";
const SECRET_A = "50000000-0000-4000-8000-000000000001";
const ROUTE_A = "60000000-0000-4000-8000-000000000001";
const FUTURE = new Date(Date.now() + 365 * 24 * 3600_000);

function principal(agentId = AGENT): ProviderPrincipalV1 {
  return {
    type: "agent",
    agentId,
    tenantId: TENANT,
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

function input(
  overrides: Partial<Parameters<typeof providerActionService.createProviderAction>[0]> = {},
) {
  const now = new Date();
  return {
    principal: principal(),
    workspaceId: WORKSPACE_A,
    providerAccountId: ACCOUNT_A,
    operationKey: "github.issue.list",
    build: buildGithubAction("github.issue.list", { owner: "octo", repo: "hello" }),
    idempotencyKeyHash: `sha256:${"a".repeat(64)}`,
    requestedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + 300_000).toISOString(),
    nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    requestId: null,
    ...overrides,
  };
}

async function seedCore() {
  const db = getDb();
  await db.insert(tenants).values([{ id: TENANT, name: "Main", apiKeyHash: "h" }]);
  await db.insert(users).values([{ id: GRANTOR, email: "g@t.test" }]);
  await db.insert(agents).values([
    { id: AGENT, tenantId: TENANT, name: "X", walletAddress: "0x1" },
    { id: AGENT_Y, tenantId: TENANT, name: "Y", walletAddress: "0x2" },
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
    {
      id: WORKSPACE_B,
      tenantId: TENANT,
      key: "client-b",
      name: "B",
      environment: "production",
      createdBy: GRANTOR,
    },
  ]);
  // A secret + route so the approval-lifecycle approval commitment can bind route/credential
  // revisions (spec §5.2: missing route/credential fails approval creation).
  await db.insert(secrets).values([
    {
      id: SECRET_A,
      tenantId: TENANT,
      name: "github-a",
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
      version: 1,
    },
  ]);
  await db.insert(secretRoutes).values([
    {
      id: ROUTE_A,
      tenantId: TENANT,
      secretId: SECRET_A,
      hostPattern: "api.github.com",
      pathPattern: "/*",
      method: "*",
      injectAs: "header",
      injectKey: "authorization",
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
      credentialSecretId: SECRET_A,
      credentialVersion: 1,
    },
    {
      id: ACCOUNT_B,
      tenantId: TENANT,
      workspaceId: WORKSPACE_B,
      adapterKey: "github",
      externalRef: "b",
      displayName: "B",
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
      secretRouteId: ROUTE_A,
    },
    {
      id: OP_A_WRITE,
      tenantId: TENANT,
      workspaceId: WORKSPACE_A,
      providerAccountId: ACCOUNT_A,
      operationKey: "github.pr.comment.create",
      riskClass: "consequential",
      secretRouteId: ROUTE_A,
    },
    {
      id: OP_B_READ,
      tenantId: TENANT,
      workspaceId: WORKSPACE_B,
      providerAccountId: ACCOUNT_B,
      operationKey: "github.issue.list",
      riskClass: "read",
    },
  ]);
}

async function grantAgent(
  agentId: string,
  workspaceId: string,
  accountId: string,
  operationKeys: string[],
) {
  await getDb().insert(providerGrants).values({
    tenantId: TENANT,
    workspaceId,
    providerAccountId: accountId,
    agentId,
    operationKeys,
    environment: "production",
    expiresAt: FUTURE,
    grantedByUserId: GRANTOR,
    reason: "test",
  });
}

async function setOpPolicyRules(opId: string, rules: unknown[]) {
  await getDb()
    .update(providerOperations)
    .set({ requestProfile: { policyRules: rules } })
    .where(eq(providerOperations.id, opId));
}

async function auditCount(): Promise<number> {
  const rows = await getDb().execute(
    sql`SELECT count(*)::int AS n FROM audit_events WHERE tenant_id = ${TENANT}`,
  );
  const arr = Array.isArray(rows) ? rows : ((rows as { rows?: unknown[] }).rows ?? []);
  return Number((arr[0] as { n: number }).n);
}

function hhmm(minute: number): string {
  const normalized = ((minute % 1440) + 1440) % 1440;
  return `${String(Math.floor(normalized / 60)).padStart(2, "0")}:${String(normalized % 60).padStart(2, "0")}`;
}

const ALL_DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

describe("provider-action service pipeline", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY ||= "0".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await seedCore();
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  beforeEach(async () => {
    __resetSecurityMetricsForTests();
    const db = getDb();
    await db.delete(providerActionAuditOutbox);
    await db.delete(providerActionBindings);
    await db.delete(intents);
    await db.delete(providerGrants);
    await db.update(providerOperations).set({ requestProfile: {} });
  });

  test("scope not found: unresolved operation writes required audit, creates NO intent", async () => {
    const before = await auditCount();
    const out = await providerActionService.createProviderAction(
      input({
        operationKey: "github.issue.list",
        providerAccountId: "30000000-0000-4000-8000-0000000000ff",
      }),
    );
    expect(out.kind).toBe("scope_not_found");
    // No binding row created.
    const bindings = await getDb().select().from(providerActionBindings);
    expect(bindings.length).toBe(0);
    // Required denial audit DID write.
    expect(await auditCount()).toBe(before + 1);
  });

  test("#207 server-time business window is enforced end to end and is load-bearing", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    const now = new Date();
    const minute = now.getUTCHours() * 60 + now.getUTCMinutes();
    const rules = (from: string, to: string) => [
      {
        id: "20700000-0000-4000-8000-000000000001",
        type: "capability-intent",
        enabled: true,
        config: {
          capabilities: ["github.issue.list"],
          effect: "allow",
          constraints: { timeWindow: { timezone: "UTC", allow: [{ days: ALL_DAYS, from, to }] } },
        },
      },
    ];

    // A narrow window containing the current server minute allows.
    await setOpPolicyRules(OP_A_READ, rules(hhmm(minute - 1), hhmm(minute + 2)));
    const allowed = await providerActionService.createProviderAction(input());
    expect(allowed.kind).toBe("allowed");

    await getDb().delete(providerActionAuditOutbox);
    await getDb().delete(providerActionBindings);
    await getDb().delete(intents);

    // Mutation proof: moving the same window just ahead of server time denies.
    await setOpPolicyRules(OP_A_READ, rules(hhmm(minute + 2), hhmm(minute + 4)));
    const denied = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"b".repeat(64)}` }),
    );
    expect(denied.kind).toBe("policy_denied");
  });

  test("metrics observer failure cannot change a real governed denial decision", async () => {
    __setSecurityMetricsObserverFailureForTests(true);
    const before = await auditCount();
    const out = await providerActionService.createProviderAction(
      input({
        operationKey: "github.issue.list",
        providerAccountId: "30000000-0000-4000-8000-0000000000ff",
      }),
    );
    expect(out.kind).toBe("scope_not_found");
    expect(await auditCount()).toBe(before + 1);
  });

  test("access deny (no grant): creates intent + binding with policy not_evaluated", async () => {
    const out = await providerActionService.createProviderAction(input());
    expect(out.kind).toBe("access_denied");
    if (out.kind !== "access_denied") throw new Error("unreachable");
    expect(out.code).toBe("GRANT_ABSENT");
    const [b] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, out.intentId));
    expect(b.accessEffect).toBe("deny");
    expect(b.policyEffect).toBe("not_evaluated");
    expect(b.status).toBe("denied");
    expect(b.policyDecisionId).toBeNull();
    // access + policy decision documents are DISTINCT: policy is null here.
    expect(b.policyDecision).toBeNull();
    expect(b.accessDecisionHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    // The real composed service -> outbox -> durable audit path feeds only the
    // bounded reason class, never the raw grant reason or principal metadata.
    const metrics = renderSecurityMetrics();
    expect(metrics).toContain('reason_class="access"} 1');
    expect(metrics).not.toContain("GRANT_ABSENT");
    expect(metrics).not.toContain(AGENT);
  });

  test("allow: grant present, no governing policy denies (default deny) unless allow rule present", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    // No policy rules on the op => POLICY_NO_GOVERNING_ALLOW (hard deny).
    const denied = await providerActionService.createProviderAction(input());
    expect(denied.kind).toBe("policy_denied");
    if (denied.kind !== "policy_denied") throw new Error("unreachable");
    expect(denied.code).toBe("POLICY_NO_GOVERNING_ALLOW");

    // Add an allow rule that governs the op => allow + stub called.
    await setOpPolicyRules(OP_A_READ, [
      {
        id: "11111111-1111-4111-8111-111111111111",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "allow" },
      },
    ]);
    const allowed = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"b".repeat(64)}` }),
    );
    expect(allowed.kind).toBe("allowed");
    if (allowed.kind !== "allowed") throw new Error("unreachable");
    expect(allowed.stub.status).toBe("stub_succeeded");
    const [b] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, allowed.intentId));
    expect(b.status).toBe("stub_succeeded");
    expect(b.accessEffect).toBe("allow");
    expect(b.policyEffect).toBe("allow");
    // Distinct decision IDs/hashes.
    expect(b.accessDecisionId).not.toBe(b.policyDecisionId);
    expect(b.policyDecisionHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("hard deny cannot become approval: allow + require-approval => approval; deny + approval => hard_deny", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    // allow + require-approval => approval_required
    await setOpPolicyRules(OP_A_READ, [
      {
        id: "11111111-1111-4111-8111-111111111111",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "allow" },
      },
      {
        id: "22222222-2222-4222-8222-222222222222",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "require-approval" },
      },
    ]);
    const appr = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"c".repeat(64)}` }),
    );
    expect(appr.kind).toBe("approval_required");

    // deny + require-approval => hard_deny (deny wins)
    await setOpPolicyRules(OP_A_READ, [
      {
        id: "33333333-3333-4333-8333-333333333333",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "deny" },
      },
      {
        id: "22222222-2222-4222-8222-222222222222",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "require-approval" },
      },
    ]);
    const den = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"d".repeat(64)}` }),
    );
    expect(den.kind).toBe("policy_denied");
    if (den.kind !== "policy_denied") throw new Error("unreachable");
    expect(den.code).toBe("POLICY_HARD_DENY");
  });

  test("idempotent replay: same key + same action returns existing intent; different action conflicts", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    await setOpPolicyRules(OP_A_READ, [
      {
        id: "11111111-1111-4111-8111-111111111111",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "allow" },
      },
    ]);
    const key = `sha256:${"e".repeat(64)}`;
    const first = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: key }),
    );
    expect(first.kind).toBe("allowed");
    if (first.kind !== "allowed") throw new Error("unreachable");
    const replay = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: key }),
    );
    expect(replay.kind).toBe("allowed");
    if (replay.kind !== "allowed") throw new Error("unreachable");
    expect(replay.intentId).toBe(first.intentId);
    // Same key, DIFFERENT action (different repo) => conflict.
    const conflict = await providerActionService.createProviderAction(
      input({
        idempotencyKeyHash: key,
        build: buildGithubAction("github.issue.list", { owner: "octo", repo: "other" }),
      }),
    );
    expect(conflict.kind).toBe("replay_conflict");
  });

  test("client-B isolation: a grant on A does not authorize the same op on B", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    const out = await providerActionService.createProviderAction(
      input({
        workspaceId: WORKSPACE_B,
        providerAccountId: ACCOUNT_B,
        idempotencyKeyHash: `sha256:${"f".repeat(64)}`,
      }),
    );
    expect(out.kind).toBe("access_denied");
    if (out.kind !== "access_denied") throw new Error("unreachable");
    expect(out.code).toBe("GRANT_ABSENT");
  });

  test("required-audit outbox drains: an allow leaves a delivered outbox row and a chained audit event", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    await setOpPolicyRules(OP_A_READ, [
      {
        id: "11111111-1111-4111-8111-111111111111",
        type: "capability-intent",
        enabled: true,
        config: { capabilities: ["github.issue.list"], effect: "allow" },
      },
    ]);
    const before = await auditCount();
    const out = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"1".repeat(64)}` }),
    );
    expect(out.kind).toBe("allowed");
    if (out.kind !== "allowed") throw new Error("unreachable");
    const outbox = await getDb()
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.intentId, out.intentId));
    expect(outbox.length).toBe(1);
    expect(outbox[0].deliveredAt).not.toBeNull();
    expect(await auditCount()).toBe(before + 1);
  });

  test("replay of a stuck allowed_stub binding COMPLETES it (never fabricates stub_succeeded)", async () => {
    // A binding stuck in allowed_stub represents the original request crashing
    // between decision-commit and the stub transition. The immutability trigger
    // makes allowed_stub reachable ONLY on INSERT (not by reverting a terminal
    // row), so we seed one directly to model the crash, then replay through the
    // service. Replay MUST drive the stub to completion, never report a fabricated
    // stub_succeeded from the stale row.
    const db = getDb();
    const intentId = `pa_${crypto.randomUUID()}`;
    const key = `sha256:${"7".repeat(64)}`;
    const build = buildGithubAction("github.issue.list", { owner: "octo", repo: "hello" });
    // The seeded binding's action digest MUST match what the replay recomputes,
    // otherwise the reused key is (correctly) a replay conflict.
    const realDigest = computeActionDigest(build.action);
    await db.insert(intents).values({
      id: intentId,
      tenantId: TENANT,
      agentId: AGENT,
      intentType: "provider-action",
      status: "authorized",
      resourceType: "provider-action",
      resourceId: OP_A_READ,
      createdByType: "agent",
      createdById: AGENT,
      payload: {},
      expiresAt: FUTURE,
    });
    await db.insert(providerActionBindings).values({
      intentId,
      tenantId: TENANT,
      workspaceId: WORKSPACE_A,
      actorAgentId: AGENT,
      providerAccountId: ACCOUNT_A,
      operationId: OP_A_READ,
      operationRevision: 1,
      canonicalProfile: build.action.profile,
      canonicalActionBytes: Buffer.from("xy", "utf8"),
      actionDigest: realDigest,
      requestEnvelope: {},
      requestHash: `sha256:${"b".repeat(64)}`,
      idempotencyKeyHash: key,
      safeSummary: {},
      accessDecisionId: crypto.randomUUID(),
      accessEffect: "allow",
      accessReasonCode: "provider_access_allowed",
      matchedBindingIds: [],
      matchedGrantIds: [],
      dependencyRevisions: {},
      accessDecision: {},
      accessDecisionHash: `sha256:${"c".repeat(64)}`,
      policyDecisionId: crypto.randomUUID(),
      policyEffect: "allow",
      policyReasonCodes: ["POLICY_ALLOW"],
      policyResults: [],
      policyRevisionHash: `sha256:${"d".repeat(64)}`,
      policyDecision: {},
      policyDecisionHash: `sha256:${"e".repeat(64)}`,
      status: "allowed_stub",
    });
    // Enqueue the required-audit outbox row so the replay's drain can complete.
    await db.insert(providerActionAuditOutbox).values({
      tenantId: TENANT,
      intentId,
      action: "provider.action.allowed",
      resourceType: "provider-action",
      resourceId: OP_A_READ,
      metadata: { actorAgentId: AGENT },
    });

    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    const replay = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: key }),
    );
    expect(replay.kind).toBe("allowed");
    if (replay.kind !== "allowed") throw new Error("unreachable");
    expect(replay.stub.status).toBe("stub_succeeded");
    const [b] = await db
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, intentId));
    expect(b.status).toBe("stub_succeeded");
  });

  test("immutability trigger: a committed binding's frozen columns cannot be mutated", async () => {
    await grantAgent(AGENT, WORKSPACE_A, ACCOUNT_A, ["github.issue.list"]);
    const out = await providerActionService.createProviderAction(
      input({ idempotencyKeyHash: `sha256:${"2".repeat(64)}` }),
    );
    if (out.kind !== "access_denied" && out.kind !== "policy_denied" && out.kind !== "allowed")
      throw new Error("unexpected");
    const intentId = (out as { intentId: string }).intentId;
    await expect(
      (async () =>
        getDb()
          .update(providerActionBindings)
          .set({ actionDigest: `sha256:${"9".repeat(64)}` })
          .where(eq(providerActionBindings.intentId, intentId)))(),
    ).rejects.toBeDefined();
  });
});

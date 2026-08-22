import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  auditChainHeads,
  auditEvents,
  createDb,
  getDb,
  intents,
  providerAccounts,
  providerActionAuditOutbox,
  providerActionBindings,
  providerActionReservationGenerations,
  providerAgentBudgets,
  providerGrants,
  providerOperations,
  secretRoutes,
  secrets,
  tenants,
  users,
  userTenants,
  workspaces,
} from "@stwd/db";
import { buildGithubAction } from "@stwd/provider-github";
import { jcsStringify, sha256HexPrefixed } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { ProviderPrincipalV1 } from "../middleware/provider-principal";
import {
  __setProviderCreateAfterBudgetReservationForTests,
  providerActionService,
} from "../services/provider-action-service";

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
const realServices =
  databaseUrl && redisUrl && process.env.STEWARD_PGLITE_MEMORY !== "true"
    ? describe
    : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `budget-race-${suffix}`;
const foreignTenantId = `budget-foreign-${suffix}`;
const userId = crypto.randomUUID();
const agentCreate = `budget-create-${suffix}`;
const agentUpdate = `budget-update-${suffix}`;
const agentDelete = `budget-delete-${suffix}`;
const foreignAgent = `budget-foreign-agent-${suffix}`;
const auditCreateAgent = `budget-audit-create-${suffix}`;
const auditUpdateAgent = `budget-audit-update-${suffix}`;
const auditDeleteAgent = `budget-audit-delete-${suffix}`;
const commitAgent = `budget-commit-${suffix}`;
const workspaceId = crypto.randomUUID();
const accountId = crypto.randomUUID();
const operationId = crypto.randomUUID();
const operationKey = "github.issue.list" as const;
const secretId = crypto.randomUUID();
const routeId = crypto.randomUUID();
const fixturePath = new URL("./fixtures/provider-budget-mutation.ts", import.meta.url).pathname;
type MutationResult = {
  ok: boolean;
  row?: { id: string; revision: number; enabled: boolean; max: number; agentId: string };
  error?: { code?: string; message: string; status?: number };
};

realServices("provider agent budget namespace serialization (PostgreSQL + Redis)", () => {
  let admin: ReturnType<typeof createDb>;
  let updateBudgetId: string;
  let deleteBudgetId: string;
  let auditUpdateBudgetId: string;
  let auditDeleteBudgetId: string;
  let commitBudgetId: string;
  let previousAuditKey: string | undefined;

  beforeAll(async () => {
    admin = createDb(databaseUrl!);
    previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_AUDIT_HMAC_KEY = `budget-race-audit-${suffix}`;
    __resetAuditHmacKeyCacheForTests();
    await admin.db.insert(tenants).values([
      { id: tenantId, name: tenantId, apiKeyHash: `hash-${suffix}` },
      { id: foreignTenantId, name: foreignTenantId, apiKeyHash: `foreign-hash-${suffix}` },
    ]);
    await admin.db.insert(users).values({
      id: userId,
      email: `${suffix}@example.test`,
      emailVerified: true,
    });
    await admin.db.insert(userTenants).values([
      { userId, tenantId, role: "owner" },
      { userId, tenantId: foreignTenantId, role: "owner" },
    ]);
    await admin.db.insert(agents).values([
      { id: agentCreate, tenantId, name: agentCreate, walletAddress: "0x7401" },
      { id: agentUpdate, tenantId, name: agentUpdate, walletAddress: "0x7402" },
      { id: agentDelete, tenantId, name: agentDelete, walletAddress: "0x7403" },
      { id: foreignAgent, tenantId: foreignTenantId, name: foreignAgent, walletAddress: "0x7405" },
      { id: auditCreateAgent, tenantId, name: auditCreateAgent, walletAddress: "0x7406" },
      { id: auditUpdateAgent, tenantId, name: auditUpdateAgent, walletAddress: "0x7407" },
      { id: auditDeleteAgent, tenantId, name: auditDeleteAgent, walletAddress: "0x7408" },
      { id: commitAgent, tenantId, name: commitAgent, walletAddress: "0x7409" },
    ]);
    await admin.db.insert(secrets).values({
      id: secretId,
      tenantId,
      name: "github",
      ciphertext: "x",
      iv: "x",
      authTag: "x",
      salt: "x",
      version: 1,
    });
    await admin.db.insert(secretRoutes).values({
      id: routeId,
      tenantId,
      secretId,
      hostPattern: "api.github.com",
      pathPattern: "/*",
      method: "*",
      injectAs: "header",
      injectKey: "authorization",
    });
    await admin.db.insert(workspaces).values({
      id: workspaceId,
      tenantId,
      key: `budget-${suffix}`,
      name: "Budget race",
      environment: "production",
      createdBy: userId,
    });
    await admin.db.insert(providerAccounts).values({
      id: accountId,
      tenantId,
      workspaceId,
      adapterKey: "github",
      externalRef: suffix,
      displayName: "Budget race",
      credentialSecretId: secretId,
      credentialVersion: 1,
    });
    await admin.db.insert(providerOperations).values({
      id: operationId,
      tenantId,
      workspaceId,
      providerAccountId: accountId,
      operationKey,
      riskClass: "read",
      secretRouteId: routeId,
      requestProfile: {
        policyRules: [
          {
            id: crypto.randomUUID(),
            type: "capability-intent",
            enabled: true,
            config: { capabilities: [operationKey], effect: "allow" },
          },
        ],
      },
    });
    await admin.db.insert(providerGrants).values(
      [
        agentCreate,
        agentUpdate,
        agentDelete,
        auditCreateAgent,
        auditUpdateAgent,
        auditDeleteAgent,
        commitAgent,
      ].map((agentId) => ({
        id: crypto.randomUUID(),
        tenantId,
        workspaceId,
        providerAccountId: accountId,
        agentId,
        operationKeys: [operationKey],
        environment: "production" as const,
        expiresAt: new Date(Date.now() + 86_400_000),
        grantedByUserId: userId,
        reason: "budget race",
      })),
    );
    const budgets = await admin.db
      .insert(providerAgentBudgets)
      .values(
        [agentUpdate, agentDelete, auditUpdateAgent, auditDeleteAgent, commitAgent].map(
          (agentId) => ({
            tenantId,
            agentId,
            dimension: "count" as const,
            windowSeconds: 3600,
            max: 10,
          }),
        ),
      )
      .returning({ id: providerAgentBudgets.id, agentId: providerAgentBudgets.agentId });
    const budgetId = (agentId: string) => {
      const id = budgets.find((budget) => budget.agentId === agentId)?.id;
      if (!id) throw new Error(`budget fixture missing for ${agentId}`);
      return id;
    };
    updateBudgetId = budgetId(agentUpdate);
    deleteBudgetId = budgetId(agentDelete);
    auditUpdateBudgetId = budgetId(auditUpdateAgent);
    auditDeleteBudgetId = budgetId(auditDeleteAgent);
    commitBudgetId = budgetId(commitAgent);
  }, 120_000);

  afterAll(async () => {
    __setProviderCreateAfterBudgetReservationForTests(null);
    await admin.db
      .delete(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.tenantId, tenantId));
    await admin.db
      .delete(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.tenantId, tenantId));
    await admin.db
      .delete(providerActionBindings)
      .where(eq(providerActionBindings.tenantId, tenantId));
    await admin.db.delete(intents).where(eq(intents.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(providerAgentBudgets).where(eq(providerAgentBudgets.tenantId, tenantId));
    await admin.db
      .delete(providerAgentBudgets)
      .where(eq(providerAgentBudgets.tenantId, foreignTenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, foreignTenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, foreignTenantId));
    await admin.db.delete(providerGrants).where(eq(providerGrants.tenantId, tenantId));
    await admin.db.delete(providerOperations).where(eq(providerOperations.tenantId, tenantId));
    await admin.db.delete(providerAccounts).where(eq(providerAccounts.tenantId, tenantId));
    await admin.db.delete(secretRoutes).where(eq(secretRoutes.tenantId, tenantId));
    await admin.db.delete(secrets).where(eq(secrets.tenantId, tenantId));
    await admin.db.delete(workspaces).where(eq(workspaces.tenantId, tenantId));
    await admin.db.delete(agents).where(eq(agents.tenantId, tenantId));
    await admin.db.delete(agents).where(eq(agents.tenantId, foreignTenantId));
    await admin.db.delete(userTenants).where(eq(userTenants.userId, userId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, foreignTenantId));
    await admin.db.delete(users).where(eq(users.id, userId));
    await admin.client.end();
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  });

  function spawnMutation(input: {
    action: "create" | "update" | "delete";
    applicationName: string;
    agentId: string;
    tenantId?: string;
    budgetId?: string;
    expectedRevision?: number;
    max: number;
    enabled?: boolean;
  }) {
    const childUrl = new URL(databaseUrl!);
    childUrl.searchParams.set("application_name", input.applicationName);
    return Bun.spawn([process.execPath, fixturePath], {
      cwd: new URL("../../../..", import.meta.url).pathname,
      env: {
        ...process.env,
        DATABASE_URL: childUrl.toString(),
        TEST_TENANT_ID: input.tenantId ?? tenantId,
        TEST_USER_ID: userId,
        TEST_AGENT_ID: input.agentId,
        TEST_ACTION: input.action,
        TEST_MAX: String(input.max),
        TEST_ENABLED: String(input.enabled ?? true),
        TEST_EXPECTED_REVISION: String(
          input.expectedRevision ?? (input.action === "create" ? 0 : 1),
        ),
        TEST_IDEMPOTENCY_KEY: `${suffix}-${input.action}-${input.applicationName}`,
        ...(input.budgetId ? { TEST_BUDGET_ID: input.budgetId } : {}),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
  }

  async function mutationResult(writer: ReturnType<typeof spawnMutation>): Promise<MutationResult> {
    const [status, stdout, stderr] = await Promise.all([
      writer.exited,
      new Response(writer.stdout).text(),
      new Response(writer.stderr).text(),
    ]);
    if (status !== 0) throw new Error(`budget mutation child failed (${status}): ${stderr}`);
    return JSON.parse(stdout) as MutationResult;
  }

  async function waitForBlocked(applicationName: string): Promise<void> {
    for (let attempt = 0; attempt < 2_000; attempt++) {
      const [row] = await admin.client<{ blockers: number[] }[]>`
        select pg_blocking_pids(pid) as blockers
        from pg_stat_activity
        where datname = current_database()
          and application_name = ${applicationName}
          and wait_event_type = 'Lock'
      `;
      if (row && row.blockers.length > 0) return;
      if (attempt === 1_999) throw new Error(`${applicationName} never blocked on reservation`);
      await Bun.sleep(10);
    }
  }

  function principal(agentId: string): ProviderPrincipalV1 {
    return {
      type: "agent",
      agentId,
      tenantId,
      platformId: null,
      issuer: "budget-race",
      subject: `agent:${agentId}`,
      tokenId: null,
      scopes: [],
      authenticatedAt: new Date().toISOString(),
      expiresAt: null,
      authnMethod: "agent-jwt-rs256",
    };
  }

  async function createPublicAction(agentId: string, seed: string) {
    const now = new Date();
    return providerActionService.createProviderAction({
      principal: principal(agentId),
      workspaceId,
      providerAccountId: accountId,
      operationKey,
      build: buildGithubAction(operationKey, { owner: "steward", repo: "budget-race" }),
      idempotencyKeyHash: `sha256:${createHash("sha256")
        .update(`${suffix}:${agentId}:${seed}`)
        .digest("hex")}`,
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + 300_000).toISOString(),
      nonce: `${seed}-${agentId}`.padEnd(32, "n").slice(0, 32),
      requestId: `budget-race-${seed}`,
    });
  }

  async function heldPublicAction(agentId: string, seed: string) {
    let release!: () => void;
    let signal!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const started = new Promise<void>((resolve) => {
      signal = resolve;
    });
    __setProviderCreateAfterBudgetReservationForTests(async () => {
      signal();
      await released;
    });
    const outcome = createPublicAction(agentId, seed).finally(() =>
      __setProviderCreateAfterBudgetReservationForTests(null),
    );
    await started;
    return { release, outcome };
  }

  test("empty-set create serializes after a reservation and the new zero cap governs the next action", async () => {
    const held = await heldPublicAction(agentCreate, `create-first-${suffix}`);
    const applicationName = `budget-create-writer-${suffix}`;
    const writer = spawnMutation({
      action: "create",
      applicationName,
      agentId: agentCreate,
      max: 0,
    });
    await waitForBlocked(applicationName);

    const foreign = spawnMutation({
      action: "create",
      applicationName: `budget-foreign-writer-${suffix}`,
      tenantId: foreignTenantId,
      agentId: foreignAgent,
      max: 7,
    });
    const isolated = await Promise.race([
      mutationResult(foreign),
      Bun.sleep(5_000).then(() => null),
    ]);
    // The held action also owns the tenant-wide required-audit lock. A
    // different agent in the same tenant can pass the budget namespace lock,
    // but its authority mutation cannot commit its required audit until the
    // held transaction finishes. Cross-tenant completion is the meaningful
    // isolation assertion here. Always release before asserting so a failed
    // diagnostic cannot strand the transaction and poison the remaining file.
    held.release();
    expect(isolated).not.toBeNull();
    expect(isolated).toEqual(
      expect.objectContaining({ ok: true, row: expect.objectContaining({ max: 7 }) }),
    );
    expect(await held.outcome).toMatchObject({ kind: "allowed" });
    expect(await mutationResult(writer)).toMatchObject({
      ok: true,
      row: { agentId: agentCreate, max: 0, revision: 1 },
    });
    expect(await createPublicAction(agentCreate, `create-next-${suffix}`)).toMatchObject({
      kind: "policy_denied",
      code: "AGENT_BUDGET_EXHAUSTED",
      httpStatus: 403,
    });
  }, 60_000);

  test("tightening and disabling serialize behind the exact budget snapshot without bypass", async () => {
    const first = await heldPublicAction(agentUpdate, `update-first-${suffix}`);
    const tightenName = `budget-update-writer-${suffix}`;
    const tighten = spawnMutation({
      action: "update",
      applicationName: tightenName,
      agentId: agentUpdate,
      budgetId: updateBudgetId,
      expectedRevision: 1,
      max: 0,
    });
    await waitForBlocked(tightenName);
    first.release();
    const firstOutcome = await first.outcome;
    expect(firstOutcome).toMatchObject({ kind: "allowed" });
    expect(await mutationResult(tighten)).toMatchObject({
      ok: true,
      row: { id: updateBudgetId, max: 0, revision: 2, enabled: true },
    });
    if (!("intentId" in firstOutcome)) throw new Error("public action did not persist an intent");
    const [binding] = await getDb()
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, firstOutcome.intentId));
    expect(
      (binding?.policyDecision as { agentBudgetResults?: Array<Record<string, unknown>> })
        .agentBudgetResults,
    ).toEqual([
      {
        budgetId: updateBudgetId,
        revision: 1,
        dimension: "count",
        workspaceId: null,
        windowSeconds: 3600,
        max: 10,
        currency: null,
        amount: 1,
        outcome: "pass",
        prior: 0,
      },
    ]);
    const [generation] = await getDb()
      .select()
      .from(providerActionReservationGenerations)
      .where(eq(providerActionReservationGenerations.intentId, firstOutcome.intentId));
    const reservationId = sha256HexPrefixed(
      jcsStringify({
        domain: "steward.provider-agent-budget.v2",
        tenantId,
        intentId: firstOutcome.intentId,
        generation: 1,
        groupKey: "global|count|__agent_budget_count__",
      }),
    );
    expect(generation).toMatchObject({
      tenantId,
      intentId: firstOutcome.intentId,
      generation: 1,
      phase: "decision",
      state: "settled",
      handles: {
        schemaVersion: "steward.provider-policy-reservations.v2",
        generation: 1,
        phase: "decision",
        cumulativeSpend: [
          {
            stream: {
              tenantId,
              agentId: agentUpdate,
              scope: "agent",
              scopeKey: "budget:global:count",
              currency: "__agent_budget_count__",
            },
            reservationId,
            amount: 1,
          },
        ],
        windowedInvoke: null,
      },
    });
    expect(await createPublicAction(agentUpdate, `update-next-${suffix}`)).toMatchObject({
      kind: "policy_denied",
      code: "AGENT_BUDGET_EXHAUSTED",
    });

    const disabling = await heldPublicAction(agentUpdate, `disable-first-${suffix}`);
    const disableName = `budget-disable-writer-${suffix}`;
    const disable = spawnMutation({
      action: "update",
      applicationName: disableName,
      agentId: agentUpdate,
      budgetId: updateBudgetId,
      expectedRevision: 2,
      max: 0,
      enabled: false,
    });
    await waitForBlocked(disableName);
    disabling.release();
    expect(await disabling.outcome).toMatchObject({
      kind: "policy_denied",
      code: "AGENT_BUDGET_EXHAUSTED",
    });
    expect(await mutationResult(disable)).toMatchObject({
      ok: true,
      row: { id: updateBudgetId, max: 0, revision: 3, enabled: false },
    });
    const disabledAction = await heldPublicAction(agentUpdate, `disabled-next-${suffix}`);
    const reenableName = `budget-reenable-writer-${suffix}`;
    const reenable = spawnMutation({
      action: "update",
      applicationName: reenableName,
      agentId: agentUpdate,
      budgetId: updateBudgetId,
      expectedRevision: 3,
      max: 0,
      enabled: true,
    });
    await waitForBlocked(reenableName);
    disabledAction.release();
    expect(await disabledAction.outcome).toMatchObject({ kind: "allowed" });
    expect(await mutationResult(reenable)).toMatchObject({
      ok: true,
      row: { id: updateBudgetId, max: 0, revision: 4, enabled: true },
    });
    expect(await createPublicAction(agentUpdate, `reenabled-next-${suffix}`)).toMatchObject({
      kind: "policy_denied",
      code: "AGENT_BUDGET_EXHAUSTED",
    });
  }, 60_000);

  test("delete serializes behind an admitted action and removes only the exact budget", async () => {
    const held = await heldPublicAction(agentDelete, `delete-first-${suffix}`);
    const applicationName = `budget-delete-writer-${suffix}`;
    const writer = spawnMutation({
      action: "delete",
      applicationName,
      agentId: agentDelete,
      budgetId: deleteBudgetId,
      expectedRevision: 1,
      max: 10,
    });
    await waitForBlocked(applicationName);
    held.release();
    expect(await held.outcome).toMatchObject({ kind: "allowed" });
    expect(await mutationResult(writer)).toMatchObject({
      ok: true,
      row: { id: deleteBudgetId, agentId: agentDelete, revision: 1 },
    });
    expect(
      await admin.db
        .select()
        .from(providerAgentBudgets)
        .where(eq(providerAgentBudgets.id, deleteBudgetId)),
    ).toHaveLength(0);
    expect(await createPublicAction(agentDelete, `delete-next-${suffix}`)).toMatchObject({
      kind: "allowed",
    });
  }, 60_000);

  test("required completion-audit failure rolls create, update, and delete back", async () => {
    const cases = [
      { action: "create" as const, agentId: auditCreateAgent },
      {
        action: "update" as const,
        agentId: auditUpdateAgent,
        budgetId: auditUpdateBudgetId,
      },
      {
        action: "delete" as const,
        agentId: auditDeleteAgent,
        budgetId: auditDeleteBudgetId,
      },
    ];
    for (const mutation of cases) {
      const action = `provider.agent_budget.${mutation.action}`;
      await admin.client.unsafe(`
        create function reject_budget_audit_${suffix}() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}' and new.action = '${action}' then
            raise exception 'forced budget completion audit failure';
          end if;
          return new;
        end
        $$;
        create trigger reject_budget_audit_${suffix}
          before insert on audit_events
          for each row execute function reject_budget_audit_${suffix}();
      `);
      try {
        const before = await admin.db
          .select()
          .from(providerAgentBudgets)
          .where(eq(providerAgentBudgets.agentId, mutation.agentId));
        const auditsBefore = await admin.db
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, action)));
        const failed = await mutationResult(
          spawnMutation({
            action: mutation.action,
            applicationName: `budget-audit-${mutation.action}-${suffix}`,
            agentId: mutation.agentId,
            budgetId: mutation.budgetId,
            expectedRevision: mutation.action === "create" ? 0 : 1,
            max: mutation.action === "update" ? 99 : 10,
          }),
        );
        expect(failed).toEqual({
          ok: false,
          error: { code: "internal", message: "authority mutation failed", status: 500 },
        });
        expect(
          await admin.db
            .select()
            .from(providerAgentBudgets)
            .where(eq(providerAgentBudgets.agentId, mutation.agentId)),
        ).toEqual(before);
        expect(
          await admin.db
            .select()
            .from(auditEvents)
            .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, action))),
        ).toEqual(auditsBefore);
      } finally {
        await admin.client.unsafe(
          `drop trigger if exists reject_budget_audit_${suffix} on audit_events`,
        );
        await admin.client.unsafe(`drop function if exists reject_budget_audit_${suffix}()`);
      }
    }
  }, 120_000);

  test("decision commit failure releases Redis admission and leaves no durable residue", async () => {
    await admin.client.unsafe(`
      create function reject_budget_commit_${suffix}() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${tenantId}' and new.actor_agent_id = '${commitAgent}' then
          raise exception 'forced provider decision commit failure';
        end if;
        return new;
      end
      $$;
      create trigger reject_budget_commit_${suffix}
        before insert on provider_action_bindings
        for each row execute function reject_budget_commit_${suffix}();
    `);
    try {
      expect(await createPublicAction(commitAgent, `commit-failure-${suffix}`)).toMatchObject({
        kind: "evidence_failure",
        code: "EVIDENCE_DECISION_PERSIST_FAILED",
        httpStatus: 503,
      });
      expect(
        await admin.db
          .select()
          .from(providerActionBindings)
          .where(eq(providerActionBindings.actorAgentId, commitAgent)),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select()
          .from(providerActionReservationGenerations)
          .where(eq(providerActionReservationGenerations.tenantId, tenantId)),
      ).not.toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            handles: expect.objectContaining({
              cumulativeSpend: expect.arrayContaining([
                expect.objectContaining({
                  stream: expect.objectContaining({ agentId: commitAgent }),
                }),
              ]),
            }),
          }),
        ]),
      );
      expect(
        await admin.db
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.actorId, commitAgent))),
      ).toHaveLength(0);
    } finally {
      await admin.client.unsafe(
        `drop trigger if exists reject_budget_commit_${suffix} on provider_action_bindings`,
      );
      await admin.client.unsafe(`drop function if exists reject_budget_commit_${suffix}()`);
    }

    const retry = await createPublicAction(commitAgent, `commit-retry-${suffix}`);
    expect(retry).toMatchObject({ kind: "allowed" });
    if (!("intentId" in retry)) throw new Error("retry did not persist an intent");
    const [binding] = await admin.db
      .select()
      .from(providerActionBindings)
      .where(eq(providerActionBindings.intentId, retry.intentId));
    expect(
      (binding?.policyDecision as { agentBudgetResults?: Array<Record<string, unknown>> })
        .agentBudgetResults,
    ).toEqual([expect.objectContaining({ budgetId: commitBudgetId, outcome: "pass", prior: 0 })]);
  }, 60_000);
});

import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  autoApprovalRules,
  createDb,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, asc, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `approval-rule-atomic-${suffix}`;
const userId = crypto.randomUUID();
const fixturePath = new URL("./fixtures/approval-rule-concurrent-request.ts", import.meta.url)
  .pathname;

type RuleResponse = {
  ok: boolean;
  data?: {
    id: string;
    tenantId: string;
    maxAmountWei: string;
    autoDenyAfterHours: number | null;
    escalateAboveWei: string | null;
    enabled: boolean;
  };
  error?: string;
};

type WriterResult = { status: number; body: RuleResponse };
type RuleAudit = {
  seq: number;
  action: string;
  resourceId: string;
  metadata: Record<string, unknown>;
  requestId: string | null;
};

realPostgres("auto-approval rule audit atomicity (mounted Postgres)", () => {
  let admin: ReturnType<typeof createDb>;
  let app: Hono<{ Variables: AppVariables }>;
  let token: string;
  let noMfaToken: string;
  let apiKey: string;
  let previousJwtSecret: string | undefined;
  let previousMasterPassword: string | undefined;
  let previousAuditKey: string | undefined;

  beforeAll(async () => {
    admin = createDb(databaseUrl!);
    previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_JWT_SECRET = `approval-rule-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `approval-rule-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `approval-rule-audit-key-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const apiKeyPair = generateApiKey();
    apiKey = apiKeyPair.key;
    await admin.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: apiKeyPair.hash,
    });
    await admin.db.insert(users).values({
      id: userId,
      email: `${suffix}@example.test`,
      emailVerified: true,
    });
    await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });

    const [{ createSessionToken }, { tenantAuth }, { approvalRoutes }] = await Promise.all([
      import("../routes/auth"),
      import("../services/context"),
      import("../routes/approvals"),
    ]);
    token = await createSessionToken("0x0000000000000000000000000000000000000720", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    noMfaToken = await createSessionToken("0x0000000000000000000000000000000000000720", tenantId, {
      userId,
      tenantId,
    });
    app = new Hono<{ Variables: AppVariables }>();
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
    app.use("*", correlationId);
    app.use("*", tenantAuth);
    app.route("/approvals", approvalRoutes);
  }, 120_000);

  afterEach(async () => {
    await admin.db.delete(autoApprovalRules).where(eq(autoApprovalRules.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  });

  afterAll(async () => {
    await admin.db.delete(autoApprovalRules).where(eq(autoApprovalRules.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.db.delete(users).where(eq(users.id, userId));
    await admin.client.end();
    if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
    else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
    if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  });

  async function putRule(body: Record<string, unknown>, requestId: string): Promise<Response> {
    return app.request("/approvals/rules", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Request-Id": requestId,
      },
      body: JSON.stringify(body),
    });
  }

  function spawnWriter(body: Record<string, unknown>, requestId: string) {
    return Bun.spawn([process.execPath, fixturePath], {
      cwd: new URL("../../../..", import.meta.url).pathname,
      env: {
        ...process.env,
        DATABASE_URL: databaseUrl!,
        TEST_TENANT_ID: tenantId,
        TEST_USER_ID: userId,
        TEST_REQUEST_ID: requestId,
        TEST_REQUEST_BODY: JSON.stringify(body),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
  }

  async function writerResult(writer: ReturnType<typeof spawnWriter>): Promise<WriterResult> {
    const [status, stdout, stderr] = await Promise.all([
      writer.exited,
      new Response(writer.stdout).text(),
      new Response(writer.stderr).text(),
    ]);
    if (status !== 0) throw new Error(`concurrent writer failed (${status}): ${stderr}`);
    return JSON.parse(stdout) as WriterResult;
  }

  async function waitForAdvisoryWaiters(minimum: number, message: string): Promise<void> {
    for (let attempt = 0; attempt < 2_000; attempt++) {
      const [row] = await admin.client<{ count: string }[]>`
        select count(*)::text as count
        from pg_stat_activity
        where datname = current_database() and wait_event = 'advisory'
      `;
      if (Number(row?.count ?? "0") >= minimum) return;
      if (attempt === 1_999) throw new Error(message);
      await Bun.sleep(10);
    }
  }

  async function installBlockingAuditFailure(input: {
    requestId: string;
    action: "approval_rule.create" | "approval_rule.update";
    gateKey: number;
    name: string;
  }): Promise<void> {
    await admin.client.unsafe(`
      create function "${input.name}"() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${tenantId}'
           and new.request_id = '${input.requestId}'
           and new.action = '${input.action}' then
          perform pg_advisory_xact_lock(${input.gateKey});
          raise exception 'forced approval rule completion audit failure';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${input.name}"
      before insert on audit_events
      for each row execute function "${input.name}"()
    `);
  }

  async function removeAuditFailure(name: string): Promise<void> {
    await admin.client.unsafe(`drop trigger if exists "${name}" on audit_events`);
    await admin.client.unsafe(`drop function if exists "${name}"()`);
  }

  async function ruleAudits(...requestIds: string[]): Promise<RuleAudit[]> {
    return admin.db
      .select({
        seq: auditEvents.seq,
        action: auditEvents.action,
        resourceId: auditEvents.resourceId,
        metadata: auditEvents.metadata,
        requestId: auditEvents.requestId,
      })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, tenantId), inArray(auditEvents.requestId, requestIds)))
      .orderBy(asc(auditEvents.seq)) as Promise<RuleAudit[]>;
  }

  async function lockTenantAudit(locker: Awaited<ReturnType<typeof admin.client.reserve>>) {
    await locker`select pg_advisory_lock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
  }

  async function unlockTenantAudit(locker: Awaited<ReturnType<typeof admin.client.reserve>>) {
    await locker`select pg_advisory_unlock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
  }

  test("preserves mounted auth, MFA, no-store, response, and partial-update semantics", async () => {
    const apiKeyDenied = await app.request("/approvals/rules", {
      method: "PUT",
      headers: {
        "X-Steward-Tenant": tenantId,
        "X-Steward-Key": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ maxAmountWei: "1" }),
    });
    expect(apiKeyDenied.status).toBe(403);
    const noMfaDenied = await app.request("/approvals/rules", {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${noMfaToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ maxAmountWei: "1" }),
    });
    expect(noMfaDenied.status).toBe(403);

    const createdResponse = await putRule(
      {
        maxAmountWei: "100",
        autoDenyAfterHours: 24,
        escalateAboveWei: "1000",
        enabled: true,
      },
      `create-${suffix}`,
    );
    expect(createdResponse.status).toBe(201);
    expect(createdResponse.headers.get("cache-control")).toContain("no-store");
    const created = (await createdResponse.json()) as RuleResponse;
    expect(created.data).toMatchObject({ maxAmountWei: "100", enabled: true });

    const readResponse = await app.request("/approvals/rules", {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(readResponse.status).toBe(200);
    expect(readResponse.headers.get("cache-control")).toContain("no-store");

    const updatedResponse = await putRule({ enabled: false }, `update-${suffix}`);
    expect(updatedResponse.status).toBe(200);
    const updated = (await updatedResponse.json()) as RuleResponse;
    expect(updated.data).toMatchObject({
      id: created.data?.id,
      maxAmountWei: "100",
      autoDenyAfterHours: 24,
      escalateAboveWei: "1000",
      enabled: false,
    });

    const completions = await admin.db
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          inArray(auditEvents.action, ["approval_rule.create", "approval_rule.update"]),
        ),
      )
      .orderBy(asc(auditEvents.seq));
    expect(completions.map(({ action }) => action)).toEqual([
      "approval_rule.create",
      "approval_rule.update",
    ]);
  });

  test("successful create-vs-create pairs authoritative authorization and completion audits", async () => {
    const firstRequestId = `create-pair-a-${suffix}`;
    const secondRequestId = `create-pair-b-${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await lockTenantAudit(locker);
      locked = true;
      const firstWriter = spawnWriter({ maxAmountWei: "111" }, firstRequestId);
      await waitForAdvisoryWaiters(1, "first create did not reach the tenant audit lock");
      const secondWriter = spawnWriter({ maxAmountWei: "222" }, secondRequestId);
      await waitForAdvisoryWaiters(2, "second create did not reach the tenant audit lock");
      await unlockTenantAudit(locker);
      locked = false;

      const results = await Promise.all([writerResult(firstWriter), writerResult(secondWriter)]);
      expect(results.map(({ status }) => status).sort()).toEqual([200, 201]);
      const createdIndex = results.findIndex(({ status }) => status === 201);
      const updatedIndex = 1 - createdIndex;
      const requestIds = [firstRequestId, secondRequestId];
      const createdRequestId = requestIds[createdIndex]!;
      const updatedRequestId = requestIds[updatedIndex]!;
      const created = results[createdIndex]!.body.data!;
      const updated = results[updatedIndex]!.body.data!;
      expect(created.id).toBe(updated.id);

      const events = await ruleAudits(firstRequestId, secondRequestId);
      const createdEvents = events.filter(({ requestId }) => requestId === createdRequestId);
      const updatedEvents = events.filter(({ requestId }) => requestId === updatedRequestId);
      expect(createdEvents.map(({ action }) => action)).toEqual([
        "approval_rule.create.authorized",
        "approval_rule.create",
      ]);
      expect(createdEvents.map(({ resourceId }) => resourceId)).toEqual([created.id, created.id]);
      expect(createdEvents[1]?.metadata.after).toMatchObject(created);
      expect(updatedEvents.map(({ action }) => action)).toEqual([
        "approval_rule.update.authorized",
        "approval_rule.update",
      ]);
      expect(updatedEvents.map(({ resourceId }) => resourceId)).toEqual([updated.id, updated.id]);
      expect(updatedEvents[0]?.metadata.before).toEqual(updatedEvents[1]?.metadata.before);
      expect(updatedEvents[0]?.metadata.before).toMatchObject(created);
      expect(updatedEvents[1]?.metadata.after).toMatchObject(updated);
    } finally {
      if (locked) await unlockTenantAudit(locker);
      locker.release();
    }
  }, 120_000);

  test("successful update-vs-update preserves exact serialized before metadata", async () => {
    const [initial] = await admin.db
      .insert(autoApprovalRules)
      .values({ tenantId, maxAmountWei: "10", enabled: true })
      .returning();
    const firstRequestId = `update-pair-a-${suffix}`;
    const secondRequestId = `update-pair-b-${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await lockTenantAudit(locker);
      locked = true;
      const firstWriter = spawnWriter({ maxAmountWei: "111" }, firstRequestId);
      await waitForAdvisoryWaiters(1, "first update did not reach the tenant audit lock");
      const secondWriter = spawnWriter({ enabled: false }, secondRequestId);
      await waitForAdvisoryWaiters(2, "second update did not reach the tenant audit lock");
      await unlockTenantAudit(locker);
      locked = false;

      const results = await Promise.all([writerResult(firstWriter), writerResult(secondWriter)]);
      expect(results.map(({ status }) => status)).toEqual([200, 200]);
      const events = await ruleAudits(firstRequestId, secondRequestId);
      for (const [index, requestId] of [firstRequestId, secondRequestId].entries()) {
        const pair = events.filter((event) => event.requestId === requestId);
        expect(pair.map(({ action }) => action)).toEqual([
          "approval_rule.update.authorized",
          "approval_rule.update",
        ]);
        expect(pair.map(({ resourceId }) => resourceId)).toEqual([initial.id, initial.id]);
        expect(pair[0]?.metadata.before).toEqual(pair[1]?.metadata.before);
        expect(pair[1]?.metadata.after).toMatchObject(results[index]!.body.data!);
      }
      const completions = events.filter(({ action }) => action === "approval_rule.update");
      expect(completions[0]?.metadata.before).toMatchObject({
        id: initial.id,
        maxAmountWei: "10",
        enabled: true,
      });
      expect(completions[1]?.metadata.before).toEqual(completions[0]?.metadata.after);
      const [stored] = await admin.db
        .select()
        .from(autoApprovalRules)
        .where(eq(autoApprovalRules.tenantId, tenantId));
      expect(completions[1]?.metadata.after).toMatchObject({
        id: stored?.id,
        maxAmountWei: stored?.maxAmountWei,
        enabled: stored?.enabled,
      });
    } finally {
      if (locked) await unlockTenantAudit(locker);
      locker.release();
    }
  }, 120_000);

  test("create-vs-create: failed completion audit cannot delete the concurrent winner", async () => {
    const failRequestId = `create-fail-${suffix}`;
    const successRequestId = `create-success-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const triggerName = `fail_rule_create_${suffix}`;
    const locker = await admin.client.reserve();
    let gateLocked = false;
    try {
      await installBlockingAuditFailure({
        requestId: failRequestId,
        action: "approval_rule.create",
        gateKey,
        name: triggerName,
      });
      await locker`select pg_advisory_lock(${gateKey})`;
      gateLocked = true;

      const failedRequest = putRule({ maxAmountWei: "111" }, failRequestId);
      await waitForAdvisoryWaiters(1, "failed create did not reach its audit gate");
      const writer = spawnWriter({ maxAmountWei: "222" }, successRequestId);
      await waitForAdvisoryWaiters(2, "concurrent create did not reach the tenant audit lock");
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;

      const [failedResponse, winner] = await Promise.all([failedRequest, writerResult(writer)]);
      expect(failedResponse.status).toBe(500);
      expect(winner.status).toBe(201);
      expect(winner.body.data?.maxAmountWei).toBe("222");

      const rules = await admin.db
        .select()
        .from(autoApprovalRules)
        .where(eq(autoApprovalRules.tenantId, tenantId));
      expect(rules).toHaveLength(1);
      expect(rules[0]?.maxAmountWei).toBe("222");
      const completions = await admin.db
        .select({ requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "approval_rule.create")),
        );
      expect(completions).toEqual([{ requestId: successRequestId }]);
      const failedEvents = await ruleAudits(failRequestId);
      expect(failedEvents.map(({ action }) => action)).toEqual(["approval_rule.create.authorized"]);
      expect(failedEvents[0]?.resourceId).not.toBe(tenantId);
      expect(failedEvents[0]?.metadata.requested).toEqual({ maxAmountWei: "111" });
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeAuditFailure(triggerName);
    }
  }, 120_000);

  test("update-vs-update: failed completion audit cannot overwrite the concurrent winner", async () => {
    await admin.db.insert(autoApprovalRules).values({
      tenantId,
      maxAmountWei: "10",
      enabled: true,
    });
    const failRequestId = `update-fail-${suffix}`;
    const successRequestId = `update-success-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(12, 24), 16);
    const triggerName = `fail_rule_update_${suffix}`;
    const locker = await admin.client.reserve();
    let gateLocked = false;
    try {
      await installBlockingAuditFailure({
        requestId: failRequestId,
        action: "approval_rule.update",
        gateKey,
        name: triggerName,
      });
      await locker`select pg_advisory_lock(${gateKey})`;
      gateLocked = true;

      const failedRequest = putRule({ maxAmountWei: "999" }, failRequestId);
      await waitForAdvisoryWaiters(1, "failed update did not reach its audit gate");
      const writer = spawnWriter({ enabled: false }, successRequestId);
      await waitForAdvisoryWaiters(2, "concurrent update did not reach the tenant audit lock");
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;

      const [failedResponse, winner] = await Promise.all([failedRequest, writerResult(writer)]);
      expect(failedResponse.status).toBe(500);
      expect(winner.status).toBe(200);
      expect(winner.body.data).toMatchObject({ maxAmountWei: "10", enabled: false });

      const [stored] = await admin.db
        .select()
        .from(autoApprovalRules)
        .where(eq(autoApprovalRules.tenantId, tenantId));
      expect(stored).toMatchObject({ maxAmountWei: "10", enabled: false });
      const completions = await admin.db
        .select({ requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "approval_rule.update")),
        );
      expect(completions).toEqual([{ requestId: successRequestId }]);
      const failedEvents = await ruleAudits(failRequestId);
      expect(failedEvents.map(({ action }) => action)).toEqual(["approval_rule.update.authorized"]);
      expect(failedEvents[0]?.resourceId).toBe(stored?.id);
      expect(failedEvents[0]?.metadata.before).toMatchObject({ maxAmountWei: "10", enabled: true });
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeAuditFailure(triggerName);
    }
  }, 120_000);

  test("a deferred commit failure rolls back the rule and preserves only its authorization attempt", async () => {
    const requestId = `commit-fail-${suffix}`;
    const triggerName = `fail_rule_commit_${suffix}`;
    await admin.client.unsafe(`
      create function "${triggerName}"() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${tenantId}'
           and new.request_id = '${requestId}'
           and new.action = 'approval_rule.create' then
          raise exception 'forced approval rule commit failure';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create constraint trigger "${triggerName}"
      after insert on audit_events
      deferrable initially deferred
      for each row execute function "${triggerName}"()
    `);
    try {
      const response = await putRule({ maxAmountWei: "333" }, requestId);
      expect(response.status).toBe(500);
      await expect(response.json()).resolves.toMatchObject({
        ok: false,
        error: "Failed to update approval rule",
      });
      expect(
        await admin.db
          .select()
          .from(autoApprovalRules)
          .where(eq(autoApprovalRules.tenantId, tenantId)),
      ).toHaveLength(0);
      const events = await ruleAudits(requestId);
      expect(events.map(({ action }) => action)).toEqual(["approval_rule.create.authorized"]);
    } finally {
      await removeAuditFailure(triggerName);
    }
  }, 120_000);
});

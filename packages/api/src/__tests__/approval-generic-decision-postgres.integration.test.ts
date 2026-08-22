import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  agents,
  approvalQueue,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
  transactions,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `approval-decision-${suffix}`;
const userId = crypto.randomUUID();
const agentId = `approval-agent-${suffix}`;
const txId = `approval-tx-${suffix}`;
const approvalId = `approval-entry-${suffix}`;
const fixturePath = new URL("./fixtures/approval-generic-deny-request.ts", import.meta.url)
  .pathname;

type WriterResult = { status: number; body: { ok: boolean; error?: string } };

realPostgres("generic approval decision races (mounted PostgreSQL)", () => {
  let admin: ReturnType<typeof createDb>;
  let app: Hono<{ Variables: AppVariables }>;
  let token: string;
  let previousJwtSecret: string | undefined;
  let previousMasterPassword: string | undefined;
  let previousAuditKey: string | undefined;

  beforeAll(async () => {
    admin = createDb(databaseUrl!);
    previousJwtSecret = process.env.STEWARD_JWT_SECRET;
    previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
    previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_JWT_SECRET = `approval-decision-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `approval-decision-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `approval-decision-audit-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const apiKey = generateApiKey();
    await admin.db
      .insert(tenants)
      .values({ id: tenantId, name: tenantId, apiKeyHash: apiKey.hash });
    await admin.db.insert(users).values({
      id: userId,
      email: `${suffix}@example.test`,
      emailVerified: true,
    });
    await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });
    await admin.db.insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x0000000000000000000000000000000000000737",
    });

    const [{ createSessionToken }, { tenantAuth }, { approvalRoutes }] = await Promise.all([
      import("../routes/auth"),
      import("../services/context"),
      import("../routes/approvals"),
    ]);
    token = await createSessionToken("0x0000000000000000000000000000000000000737", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    app = new Hono<{ Variables: AppVariables }>();
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
    app.use("*", correlationId);
    app.use("*", tenantAuth);
    app.route("/approvals", approvalRoutes);
  }, 120_000);

  afterEach(async () => {
    await admin.db.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
    await admin.db.delete(transactions).where(eq(transactions.agentId, agentId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  });

  afterAll(async () => {
    await admin.db.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
    await admin.db.delete(transactions).where(eq(transactions.agentId, agentId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(agents).where(eq(agents.id, agentId));
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

  async function seedPending(): Promise<void> {
    await admin.db.insert(transactions).values({
      id: txId,
      agentId,
      status: "pending",
      toAddress: "0x0000000000000000000000000000000000000001",
      value: "1",
      chainId: 8453,
    });
    await admin.db
      .insert(approvalQueue)
      .values({ id: approvalId, txId, agentId, status: "pending" });
  }

  function spawnDeny(requestId: string, applicationName: string) {
    const writerDatabaseUrl = new URL(databaseUrl!);
    writerDatabaseUrl.searchParams.set("application_name", applicationName);
    return Bun.spawn([process.execPath, fixturePath], {
      cwd: new URL("../../../..", import.meta.url).pathname,
      env: {
        ...process.env,
        DATABASE_URL: writerDatabaseUrl.toString(),
        TEST_TENANT_ID: tenantId,
        TEST_USER_ID: userId,
        TEST_TX_ID: txId,
        TEST_REQUEST_ID: requestId,
        TEST_DENY_REASON: "concurrent denial",
      },
      stdout: "pipe",
      stderr: "pipe",
    });
  }

  async function writerResult(writer: ReturnType<typeof spawnDeny>): Promise<WriterResult> {
    const [status, stdout, stderr] = await Promise.all([
      writer.exited,
      new Response(writer.stdout).text(),
      new Response(writer.stderr).text(),
    ]);
    if (status !== 0) throw new Error(`concurrent denial failed (${status}): ${stderr}`);
    return JSON.parse(stdout) as WriterResult;
  }

  async function waitForAuditWaiter(applicationName: string, blockerPid: number): Promise<void> {
    for (let attempt = 0; attempt < 2_000; attempt++) {
      const [row] = await admin.client<{ blocker_pids: number[] }[]>`
        select pg_blocking_pids(activity.pid) as blocker_pids
        from pg_stat_activity activity
        join pg_locks lock on lock.pid = activity.pid
        where activity.datname = current_database()
          and activity.application_name = ${applicationName}
          and activity.wait_event = 'advisory'
          and lock.locktype = 'advisory'
          and not lock.granted
          and lock.classid::bigint =
            ((hashtextextended(${`steward_audit_${tenantId}`}, 0) >> 32) & 4294967295)
          and lock.objid::bigint =
            (hashtextextended(${`steward_audit_${tenantId}`}, 0) & 4294967295)
          and lock.objsubid = 1
      `;
      if (row?.blocker_pids.includes(blockerPid)) return;
      if (attempt === 1_999) throw new Error("denial never reached tenant audit lock");
      await Bun.sleep(10);
    }
  }

  async function approve(): Promise<Response> {
    return app.request(`/approvals/${txId}/approve`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Request-Id": `approve-${suffix}`,
      },
      body: "{}",
    });
  }

  async function completionAudits() {
    return admin.db
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "approval.deny")));
  }

  test("concurrent generic approve is a stable loser and denial commits one coherent decision", async () => {
    await seedPending();
    const blocker = await admin.client.reserve();
    const [{ pid: blockerPid }] = await blocker<{ pid: number }[]>`select pg_backend_pid() as pid`;
    await blocker`select pg_advisory_lock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
    const applicationName = `approval-deny-${suffix}`;
    const deny = spawnDeny(`deny-${suffix}`, applicationName);
    try {
      await waitForAuditWaiter(applicationName, blockerPid);
      const approveResponse = await approve();
      expect(approveResponse.status).toBe(409);
      const [queueBefore] = await admin.db
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.id, approvalId));
      const [txBefore] = await admin.db
        .select()
        .from(transactions)
        .where(eq(transactions.id, txId));
      expect({ queue: queueBefore?.status, transaction: txBefore?.status }).toEqual({
        queue: "pending",
        transaction: "pending",
      });
    } finally {
      await blocker`select pg_advisory_unlock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
      blocker.release();
    }
    expect((await writerResult(deny)).status).toBe(200);
    const [queue] = await admin.db
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.id, approvalId));
    const [transaction] = await admin.db
      .select()
      .from(transactions)
      .where(eq(transactions.id, txId));
    expect({ queue: queue?.status, transaction: transaction?.status }).toEqual({
      queue: "rejected",
      transaction: "rejected",
    });
    expect(await completionAudits()).toHaveLength(1);
  }, 60_000);

  test("a terminal transaction race rolls denial back without splitting queue state", async () => {
    await seedPending();
    const blocker = await admin.client.reserve();
    const [{ pid: blockerPid }] = await blocker<{ pid: number }[]>`select pg_backend_pid() as pid`;
    await blocker`select pg_advisory_lock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
    const applicationName = `approval-terminal-${suffix}`;
    const deny = spawnDeny(`terminal-${suffix}`, applicationName);
    try {
      await waitForAuditWaiter(applicationName, blockerPid);
      await admin.db
        .update(transactions)
        .set({ status: "confirmed" })
        .where(eq(transactions.id, txId));
    } finally {
      await blocker`select pg_advisory_unlock(hashtextextended(${`steward_audit_${tenantId}`}, 0))`;
      blocker.release();
    }
    expect((await writerResult(deny)).status).toBe(409);
    const [queue] = await admin.db
      .select()
      .from(approvalQueue)
      .where(eq(approvalQueue.id, approvalId));
    const [transaction] = await admin.db
      .select()
      .from(transactions)
      .where(eq(transactions.id, txId));
    expect({ queue: queue?.status, transaction: transaction?.status }).toEqual({
      queue: "pending",
      transaction: "confirmed",
    });
    expect(await completionAudits()).toHaveLength(0);
  }, 60_000);
});

import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import { generateApiKey } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
  users,
  userTenants,
  webhookConfigs,
  webhookDeliveries,
} from "@stwd/db";
import { and, asc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const realPostgres = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `webhook-atomic-${suffix}`;
const userId = crypto.randomUUID();
const fixturePath = new URL("./fixtures/webhook-concurrent-request.ts", import.meta.url).pathname;

type WriterResult = { status: number; body: { ok: boolean; data?: Record<string, unknown> } };

realPostgres("webhook mutation audit atomicity (mounted Postgres)", () => {
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
    process.env.STEWARD_JWT_SECRET = `webhook-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `webhook-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `webhook-audit-key-${suffix}`;
    __resetAuditHmacKeyCacheForTests();

    const apiKey = generateApiKey();
    await admin.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: apiKey.hash,
    });
    await admin.db.insert(users).values({
      id: userId,
      email: `${suffix}@example.test`,
      emailVerified: true,
    });
    await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });

    const [{ createSessionToken }, { tenantAuth }, { webhookRoutes }] = await Promise.all([
      import("../routes/auth"),
      import("../services/context"),
      import("../routes/webhooks"),
    ]);
    token = await createSessionToken("0x0000000000000000000000000000000000000719", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    app = new Hono<{ Variables: AppVariables }>();
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
    app.use("*", correlationId);
    app.use("*", tenantAuth);
    app.route("/webhooks", webhookRoutes);
  }, 120_000);

  afterEach(async () => {
    await admin.db.delete(webhookDeliveries).where(eq(webhookDeliveries.tenantId, tenantId));
    await admin.db.delete(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId));
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
  });

  afterAll(async () => {
    await admin.db.delete(webhookDeliveries).where(eq(webhookDeliveries.tenantId, tenantId));
    await admin.db.delete(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId));
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

  function request(
    method: string,
    path: string,
    body: Record<string, unknown> | undefined,
    requestId: string,
  ): Promise<Response> {
    return app.request(path, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "X-Request-Id": requestId,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  }

  function spawnWriter(
    method: string,
    path: string,
    body: Record<string, unknown> | undefined,
    requestId: string,
  ) {
    return Bun.spawn([process.execPath, fixturePath], {
      cwd: new URL("../../../..", import.meta.url).pathname,
      env: {
        ...process.env,
        DATABASE_URL: `${databaseUrl!}?application_name=${writerApplication(requestId)}`,
        TEST_TENANT_ID: tenantId,
        TEST_USER_ID: userId,
        TEST_REQUEST_ID: requestId,
        TEST_REQUEST_METHOD: method,
        TEST_REQUEST_PATH: path,
        ...(body === undefined ? {} : { TEST_REQUEST_BODY: JSON.stringify(body) }),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
  }

  function writerApplication(requestId: string) {
    return `webhook_writer_${requestId}`.slice(0, 63);
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

  async function backendPid(client: Awaited<ReturnType<typeof admin.client.reserve>>) {
    const [row] = await client<{ pid: number }[]>`select pg_backend_pid()::int as pid`;
    if (!row) throw new Error("expected a PostgreSQL backend PID");
    return row.pid;
  }

  async function waitForGate(gateKey: number, holderPid: number) {
    const classId = Math.floor(gateKey / 4_294_967_296);
    const objectId = gateKey % 4_294_967_296;
    for (let attempt = 0; attempt < 600; attempt++) {
      const [row] = await admin.client<{ pid: number; blockers: number[] }[]>`
        select pid::int as pid, pg_blocking_pids(pid)::int[] as blockers
        from pg_locks
        where locktype = 'advisory'
          and classid::bigint = ${classId}
          and objid::bigint = ${objectId}
          and objsubid = 1
          and granted = false
      `;
      if (row?.blockers.map(Number).includes(holderPid)) return row.pid;
      if (attempt === 599)
        throw new Error(
          `expected a request blocked by backend ${holderPid} on advisory gate ${gateKey}`,
        );
      await Bun.sleep(10);
    }
    throw new Error("unreachable advisory-gate wait");
  }

  async function waitForTenantAuditBlockedBy(applicationName: string, blockerPid: number) {
    for (let attempt = 0; attempt < 600; attempt++) {
      const [row] = await admin.client<
        { pid: number; blockers: number[]; waits_on_tenant_audit: boolean }[]
      >`
        select
          activity.pid::int as pid,
          pg_blocking_pids(activity.pid)::int[] as blockers,
          exists (
            select 1
            from pg_locks waiting
            where waiting.pid = activity.pid
              and waiting.locktype = 'advisory'
              and waiting.classid::bigint =
                ((hashtextextended(${`steward_audit_${tenantId}`}, 0) >> 32) & 4294967295)
              and waiting.objid::bigint =
                (hashtextextended(${`steward_audit_${tenantId}`}, 0) & 4294967295)
              and waiting.objsubid = 1
              and waiting.granted = false
          ) as waits_on_tenant_audit
        from pg_stat_activity activity
        where activity.datname = current_database()
          and activity.application_name = ${applicationName}
      `;
      if (
        row?.waits_on_tenant_audit &&
        row.blockers.map(Number).includes(blockerPid) &&
        row.pid !== blockerPid
      ) {
        return row.pid;
      }
      if (attempt === 599) {
        throw new Error(
          `expected ${applicationName} to wait on tenant audit backend ${blockerPid}; observed ${JSON.stringify(row)}`,
        );
      }
      await Bun.sleep(10);
    }
    throw new Error("unreachable tenant-audit wait");
  }

  async function installAuditGate(input: {
    requestId: string;
    action: string;
    gateKey: number;
    name: string;
    fail?: boolean;
  }) {
    await admin.client.unsafe(`
      create function "${input.name}"() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${tenantId}'
           and new.request_id = '${input.requestId}'
           and new.action = '${input.action}' then
          perform pg_advisory_xact_lock(${input.gateKey});
          ${input.fail ? "raise exception 'forced webhook completion audit failure';" : ""}
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${input.name}" before insert on audit_events
      for each row execute function "${input.name}"()
    `);
  }

  async function removeGate(name: string) {
    await admin.client.unsafe(`drop trigger if exists "${name}" on audit_events`);
    await admin.client.unsafe(`drop function if exists "${name}"()`);
  }

  async function seedWebhook(url: string, secret = `ciphertext-${suffix}`) {
    const [row] = await admin.db
      .insert(webhookConfigs)
      .values({ tenantId, url, secret, events: ["tx.pending"], enabled: true })
      .returning();
    return row;
  }

  test("returns the one-time secret only after the final enabled row and both audits commit", async () => {
    const requestId = `mounted-create-${suffix}`;
    const response = await request(
      "POST",
      "/webhooks",
      { url: `https://example.com/${suffix}/mounted`, events: ["tx.pending"] },
      requestId,
    );
    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toContain("no-store");
    const body = (await response.json()) as WriterResult["body"];
    expect(body.data?.secret).toMatch(/^whsec_/);
    const [stored] = await admin.db
      .select()
      .from(webhookConfigs)
      .where(eq(webhookConfigs.tenantId, tenantId));
    expect(stored).toMatchObject({ enabled: true });
    expect(stored?.secret).not.toBe(body.data?.secret);
    const events = await admin.db
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.requestId, requestId)))
      .orderBy(asc(auditEvents.seq));
    expect(events.map(({ action }) => action)).toEqual([
      "webhook.create.authorized",
      "webhook.create",
    ]);
  });

  test("create-vs-create exposes no partial row and commits one audited winner", async () => {
    const firstId = `create-first-${suffix}`;
    const secondId = `create-second-${suffix}`;
    const url = `https://example.com/${suffix}/same`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const name = `webhook_create_gate_${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({ requestId: firstId, action: "webhook.create", gateKey, name });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const first = request("POST", "/webhooks", { url }, firstId);
      const firstPid = await waitForGate(gateKey, lockerPid);
      expect(
        await admin.db.select().from(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId)),
      ).toHaveLength(0);
      const second = spawnWriter("POST", "/webhooks", { url }, secondId);
      const secondPid = await waitForTenantAuditBlockedBy(writerApplication(secondId), firstPid);
      expect(new Set([lockerPid, firstPid, secondPid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;
      const [firstResponse, secondResponse] = await Promise.all([first, writerResult(second)]);
      expect(firstResponse.status).toBe(201);
      expect(secondResponse.status).toBe(409);
      const rows = await admin.db
        .select()
        .from(webhookConfigs)
        .where(eq(webhookConfigs.tenantId, tenantId));
      expect(rows).toHaveLength(1);
      expect(rows[0]?.enabled).toBe(true);
      const completions = await admin.db
        .select({ requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "webhook.create")));
      expect(completions).toEqual([{ requestId: firstId }]);
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeGate(name);
    }
  }, 120_000);

  test("failed update cannot overwrite a concurrent update winner", async () => {
    const webhook = await seedWebhook(`https://example.com/${suffix}/update`);
    const failedId = `update-failed-${suffix}`;
    const winnerId = `update-winner-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(12, 24), 16);
    const name = `webhook_update_gate_${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({
        requestId: failedId,
        action: "webhook.update",
        gateKey,
        name,
        fail: true,
      });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const failed = request("PUT", `/webhooks/${webhook.id}`, { description: "stale" }, failedId);
      const failedPid = await waitForGate(gateKey, lockerPid);
      const winner = spawnWriter(
        "PUT",
        `/webhooks/${webhook.id}`,
        { description: "winner" },
        winnerId,
      );
      const winnerPid = await waitForTenantAuditBlockedBy(writerApplication(winnerId), failedPid);
      expect(new Set([lockerPid, failedPid, winnerPid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;
      const [failedResponse, winnerResponse] = await Promise.all([failed, writerResult(winner)]);
      expect(failedResponse.status).toBe(500);
      expect(winnerResponse.status).toBe(200);
      const [stored] = await admin.db
        .select()
        .from(webhookConfigs)
        .where(eq(webhookConfigs.id, webhook.id));
      expect(stored?.description).toBe("winner");
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeGate(name);
    }
  }, 120_000);

  test("update-first serializes delete after the committed update and its audits", async () => {
    const webhook = await seedWebhook(`https://example.com/${suffix}/update-delete-update-first`);
    const updateId = `update-delete-first-${suffix}`;
    const deleteId = `update-delete-second-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(2, 14), 16);
    const name = `webhook_update_delete_first_${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({ requestId: updateId, action: "webhook.update", gateKey, name });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const update = request(
        "PUT",
        `/webhooks/${webhook.id}`,
        { description: "committed-before-delete" },
        updateId,
      );
      const updatePid = await waitForGate(gateKey, lockerPid);
      const deletion = spawnWriter("DELETE", `/webhooks/${webhook.id}`, undefined, deleteId);
      const deletePid = await waitForTenantAuditBlockedBy(writerApplication(deleteId), updatePid);
      expect(new Set([lockerPid, updatePid, deletePid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;

      const [updateResponse, deleteResponse] = await Promise.all([update, writerResult(deletion)]);
      expect(updateResponse.status).toBe(200);
      expect(deleteResponse.status).toBe(200);
      expect(
        await admin.db.select().from(webhookConfigs).where(eq(webhookConfigs.id, webhook.id)),
      ).toHaveLength(0);
      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId))
        .orderBy(asc(auditEvents.seq));
      expect(events).toEqual([
        { action: "webhook.update.authorized", requestId: updateId },
        { action: "webhook.update", requestId: updateId },
        { action: "webhook.delete.authorized", requestId: deleteId },
        { action: "webhook.delete", requestId: deleteId },
      ]);
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeGate(name);
    }
  }, 120_000);

  test("delete-first makes the waiting update re-read the committed absence", async () => {
    const webhook = await seedWebhook(`https://example.com/${suffix}/update-delete-delete-first`);
    const deleteId = `delete-update-first-${suffix}`;
    const updateId = `delete-update-second-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(6, 18), 16);
    const name = `webhook_delete_update_first_${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({ requestId: deleteId, action: "webhook.delete", gateKey, name });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const deletion = request("DELETE", `/webhooks/${webhook.id}`, undefined, deleteId);
      const deletePid = await waitForGate(gateKey, lockerPid);
      const update = spawnWriter(
        "PUT",
        `/webhooks/${webhook.id}`,
        { description: "must-not-resurrect" },
        updateId,
      );
      const updatePid = await waitForTenantAuditBlockedBy(writerApplication(updateId), deletePid);
      expect(new Set([lockerPid, deletePid, updatePid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;

      const [deleteResponse, updateResponse] = await Promise.all([deletion, writerResult(update)]);
      expect(deleteResponse.status).toBe(200);
      expect(updateResponse.status).toBe(404);
      expect(
        await admin.db.select().from(webhookConfigs).where(eq(webhookConfigs.id, webhook.id)),
      ).toHaveLength(0);
      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(eq(auditEvents.tenantId, tenantId))
        .orderBy(asc(auditEvents.seq));
      expect(events).toEqual([
        { action: "webhook.delete.authorized", requestId: deleteId },
        { action: "webhook.delete", requestId: deleteId },
      ]);
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeGate(name);
    }
  }, 120_000);

  test("failed delete cannot resurrect a stale secret over a concurrent recreate", async () => {
    const oldSecret = `old-ciphertext-${suffix}`;
    const url = `https://example.com/${suffix}/delete-recreate`;
    const webhook = await seedWebhook(url, oldSecret);
    const deleteId = `delete-failed-${suffix}`;
    const createId = `recreate-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(4, 16), 16);
    const name = `webhook_delete_gate_${suffix}`;
    const locker = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({
        requestId: deleteId,
        action: "webhook.delete",
        gateKey,
        name,
        fail: true,
      });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const failedDelete = request("DELETE", `/webhooks/${webhook.id}`, undefined, deleteId);
      const failedDeletePid = await waitForGate(gateKey, lockerPid);
      const recreate = spawnWriter("POST", "/webhooks", { url }, createId);
      const recreatePid = await waitForTenantAuditBlockedBy(
        writerApplication(createId),
        failedDeletePid,
      );
      expect(new Set([lockerPid, failedDeletePid, recreatePid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;
      const [deleteResponse, recreateResponse] = await Promise.all([
        failedDelete,
        writerResult(recreate),
      ]);
      expect(deleteResponse.status).toBe(500);
      expect(recreateResponse.status).toBe(409);
      const [stored] = await admin.db
        .select()
        .from(webhookConfigs)
        .where(eq(webhookConfigs.id, webhook.id));
      expect(stored?.secret).toBe(oldSecret);
      expect(stored?.url).toBe(url);
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await removeGate(name);
    }
  }, 120_000);

  test("retry audit failure releases the row lock to the worker's exact terminal winner", async () => {
    const webhook = await seedWebhook(`https://example.com/${suffix}/retry`);
    const [delivery] = await admin.db
      .insert(webhookDeliveries)
      .values({
        tenantId,
        webhookConfigId: webhook.id,
        eventType: "tx.pending",
        payload: { webhookConfigId: webhook.id },
        url: webhook.url,
        secret: webhook.secret,
        events: webhook.events,
        status: "failed",
        attempts: 1,
        maxAttempts: 3,
        lastError: "retry me",
      })
      .returning();
    const requestId = `retry-failed-${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(8, 20), 16);
    const name = `webhook_retry_gate_${suffix}`;
    const locker = await admin.client.reserve();
    const workerClient = await admin.client.reserve();
    let locked = false;
    try {
      await installAuditGate({
        requestId,
        action: "webhook_delivery.retry",
        gateKey,
        name,
        fail: true,
      });
      const lockerPid = await backendPid(locker);
      await locker`select pg_advisory_lock(${gateKey})`;
      locked = true;
      const retry = request("POST", `/webhooks/deliveries/${delivery.id}/retry`, {}, requestId);
      const retryPid = await waitForGate(gateKey, lockerPid);
      const workerApplication = `webhook_719_worker_${suffix}`;
      await workerClient`select set_config('application_name', ${workerApplication}, false)`;
      const workerPid = await backendPid(workerClient);
      const worker = workerClient<{ status: string }[]>`
        update webhook_deliveries
        set status = 'delivered', delivered_at = now(), last_error = null
        where id = ${delivery.id}
        returning status
      `.then((rows) => rows);
      for (let attempt = 0; attempt < 600; attempt++) {
        const [row] = await admin.client<{ blockers: number[]; waits_on_tuple: boolean }[]>`
          select
            pg_blocking_pids(${workerPid})::int[] as blockers,
            exists (
              select 1 from pg_locks
              where pid = ${workerPid}
                and locktype in ('transactionid', 'tuple')
                and granted = false
            ) as waits_on_tuple
        `;
        if (row?.waits_on_tuple && row.blockers.map(Number).includes(retryPid)) break;
        if (attempt === 599) {
          throw new Error(
            `expected worker backend ${workerPid} to wait on retry backend ${retryPid}; observed ${JSON.stringify(row)}`,
          );
        }
        await Bun.sleep(10);
      }
      expect(new Set([lockerPid, retryPid, workerPid]).size).toBe(3);
      await locker`select pg_advisory_unlock(${gateKey})`;
      locked = false;
      const [retryResponse, workerRows] = await Promise.all([retry, worker]);
      expect(retryResponse.status).toBe(500);
      expect(workerRows[0]?.status).toBe("delivered");
      const [stored] = await admin.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.id, delivery.id));
      expect(stored).toMatchObject({ status: "delivered", lastError: null });
      expect(
        await admin.db
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.requestId, requestId))),
      ).toHaveLength(0);
    } finally {
      if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      workerClient.release();
      await removeGate(name);
    }
  }, 120_000);

  test("a deferred completion-audit failure commits neither authority nor secret", async () => {
    const requestId = `deferred-create-${suffix}`;
    const name = `webhook_deferred_${suffix}`;
    await admin.client.unsafe(`
      create function "${name}"() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${tenantId}' and new.request_id = '${requestId}'
           and new.action = 'webhook.create' then
          raise exception 'forced deferred webhook commit failure';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create constraint trigger "${name}" after insert on audit_events
      deferrable initially deferred for each row execute function "${name}"()
    `);
    try {
      const response = await request(
        "POST",
        "/webhooks",
        { url: `https://example.com/${suffix}/deferred` },
        requestId,
      );
      expect(response.status).toBe(500);
      expect(
        await admin.db.select().from(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId)),
      ).toHaveLength(0);
      expect(
        await admin.db
          .select()
          .from(auditEvents)
          .where(and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.requestId, requestId))),
      ).toHaveLength(0);
    } finally {
      await removeGate(name);
    }
  }, 120_000);
});

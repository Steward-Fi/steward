import { afterAll, afterEach, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  conditionSetItems,
  conditionSets,
  createDb,
  tenants,
} from "@stwd/db";
import { and, count, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const databaseUrl = process.env.DATABASE_URL;
const describeRealPostgres =
  databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;

describeRealPostgres("condition set real-PostgreSQL atomicity", () => {
  let admin: ReturnType<typeof createDb>;
  let app: Hono<{ Variables: AppVariables }>;
  const tenantIds: string[] = [];
  const childProcesses = new Set<ReturnType<typeof Bun.spawn>>();

  beforeAll(async () => {
    admin = createDb(databaseUrl!);
    process.env.STEWARD_AUDIT_HMAC_KEY = "condition-set-postgres-audit-key-with-enough-entropy";
    __resetAuditHmacKeyCacheForTests();
    const { conditionSetRoutes } = await import("../routes/condition-sets");
    app = new Hono<{ Variables: AppVariables }>();
    app.use("*", async (c, next) => {
      c.set("tenantId", c.req.header("x-test-tenant")!);
      c.set("authType", "session-jwt");
      c.set("tenantRole", "admin");
      c.set("userId", "condition-set-postgres-admin");
      c.set("sessionMfaVerifiedAt", Date.now());
      c.set("requestId", c.req.header("x-request-id"));
      await next();
    });
    app.route("/condition-sets", conditionSetRoutes);
  });

  afterAll(async () => {
    if (tenantIds.length > 0) {
      await admin.db.delete(auditEvents).where(inArray(auditEvents.tenantId, tenantIds));
      await admin.db.delete(auditChainHeads).where(inArray(auditChainHeads.tenantId, tenantIds));
      await admin.db.delete(tenants).where(inArray(tenants.id, tenantIds));
    }
    await admin.client.end();
  });

  afterEach(async () => {
    await Promise.all(
      [...childProcesses].map(async (childProcess) => {
        childProcess.kill("SIGTERM");
        const exited = await Promise.race([
          childProcess.exited.then(() => true),
          Bun.sleep(1_000).then(() => false),
        ]);
        if (!exited) {
          childProcess.kill("SIGKILL");
          await childProcess.exited;
        }
      }),
    );
    childProcesses.clear();
  });

  async function createTenant(label: string) {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `condition-set-${label}-${suffix}`.slice(0, 64);
    tenantIds.push(tenantId);
    await admin.db.insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: suffix });
    return { suffix, tenantId };
  }

  function request(tenantId: string, path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set("x-test-tenant", tenantId);
    if (init.body) headers.set("Content-Type", "application/json");
    return app.request(path, { ...init, headers });
  }

  function spawnRoute(input: {
    tenantId: string;
    path: string;
    method: string;
    body?: unknown;
    requestId?: string;
  }) {
    const childProcess = Bun.spawn(
      [
        globalThis.process.execPath,
        new URL("./fixtures/condition-set-route-writer.ts", import.meta.url).pathname,
      ],
      {
        cwd: new URL("../../../..", import.meta.url).pathname,
        env: {
          ...globalThis.process.env,
          DATABASE_URL: databaseUrl!,
          STEWARD_AUDIT_HMAC_KEY: process.env.STEWARD_AUDIT_HMAC_KEY!,
          TEST_TENANT_ID: input.tenantId,
          TEST_PATH: input.path,
          TEST_METHOD: input.method,
          ...(input.body === undefined ? {} : { TEST_BODY: JSON.stringify(input.body) }),
          ...(input.requestId ? { TEST_REQUEST_ID: input.requestId } : {}),
        },
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    childProcesses.add(childProcess);

    let resolveBackendPid!: (pid: number) => void;
    let rejectBackendPid!: (error: unknown) => void;
    const backendPid = new Promise<number>((resolve, reject) => {
      resolveBackendPid = resolve;
      rejectBackendPid = reject;
    });
    const output = (async () => {
      const reader = childProcess.stdout.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let result: { status: number; body: unknown } | undefined;
      try {
        while (true) {
          const { done, value } = await reader.read();
          buffer += decoder.decode(value, { stream: !done });
          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";
          for (const line of lines) {
            if (!line) continue;
            const frame = JSON.parse(line) as
              | { type: "backend"; pid: number }
              | { type: "result"; status: number; body: unknown };
            if (frame.type === "backend") resolveBackendPid(frame.pid);
            else result = { status: frame.status, body: frame.body };
          }
          if (done) break;
        }
        if (!result) throw new Error("condition-set writer emitted no result frame");
        return result;
      } catch (error) {
        rejectBackendPid(error);
        throw error;
      }
    })();
    return {
      backendPid,
      childProcess,
      output,
      stderr: new Response(childProcess.stderr).text(),
    };
  }

  async function routeResult(routeProcess: ReturnType<typeof spawnRoute>) {
    try {
      const [exit, output, errorOutput] = await Promise.all([
        routeProcess.childProcess.exited,
        routeProcess.output,
        routeProcess.stderr,
      ]);
      if (exit !== 0) {
        throw new Error(`condition-set writer failed: ${errorOutput}`);
      }
      return output;
    } finally {
      childProcesses.delete(routeProcess.childProcess);
    }
  }

  async function advisoryKey(value: string): Promise<string> {
    const [row] = await admin.client<{ key: string }[]>`
      select hashtextextended(${value}, 0)::text as key
    `;
    if (!row) throw new Error(`failed to derive advisory key for ${value}`);
    return row.key;
  }

  async function waitForAdvisoryWaiter(lockKey: string, expectedPid?: number) {
    for (let attempt = 0; attempt < 200; attempt++) {
      const rows = await admin.client<{ pid: number }[]>`
        with expected as (select ${lockKey}::bigint as key)
        select locks.pid
        from pg_locks locks
        cross join expected
        where locks.locktype = 'advisory'
          and not locks.granted
          and locks.objsubid = 1
          and locks.classid = ((expected.key >> 32) & 4294967295)::oid
          and locks.objid = (expected.key & 4294967295)::oid
      `;
      if (rows.length > 1) {
        throw new Error(`ambiguous advisory waiters for key ${lockKey}: ${rows.length}`);
      }
      if (rows.length === 1) {
        const waiterPid = rows[0].pid;
        if (expectedPid !== undefined && waiterPid !== expectedPid) {
          throw new Error(
            `advisory waiter for key ${lockKey} was backend ${waiterPid}, expected ${expectedPid}`,
          );
        }
        return waiterPid;
      }
      if (attempt === 199) throw new Error(`missing advisory waiter for key ${lockKey}`);
      await Bun.sleep(10);
    }
    throw new Error(`missing advisory waiter for key ${lockKey}`);
  }

  async function installAuditGate(input: {
    suffix: string;
    tenantId: string;
    requestId: string;
    action: string;
    fail: boolean;
  }) {
    const functionName = `condition_set_gate_${input.suffix}`;
    const triggerName = `condition_set_gate_${input.suffix}`;
    const gateKey = Number.parseInt(input.suffix.slice(0, 12), 16);
    const locker = await admin.client.reserve();
    await admin.client.unsafe(`
      create function "${functionName}"() returns trigger language plpgsql as $$
      begin
        if new.tenant_id = '${input.tenantId}'
           and new.request_id = '${input.requestId}'
           and new.action = '${input.action}' then
          perform pg_advisory_xact_lock(${gateKey});
          ${input.fail ? "raise exception 'forced condition set completion audit failure';" : "return new;"}
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${triggerName}"
      before insert on audit_events
      for each row execute function "${functionName}"()
    `);
    await locker`select pg_advisory_lock(${gateKey})`;
    let locked = true;
    return {
      gateKey,
      release: async () => {
        if (!locked) return;
        await locker`select pg_advisory_unlock(${gateKey})`;
        locked = false;
      },
      cleanup: async () => {
        if (locked) await locker`select pg_advisory_unlock(${gateKey})`;
        locker.release();
        await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
        await admin.client.unsafe(`drop function if exists "${functionName}"()`);
      },
    };
  }

  it("admits exactly one concurrent 100th set and 1,000th item", async () => {
    const { tenantId } = await createTenant("quota");
    await admin.db.insert(conditionSets).values(
      Array.from({ length: 99 }, (_, index) => ({
        tenantId,
        name: `seed-set-${index}`,
        ownerId: "postgres-quota",
      })),
    );
    const setResponses = await Promise.all(
      ["candidate-a", "candidate-b"].map((name) =>
        routeResult(
          spawnRoute({
            tenantId,
            path: "/condition-sets",
            method: "POST",
            body: { name, ownerId: "postgres-quota" },
          }),
        ),
      ),
    );
    expect(setResponses.map((response) => response.status).sort()).toEqual([201, 400]);
    const [{ total: setTotal }] = await admin.db
      .select({ total: count() })
      .from(conditionSets)
      .where(eq(conditionSets.tenantId, tenantId));
    expect(Number(setTotal)).toBe(100);

    const [itemSet] = await admin.db
      .insert(conditionSets)
      .values({ tenantId, name: "item-quota", ownerId: "postgres-quota" })
      .returning({ id: conditionSets.id });
    await admin.db.insert(conditionSetItems).values(
      Array.from({ length: 999 }, (_, index) => ({
        tenantId,
        conditionSetId: itemSet.id,
        value: `seed-item-${index}`,
      })),
    );
    const itemResponses = await Promise.all(
      ["candidate-item-a", "candidate-item-b"].map((value) =>
        routeResult(
          spawnRoute({
            tenantId,
            path: `/condition-sets/${itemSet.id}/items`,
            method: "POST",
            body: { value },
          }),
        ),
      ),
    );
    expect(itemResponses.map((response) => response.status).sort()).toEqual([201, 400]);
    const [{ total: itemTotal }] = await admin.db
      .select({ total: count() })
      .from(conditionSetItems)
      .where(eq(conditionSetItems.conditionSetId, itemSet.id));
    expect(Number(itemTotal)).toBe(1_000);
  }, 120_000);

  it("rolls back an audit-failed item update before a concurrent winner commits", async () => {
    const { suffix, tenantId } = await createTenant("audit-race");
    const [set] = await admin.db
      .insert(conditionSets)
      .values({ tenantId, name: "audit race", ownerId: "postgres-race" })
      .returning({ id: conditionSets.id });
    const [item] = await admin.db
      .insert(conditionSetItems)
      .values({ tenantId, conditionSetId: set.id, value: "target", label: "original" })
      .returning({ id: conditionSetItems.id });
    const failedRequestId = `failed-${suffix}`;
    const winnerRequestId = `winner-${suffix}`;
    const gate = await installAuditGate({
      suffix,
      tenantId,
      requestId: failedRequestId,
      action: "condition_set.item.update",
      fail: true,
    });
    try {
      const failed = request(tenantId, `/condition-sets/${set.id}/items/${item.id}`, {
        method: "PATCH",
        headers: { "x-request-id": failedRequestId },
        body: JSON.stringify({ label: "failed-label" }),
      });
      const failedPid = await waitForAdvisoryWaiter(String(gate.gateKey));
      const winner = spawnRoute({
        tenantId,
        path: `/condition-sets/${set.id}/items/${item.id}`,
        method: "PATCH",
        requestId: winnerRequestId,
        body: { label: "winner-label" },
      });
      const expectedWinnerPid = await winner.backendPid;
      const winnerPid = await waitForAdvisoryWaiter(
        await advisoryKey(`steward_audit_${tenantId}`),
        expectedWinnerPid,
      );
      expect(winnerPid).toBe(expectedWinnerPid);
      expect(winnerPid).not.toBe(failedPid);
      await gate.release();
      const [failedResponse, winnerResponse] = await Promise.all([failed, routeResult(winner)]);
      expect(failedResponse.status).toBe(500);
      expect(winnerResponse.status).toBe(200);
      expect(
        await admin.db
          .select({ label: conditionSetItems.label })
          .from(conditionSetItems)
          .where(eq(conditionSetItems.id, item.id)),
      ).toEqual([{ label: "winner-label" }]);
      const events = await admin.db
        .select({ requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, tenantId),
            eq(auditEvents.action, "condition_set.item.update"),
          ),
        );
      expect(events).toEqual([{ requestId: winnerRequestId }]);
    } finally {
      await gate.cleanup();
    }
  }, 120_000);

  it("serializes replace before an upsert queued on the same condition set", async () => {
    const { suffix, tenantId } = await createTenant("replace-upsert");
    const [set] = await admin.db
      .insert(conditionSets)
      .values({ tenantId, name: "replace upsert", ownerId: "postgres-race" })
      .returning({ id: conditionSets.id });
    await admin.db
      .insert(conditionSetItems)
      .values({ tenantId, conditionSetId: set.id, value: "original" });
    const replaceRequestId = `replace-${suffix}`;
    const upsertRequestId = `upsert-${suffix}`;
    const gate = await installAuditGate({
      suffix,
      tenantId,
      requestId: replaceRequestId,
      action: "condition_set.items.replace",
      fail: false,
    });
    try {
      const replace = request(tenantId, `/condition-sets/${set.id}/items`, {
        method: "PUT",
        headers: { "x-request-id": replaceRequestId },
        body: JSON.stringify({ items: [{ value: "replacement" }] }),
      });
      const replacePid = await waitForAdvisoryWaiter(String(gate.gateKey));
      const upsert = spawnRoute({
        tenantId,
        path: `/condition-sets/${set.id}/items`,
        method: "POST",
        requestId: upsertRequestId,
        body: { value: "concurrent-upsert" },
      });
      const expectedUpsertPid = await upsert.backendPid;
      const upsertPid = await waitForAdvisoryWaiter(
        await advisoryKey(`steward_audit_${tenantId}`),
        expectedUpsertPid,
      );
      expect(upsertPid).toBe(expectedUpsertPid);
      expect(upsertPid).not.toBe(replacePid);
      await gate.release();
      const [replaceResponse, upsertResponse] = await Promise.all([replace, routeResult(upsert)]);
      expect(replaceResponse.status).toBe(200);
      expect(upsertResponse.status).toBe(201);
      const values = await admin.db
        .select({ value: conditionSetItems.value })
        .from(conditionSetItems)
        .where(eq(conditionSetItems.conditionSetId, set.id));
      expect(values.map((row) => row.value).sort()).toEqual(["concurrent-upsert", "replacement"]);
      const events = await admin.db
        .select({ action: auditEvents.action, requestId: auditEvents.requestId })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, tenantId),
            inArray(auditEvents.action, [
              "condition_set.items.replace",
              "condition_set.item.upsert",
            ]),
          ),
        );
      expect(events).toEqual([
        { action: "condition_set.items.replace", requestId: replaceRequestId },
        { action: "condition_set.item.upsert", requestId: upsertRequestId },
      ]);
    } finally {
      await gate.cleanup();
    }
  }, 120_000);
});

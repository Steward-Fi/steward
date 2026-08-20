import { afterAll, afterEach, beforeAll, describe, expect, test } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  closeDb,
  createDb,
  intents,
  providerActionAuditOutbox,
  tenants,
} from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";
import {
  __setProviderAuditOutboxAfterClaimForTests,
  __setProviderAuditOutboxFaultForTests,
  providerActionService,
} from "../services/provider-action-service";

const databaseUrl = process.env.DATABASE_URL;

describe.skipIf(!databaseUrl)("provider required-audit outbox (real Postgres)", () => {
  const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `audit-outbox-${suffix}`;
  const intentId = `pa_${crypto.randomUUID()}`;
  const auditKey = `provider-audit-outbox-${suffix}`;
  const admin = databaseUrl ? createDb(databaseUrl) : null;

  async function resetEvidence(): Promise<typeof providerActionAuditOutbox.$inferSelect> {
    await admin!.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin!.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin!.db
      .update(providerActionAuditOutbox)
      .set({ deliveredAt: null, claimToken: null, claimedAt: null })
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    const [row] = await admin!.db
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    return row;
  }

  async function evidenceRows(): Promise<Array<{ outbox_id: string }>> {
    const result = await admin!.db.execute(sql`
      SELECT metadata->>'requiredOutboxId' AS outbox_id
      FROM audit_events
      WHERE tenant_id = ${tenantId}
      ORDER BY metadata->>'requiredOutboxId'
    `);
    return (
      Array.isArray(result) ? result : ((result as { rows?: unknown[] }).rows ?? [])
    ) as Array<{
      outbox_id: string;
    }>;
  }

  beforeAll(async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY = auditKey;
    __resetAuditHmacKeyCacheForTests();
    await admin!.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: `sha256:${suffix}`,
    });
    await admin!.db.insert(intents).values({
      id: intentId,
      tenantId,
      intentType: "provider-action",
      status: "authorized",
      resourceType: "provider_action",
      resourceId: intentId,
      createdByType: "system",
      createdById: "provider-audit-outbox-test",
    });
    await admin!.db.insert(providerActionAuditOutbox).values({
      tenantId,
      intentId,
      action: "provider.action.allowed",
      resourceType: "provider_action",
      resourceId: intentId,
      metadata: { intentId, actorAgentId: "provider-audit-outbox-test" },
    });
  });

  afterEach(async () => {
    __setProviderAuditOutboxAfterClaimForTests(null);
    __setProviderAuditOutboxFaultForTests(null);
    const rows = await admin!.db
      .select({ id: providerActionAuditOutbox.id })
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    if (rows.length > 1) {
      await admin!.db
        .delete(providerActionAuditOutbox)
        .where(
          and(eq(providerActionAuditOutbox.intentId, intentId), sql`id <> ${rows[0]!.id}::uuid`),
        );
    }
  });

  afterAll(async () => {
    await admin!.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin!.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin!.db
      .delete(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.intentId, intentId));
    await admin!.db.delete(intents).where(eq(intents.id, intentId));
    await admin!.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin!.client.end();
    await closeDb();
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  });

  test("two processes racing one row produce one signed event and one completion", async () => {
    const row = await resetEvidence();
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const locker = await admin!.client.reserve();
    let gateLocked = false;
    await locker`select pg_advisory_lock(${gateKey})`;
    gateLocked = true;
    const command = [
      process.execPath,
      new URL("./fixtures/provider-audit-outbox-worker.ts", import.meta.url).pathname,
    ];
    const workerEnv = {
      ...process.env,
      DATABASE_URL: databaseUrl!,
      STEWARD_AUDIT_HMAC_KEY: auditKey,
      STEWARD_DB_MODE: "postgres",
      STEWARD_PGLITE_MEMORY: "",
      TEST_TENANT_ID: tenantId,
      TEST_INTENT_ID: intentId,
      TEST_GATE_KEY: String(gateKey),
    };
    const workers = [
      Bun.spawn(command, {
        cwd: new URL("../../../..", import.meta.url).pathname,
        env: workerEnv,
        stdout: "pipe",
        stderr: "pipe",
      }),
      Bun.spawn(command, {
        cwd: new URL("../../../..", import.meta.url).pathname,
        env: workerEnv,
        stdout: "pipe",
        stderr: "pipe",
      }),
    ];
    try {
      for (let attempt = 0; attempt < 200; attempt++) {
        const [waiting] = await admin!.client<{ count: string }[]>`
          SELECT count(*)::text AS count
          FROM pg_stat_activity
          WHERE wait_event = 'advisory'
            AND query ILIKE '%pg_advisory_lock_shared%'
        `;
        if (Number(waiting?.count ?? "0") >= 2) break;
        if (attempt === 199) throw new Error("workers did not reach the shared start gate");
        await Bun.sleep(10);
      }
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;
      const exits = await Promise.all(workers.map((worker) => worker.exited));
      for (let index = 0; index < workers.length; index++) {
        if (exits[index] !== 0) {
          throw new Error(await new Response(workers[index]!.stderr).text());
        }
      }
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
    }

    expect(await evidenceRows()).toEqual([{ outbox_id: row.id }]);
    const [completed] = await admin!.db
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.id, row.id));
    expect(completed.deliveredAt).not.toBeNull();
    expect(completed.claimToken).toBeNull();
  }, 120_000);

  test("fault after append rolls back both writes and a retry signs once", async () => {
    const row = await resetEvidence();
    __setProviderAuditOutboxFaultForTests("after_append");
    await expect(providerActionService.recoverUnsignedIntents(tenantId, intentId)).rejects.toThrow(
      "injected crash after required-audit append",
    );
    expect(await evidenceRows()).toHaveLength(0);
    const [pending] = await admin!.db
      .select()
      .from(providerActionAuditOutbox)
      .where(eq(providerActionAuditOutbox.id, row.id));
    expect(pending.deliveredAt).toBeNull();
    expect(pending.claimToken).toBeNull();

    __setProviderAuditOutboxFaultForTests(null);
    expect(await providerActionService.recoverUnsignedIntents(tenantId, intentId)).toBe(1);
    expect(await evidenceRows()).toEqual([{ outbox_id: row.id }]);
  });

  test("stale takeover fences the expired worker token", async () => {
    const row = await resetEvidence();
    let releaseExpired!: () => void;
    const expiredGate = new Promise<void>((resolve) => {
      releaseExpired = resolve;
    });
    let claimed!: () => void;
    const firstClaim = new Promise<void>((resolve) => {
      claimed = resolve;
    });
    __setProviderAuditOutboxAfterClaimForTests(async (_token, ids) => {
      if (ids.length === 0) return;
      claimed();
      await expiredGate;
    });
    const expiredWorker = providerActionService.recoverUnsignedIntents(tenantId, intentId);
    await firstClaim;
    await admin!.db.execute(sql`
      UPDATE provider_action_audit_outbox
      SET claimed_at = now() - interval '2 minutes'
      WHERE id = ${row.id}::uuid
    `);
    __setProviderAuditOutboxAfterClaimForTests(null);
    expect(await providerActionService.recoverUnsignedIntents(tenantId, intentId)).toBe(1);
    releaseExpired();
    expect(await expiredWorker).toBe(0);
    expect(await evidenceRows()).toEqual([{ outbox_id: row.id }]);
  });

  test("distinct immutable identities preserve same-action multiplicity", async () => {
    const first = await resetEvidence();
    const [second] = await admin!.db
      .insert(providerActionAuditOutbox)
      .values({
        tenantId,
        intentId,
        action: first.action,
        resourceType: first.resourceType,
        resourceId: first.resourceId,
        metadata: first.metadata,
      })
      .returning();
    expect(await providerActionService.recoverUnsignedIntents(tenantId, intentId)).toBe(2);
    expect(await evidenceRows()).toEqual(
      [{ outbox_id: first.id }, { outbox_id: second.id }].sort((a, b) =>
        a.outbox_id.localeCompare(b.outbox_id),
      ),
    );
  });
});

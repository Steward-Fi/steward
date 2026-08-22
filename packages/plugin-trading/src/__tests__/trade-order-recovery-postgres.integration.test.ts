import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tradeOrderRecoveries,
} from "@stwd/db";
import { and, eq, sql } from "drizzle-orm";
import Redis from "ioredis";
import { DurableIdempotencyStore } from "../routes/idempotency";

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
const enabled = Boolean(databaseUrl && redisUrl && process.env.STEWARD_PGLITE_MEMORY !== "true");
const realServices = enabled ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "");
const tenantId = `trade-recovery-${suffix}`;
const agentId = `trade-recovery-agent-${suffix}`;
const sessionId = `trade-recovery-session-${suffix}`;
const idempotencyScope = `${tenantId}:${agentId}`;
const idempotencyKey = `trade-recovery-key-${suffix}`;
const bodyHash = suffix.padEnd(64, "a").slice(0, 64);
const auditKey = `trade-recovery-audit-${suffix}`;
const fixturePath = new URL("./fixtures/trade-order-recovery-worker.ts", import.meta.url).pathname;
const repositoryRoot = new URL("../../../..", import.meta.url).pathname;

realServices("trade recovery across real PostgreSQL and Redis processes", () => {
  const offline = "postgresql://unused:unused@127.0.0.1:1/unused";
  const admin = createDb(enabled ? databaseUrl! : offline);
  const redis = new Redis(enabled ? redisUrl! : "redis://127.0.0.1:1", {
    lazyConnect: !enabled,
    maxRetriesPerRequest: 1,
  });
  let recoveryId: string;
  let previousAuditKey: string | undefined;

  beforeAll(async () => {
    previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_AUDIT_HMAC_KEY = auditKey;
    __resetAuditHmacKeyCacheForTests();
    expect(await redis.ping()).toBe("PONG");
    const replayStore = new DurableIdempotencyStore<{ status: number; body: unknown }>({
      namespace: "trade-order-recovery-real-services",
      getRedisClient: () => redis,
    });
    const pending = await replayStore.check(idempotencyScope, idempotencyKey, bodyHash);
    const owner = pending.claim ? await pending.claim() : pending;
    if (!owner.store) throw new Error("failed to establish real Redis recovery response owner");
    await owner.store({ status: 200, body: { ok: true, orderId: `venue-${suffix}` } });

    const [row] = await admin.db
      .insert(tradeOrderRecoveries)
      .values({
        tenantId,
        agentId,
        sessionId,
        venue: "hyperliquid",
        idempotencyKeyHash: suffix.padEnd(64, "b").slice(0, 64),
        bodyHash,
        state: "submitted",
        venueIdentity: `venue-${suffix}`,
        effectMetadata: { venue: "hyperliquid", orderId: `venue-${suffix}` },
        venueResult: { status: "filled", orderId: `venue-${suffix}` },
        responseEnvelope: { status: 200, body: { ok: true, orderId: `venue-${suffix}` } },
        claimToken: crypto.randomUUID(),
        claimedAt: new Date(0),
      })
      .returning({ id: tradeOrderRecoveries.id });
    recoveryId = row!.id;
  });

  afterAll(async () => {
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(tradeOrderRecoveries).where(eq(tradeOrderRecoveries.id, recoveryId));
    const storageKey = createHash("sha256")
      .update(
        `${idempotencyScope.length}:${idempotencyScope}${idempotencyKey.length}:${idempotencyKey}`,
        "utf8",
      )
      .digest("hex");
    await redis.del(`idempotency:trade-order-recovery-real-services:${storageKey}`);
    await Promise.all([admin.client.end(), redis.quit()]);
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  });

  test("two cold replicas replay one Redis result and deliver one signed effect", async () => {
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const locker = await admin.client.reserve();
    await locker`select pg_advisory_lock(${gateKey})`;
    let gateLocked = true;
    const env = {
      ...process.env,
      DATABASE_URL: databaseUrl!,
      REDIS_URL: redisUrl!,
      STEWARD_AUDIT_HMAC_KEY: auditKey,
      STEWARD_DB_MODE: "postgres",
      STEWARD_PGLITE_MEMORY: "",
      TEST_RECOVERY_ID: recoveryId,
      TEST_GATE_KEY: String(gateKey),
      TEST_IDEMPOTENCY_SCOPE: idempotencyScope,
      TEST_IDEMPOTENCY_KEY: idempotencyKey,
      TEST_BODY_HASH: bodyHash,
    };
    const workers = [
      Bun.spawn([process.execPath, fixturePath], {
        cwd: repositoryRoot,
        env,
        stdout: "pipe",
        stderr: "pipe",
      }),
      Bun.spawn([process.execPath, fixturePath], {
        cwd: repositoryRoot,
        env,
        stdout: "pipe",
        stderr: "pipe",
      }),
    ];
    try {
      for (let attempt = 0; attempt < 2_000; attempt++) {
        const [waiting] = await admin.client<{ count: string }[]>`
          select count(*)::text as count
          from pg_stat_activity
          where wait_event = 'advisory'
            and query ilike '%pg_advisory_lock_shared%'
        `;
        if (Number(waiting?.count ?? "0") >= 2) break;
        if (attempt === 1_999) throw new Error("trade recovery workers missed the start gate");
        await Bun.sleep(10);
      }
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;
      const outputs = await Promise.all(
        workers.map(async (worker) => {
          const [exit, stdout, stderr] = await Promise.all([
            worker.exited,
            new Response(worker.stdout).text(),
            new Response(worker.stderr).text(),
          ]);
          if (exit !== 0) throw new Error(`trade recovery worker failed (${exit}): ${stderr}`);
          const lastLine = stdout.trim().split("\n").at(-1);
          if (!lastLine) throw new Error("trade recovery worker returned no result");
          return JSON.parse(lastLine) as { delivered: boolean; replay: { status: number } };
        }),
      );
      expect(outputs.every((output) => output.replay.status === 200)).toBe(true);
      expect(outputs.filter((output) => output.delivered)).toHaveLength(1);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
    }

    const evidence = await admin.db
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          sql`${auditEvents.metadata}->>'tradeRecoveryId' = ${recoveryId}`,
        ),
      );
    expect(evidence).toHaveLength(1);
    const [completed] = await admin.db
      .select()
      .from(tradeOrderRecoveries)
      .where(eq(tradeOrderRecoveries.id, recoveryId));
    expect(completed!.state).toBe("completed");
    expect(completed!.auditDeliveredAt).not.toBeNull();
  }, 120_000);
});

import { closeDb, createDb, getDb, tradeOrderRecoveries, writeAuditEvent } from "@stwd/db";
import { eq } from "drizzle-orm";
import Redis from "ioredis";
import { DurableIdempotencyStore } from "../../routes/idempotency";
import { drainTradeRecoveryAudit } from "../../routes/trade-recovery";

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
const recoveryId = process.env.TEST_RECOVERY_ID;
const gateKey = Number(process.env.TEST_GATE_KEY);
const scope = process.env.TEST_IDEMPOTENCY_SCOPE;
const key = process.env.TEST_IDEMPOTENCY_KEY;
const bodyHash = process.env.TEST_BODY_HASH;
if (!databaseUrl || !redisUrl || !recoveryId || !scope || !key || !bodyHash) {
  throw new Error("trade recovery worker fixture is missing required environment");
}
if (!Number.isSafeInteger(gateKey)) throw new Error("invalid recovery worker gate key");

const gate = createDb(databaseUrl).client;
const redis = new Redis(redisUrl, { maxRetriesPerRequest: 1 });
try {
  // The parent owns the exclusive form until both processes are observably
  // waiting. Releasing it starts both cold replicas at the same durable row.
  await gate`select pg_advisory_lock_shared(${gateKey})`;
  await gate`select pg_advisory_unlock_shared(${gateKey})`;

  const replayStore = new DurableIdempotencyStore<{ status: number; body: unknown }>({
    namespace: "trade-order-recovery-real-services",
    getRedisClient: () => redis,
  });
  const replay = await replayStore.check(scope, key, bodyHash);
  if (!replay.record || replay.record.status !== 200) {
    throw new Error("real Redis durable response was not replayable in cold worker");
  }

  const db = getDb();
  const [row] = await db
    .select()
    .from(tradeOrderRecoveries)
    .where(eq(tradeOrderRecoveries.id, recoveryId));
  if (!row) throw new Error("durable recovery row was not found");
  const delivered = await drainTradeRecoveryAudit(db, {
    row,
    writeAuditEvent,
    details: row.effectMetadata,
  });
  process.stdout.write(`${JSON.stringify({ delivered, replay: replay.record })}\n`);
} finally {
  await Promise.allSettled([redis.quit(), gate.end(), closeDb()]);
}

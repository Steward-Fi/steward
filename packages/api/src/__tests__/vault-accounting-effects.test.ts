import { afterAll, beforeAll, beforeEach, describe, expect, test } from "bun:test";
import { agents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { disconnectRedis, getAggregationSnapshot, getRedis, getSpend } from "@stwd/redis";
import { eq } from "drizzle-orm";
import { initRedis, shutdownRedis } from "../middleware/redis";
import {
  __setVaultAccountingEffectFaultForTests,
  completeNonSolanaAccountingEffects,
  stageNonSolanaAccountingEffects,
} from "../services/vault-accounting-effects";

const TENANT_ID = `vault-effects-tenant-${Date.now()}`;
const AGENT_ID = `vault-effects-agent-${Date.now()}`;
const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;
const originalRedisUrl = process.env.REDIS_URL;

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
  else process.env.REDIS_URL = originalRedisUrl;
});

function payload(row: { actionPayload: unknown }): Record<string, unknown> {
  return row.actionPayload as Record<string, unknown>;
}

async function insertEffectRow(input: {
  id: string;
  occurredAt: Date;
  value?: string;
  recordSpend?: boolean;
}) {
  await getDb()
    .insert(transactions)
    .values({
      id: input.id,
      agentId: AGENT_ID,
      status: "broadcast",
      toAddress: "0x1111111111111111111111111111111111111111",
      value: input.value ?? "1000000000000000000",
      chainId: 8453,
      txHash: `0x${input.id.padEnd(64, "0").slice(0, 64)}`,
      signedAt: input.occurredAt,
      actionPayload: stageNonSolanaAccountingEffects(
        { type: "transaction", broadcast: true },
        {
          txId: input.id,
          occurredAt: input.occurredAt,
          shouldAccount: true,
          recordSpend: input.recordSpend,
        },
      ),
    });
}

describe("non-Solana durable vault accounting", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb()
      .insert(tenants)
      .values({
        id: TENANT_ID,
        name: "Vault Effects Tenant",
        apiKeyHash: `hash-${TENANT_ID}`,
      });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Vault Effects Agent",
      walletAddress: "0x2222222222222222222222222222222222222222",
    });
  });

  beforeEach(async () => {
    __setVaultAccountingEffectFaultForTests(null);
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  });

  test("signed-only artifacts have an explicit non-spend contract", () => {
    const occurredAt = new Date("2026-08-20T12:00:00.000Z");
    const staged = stageNonSolanaAccountingEffects(
      { type: "transaction", broadcast: false },
      { txId: "offline", occurredAt, shouldAccount: false },
    );
    expect(staged).toEqual({ type: "transaction", broadcast: false });
  });

  test("assets without vetted USD valuation can aggregate without debiting EVM spend", () => {
    const occurredAt = new Date("2026-08-20T12:00:00.000Z");
    const staged = stageNonSolanaAccountingEffects(
      { type: "monero_transfer", broadcast: true },
      { txId: "monero", occurredAt, shouldAccount: true, recordSpend: false },
    );
    expect(staged.recoveryEffectsEventId).toBe("vault:monero");
    expect(staged.recoveryEffectsOccurredAt).toBe(occurredAt.toISOString());
    expect(staged.recoveryEffectsRecordSpend).toBe(false);
    expect(staged.recoveryEffectsState).toBe("pending");
  });

  test("a configured Redis outage leaves the terminal row durably pending", async () => {
    const occurredAt = new Date("2026-08-18T12:00:00.000Z");
    await insertEffectRow({ id: "redis-outage", occurredAt });
    process.env.REDIS_URL = "redis://127.0.0.1:1";

    expect(
      await completeNonSolanaAccountingEffects({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        txId: "redis-outage",
      }),
    ).toBe(false);

    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, "redis-outage"));
    expect(row?.status).toBe("broadcast");
    expect(payload(row!).recoveryEffectsState).toBe("pending");
    expect(payload(row!).recoveryEffectsEventId).toBe("vault:redis-outage");
    expect(payload(row!).recoveryEffectsOccurredAt).toBe(occurredAt.toISOString());
    if (originalRedisUrl === undefined) delete process.env.REDIS_URL;
    else process.env.REDIS_URL = originalRedisUrl;
  });
});

describeRedis("non-Solana vault accounting with real Redis", () => {
  const originalFetch = globalThis.fetch;

  beforeAll(async () => {
    process.env.REDIS_URL = originalRedisUrl ?? "redis://localhost:6379";
    expect(await initRedis()).toBe(true);
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ pairs: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;
  });

  beforeEach(async () => {
    __setVaultAccountingEffectFaultForTests(null);
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
    const redis = getRedis();
    const keys = await redis.keys(`*${AGENT_ID}*`);
    if (keys.length > 0) await redis.del(...keys);
  });

  afterAll(async () => {
    globalThis.fetch = originalFetch;
    await shutdownRedis();
    await disconnectRedis();
  });

  test("crash after spend, replay, and concurrent workers debit exactly once at the original time", async () => {
    const occurredAt = new Date(Date.now() - 2 * 86_400_000);
    await insertEffectRow({ id: "partial-replay", occurredAt });
    __setVaultAccountingEffectFaultForTests("after_spend");

    expect(
      await completeNonSolanaAccountingEffects({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        txId: "partial-replay",
      }),
    ).toBe(false);

    const outcomes = await Promise.all(
      Array.from({ length: 8 }, () =>
        completeNonSolanaAccountingEffects({
          tenantId: TENANT_ID,
          agentId: AGENT_ID,
          txId: "partial-replay",
        }),
      ),
    );
    expect(outcomes.some(Boolean)).toBe(true);
    expect(
      await completeNonSolanaAccountingEffects({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        txId: "partial-replay",
      }),
    ).toBe(true);

    expect(await getSpend(AGENT_ID, "day", occurredAt)).toBe(10_000);
    expect(await getSpend(AGENT_ID, "day", new Date())).toBe(0);
    expect(
      await getAggregationSnapshot(
        {
          agentId: AGENT_ID,
          metric: "tx_count",
          windowSeconds: 86_400,
          scope: "agent",
          scopeKey: "",
        },
        Date.now(),
      ),
    ).toBe(0n);
    expect(
      await getAggregationSnapshot(
        {
          agentId: AGENT_ID,
          metric: "tx_count",
          windowSeconds: 2_592_000,
          scope: "agent",
          scopeKey: "",
        },
        Date.now(),
      ),
    ).toBe(1n);

    const [row] = await getDb()
      .select()
      .from(transactions)
      .where(eq(transactions.id, "partial-replay"));
    expect(payload(row!).recoveryEffectsState).toBe("complete");
    expect(payload(row!).recoveryEffectsOccurredAt).toBe(occurredAt.toISOString());
  });
});

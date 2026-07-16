/**
 * cumulative-spend-tracker.test.ts — proves the #206 atomic, configurable-window
 * cumulative spend reservation against a REAL Redis (STEWARD_REDIS_TESTS=1).
 *
 * Adversarial coverage:
 *  - reserve admits under cap, rejects at/over cap (boundary is inclusive: a
 *    reserve that lands the sum EXACTLY on max is admitted; one micro over is not).
 *  - REAL concurrency: N parallel reserves that would collectively exceed the cap
 *    admit only as many as fit — the atomic Lua script is single-winner (no
 *    read-then-check race).
 *  - window ageout: an entry older than the trailing window is excluded from the
 *    sum; a boundary entry exactly S seconds old has aged out.
 *  - release reclaims budget; settle keeps it counted.
 *  - scope isolation: operation / agent / grant + currency each get a distinct
 *    bucket (no cross-contamination).
 *  - corrupt member => fail closed (throws / null).
 */

import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { disconnectRedis, getRedis } from "../client.js";
import {
  cumulativeSpendKeyForTest,
  getCumulativeSpendSum,
  releaseCumulativeSpend,
  reserveCumulativeSpend,
  settleCumulativeSpend,
} from "../cumulative-spend-tracker.js";

const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;

const AGENT = `cumspend-test-${Date.now()}`;

async function cleanup() {
  const redis = getRedis();
  let cursor = "0";
  do {
    const [next, keys] = await redis.scan(cursor, "MATCH", `cumspend:${AGENT}*`, "COUNT", 100);
    cursor = next;
    if (keys.length > 0) await redis.del(...keys);
  } while (cursor !== "0");
}

beforeEach(async () => {
  if (!runRedis) return;
  await cleanup();
});

afterAll(async () => {
  if (!runRedis) return;
  await cleanup();
  await disconnectRedis();
});

describeRedis("reserveCumulativeSpend — under / boundary / over", () => {
  test("under cap admits and reports priorSum", async () => {
    const r = await reserveCumulativeSpend({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 5_000_000,
      amount: 1_000_000,
    });
    expect(r.ok).toBe(true);
    expect(r.priorSum).toBe(0);
    expect(typeof r.reservationId).toBe("string");
  });

  test("EXACT boundary admits (sum lands on max), one micro over rejects", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 5_000_000,
    };
    // fill 4M
    expect((await reserveCumulativeSpend({ ...base, amount: 4_000_000 })).ok).toBe(true);
    // +1M => exactly 5M => admit
    expect((await reserveCumulativeSpend({ ...base, amount: 1_000_000 })).ok).toBe(true);
    // +1 => 5_000_001 > 5M => reject
    const over = await reserveCumulativeSpend({ ...base, amount: 1 });
    expect(over.ok).toBe(false);
    expect(over.priorSum).toBe(5_000_000);
    expect(over.reservationId).toBeUndefined();
  });
});

describeRedis("reserveCumulativeSpend — REAL concurrency single-winner", () => {
  test("100 parallel reserves of 100k against a 1M cap admit exactly 10", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 1_000_000,
      amount: 100_000,
    };
    const results = await Promise.all(
      Array.from({ length: 100 }, () => reserveCumulativeSpend({ ...base })),
    );
    const admitted = results.filter((r) => r.ok).length;
    // 1_000_000 / 100_000 = exactly 10 fit; the atomic script must admit no more.
    expect(admitted).toBe(10);
    const snap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
    });
    expect(snap?.sum).toBe(1_000_000);
  });
});

describeRedis("window ageout", () => {
  test("an entry older than the window is excluded from the sum", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 100, // 100s window
      max: 10_000_000,
    };
    const t0 = Date.now();
    // an entry 101s ago (outside the (now-100s, now] window at t0).
    await reserveCumulativeSpend({ ...base, amount: 3_000_000, now: t0 - 101_000 });
    // a fresh reserve at t0 should see priorSum 0 (old entry aged out).
    const r = await reserveCumulativeSpend({ ...base, amount: 1_000_000, now: t0 });
    expect(r.ok).toBe(true);
    expect(r.priorSum).toBe(0);
  });

  test("boundary: an entry EXACTLY windowSeconds old has aged out (half-open)", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 100,
      max: 10_000_000,
    };
    const t0 = Date.now();
    // exactly 100s old => score == windowStart => excluded by the exclusive lower bound.
    await reserveCumulativeSpend({ ...base, amount: 2_000_000, now: t0 - 100_000 });
    const r = await reserveCumulativeSpend({ ...base, amount: 1_000_000, now: t0 });
    expect(r.priorSum).toBe(0);
    // an entry 99s old IS still in-window.
    await cleanup();
    await reserveCumulativeSpend({ ...base, amount: 2_000_000, now: t0 - 99_000 });
    const r2 = await reserveCumulativeSpend({ ...base, amount: 1_000_000, now: t0 });
    expect(r2.priorSum).toBe(2_000_000);
  });
});

describeRedis("release / settle lifecycle", () => {
  test("release reclaims the reserved budget", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 1_000_000,
    };
    const first = await reserveCumulativeSpend({ ...base, amount: 1_000_000 });
    expect(first.ok).toBe(true);
    // cap is now full; a second reserve rejects.
    expect((await reserveCumulativeSpend({ ...base, amount: 1 })).ok).toBe(false);
    // release the first, budget is reclaimed.
    await releaseCumulativeSpend({
      keyParts: { agentId: AGENT, scope: "agent", scopeKey: "", currency: "USD" },
      reservationId: first.reservationId as string,
      amount: 1_000_000,
    });
    const after = await reserveCumulativeSpend({ ...base, amount: 500_000 });
    expect(after.ok).toBe(true);
    expect(after.priorSum).toBe(0);
  });

  test("settle keeps the reservation counted (no-op mark)", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 1_000_000,
    };
    const r = await reserveCumulativeSpend({ ...base, amount: 600_000 });
    await settleCumulativeSpend({
      keyParts: { agentId: AGENT, scope: "agent", scopeKey: "", currency: "USD" },
      reservationId: r.reservationId as string,
    });
    const snap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
    });
    expect(snap?.sum).toBe(600_000);
  });
});

describeRedis("scope + currency isolation", () => {
  test("operation / agent / grant + currency each get a distinct bucket", async () => {
    const k = (scope: "operation" | "agent" | "grant", scopeKey: string, currency: string) =>
      cumulativeSpendKeyForTest({ agentId: AGENT, scope, scopeKey, currency });
    // distinct keys prove no cross-contamination.
    const keys = new Set([
      k("agent", "", "USD"),
      k("operation", "wallet.transfer", "USD"),
      k("grant", "grant-1", "USD"),
      k("agent", "", "USDC"),
    ]);
    expect(keys.size).toBe(4);

    // a reserve in the operation bucket does not affect the agent bucket.
    await reserveCumulativeSpend({
      agentId: AGENT,
      scope: "operation",
      scopeKey: "wallet.transfer",
      currency: "USD",
      windowSeconds: 3600,
      max: 5_000_000,
      amount: 4_000_000,
    });
    const agentSnap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
    });
    expect(agentSnap?.sum).toBe(0);
  });
});

describeRedis("fail closed", () => {
  test("a corrupt member in the bucket makes reserve throw + sum return null", async () => {
    const redis = getRedis();
    const key = cumulativeSpendKeyForTest({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
    });
    // inject a member with no parseable amount.
    await redis.zadd(key, Date.now(), "garbage-no-bars");
    await expect(
      reserveCumulativeSpend({
        agentId: AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "USD",
        windowSeconds: 3600,
        max: 5_000_000,
        amount: 1,
      }),
    ).rejects.toThrow();
    const snap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
    });
    expect(snap).toBeNull();
  });

  test("invalid amount / window throws (never free budget)", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 5_000_000,
    };
    await expect(reserveCumulativeSpend({ ...base, amount: -1 })).rejects.toThrow();
    await expect(reserveCumulativeSpend({ ...base, amount: 1.5 })).rejects.toThrow();
    await expect(
      reserveCumulativeSpend({ ...base, amount: 1, windowSeconds: 0 }),
    ).rejects.toThrow();
  });
});

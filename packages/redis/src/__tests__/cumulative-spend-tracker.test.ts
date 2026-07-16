/**
 * cumulative-spend-tracker.test.ts - proves the #206 atomic, configurable-window
 * cumulative spend reservation against a REAL Redis (STEWARD_REDIS_TESTS=1).
 *
 * Adversarial coverage:
 *  - reserve admits under cap, rejects at/over cap (boundary is inclusive: a
 *    reserve that lands the sum EXACTLY on max is admitted; one micro over is not).
 *  - REAL concurrency: N parallel reserves that would collectively exceed the cap
 *    admit only as many as fit - the atomic Lua script is single-winner (no
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
  getWindowedInvokeCount,
  recordWindowedInvoke,
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

describeRedis("reserveCumulativeSpend - under / boundary / over", () => {
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

describeRedis("reserveCumulativeSpend - REAL concurrency single-winner", () => {
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
      max: 1_000_000,
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
      keyParts: {
        agentId: AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "USD",
        windowSeconds: 3600,
        max: 1_000_000,
      },
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
      keyParts: {
        agentId: AGENT,
        scope: "agent",
        scopeKey: "",
        currency: "USD",
        windowSeconds: 3600,
        max: 1_000_000,
      },
      reservationId: r.reservationId as string,
    });
    const snap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 1_000_000,
    });
    expect(snap?.sum).toBe(600_000);
  });
});

describeRedis("scope + currency isolation", () => {
  test("operation / agent / grant + currency each get a distinct bucket", async () => {
    const k = (scope: "operation" | "agent" | "grant", scopeKey: string, currency: string) =>
      cumulativeSpendKeyForTest({
        agentId: AGENT,
        scope,
        scopeKey,
        currency,
        windowSeconds: 3600,
        max: 5_000_000,
      });
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
      max: 5_000_000,
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
      windowSeconds: 3600,
      max: 5_000_000,
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
      max: 5_000_000,
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

  test("over-retention window (> 30d) throws / sum returns null (codex P1)", async () => {
    const base = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      max: 5_000_000,
    };
    // 30d + 1s is beyond retention; reserving would silently clamp => reject.
    await expect(
      reserveCumulativeSpend({ ...base, windowSeconds: 2_592_001, amount: 1 }),
    ).rejects.toThrow();
    const snap = await getCumulativeSpendSum({
      agentId: AGENT,
      scope: "agent",
      scopeKey: "",
      currency: "USD",
      windowSeconds: 2_592_001,
      max: 5_000_000,
    });
    expect(snap).toBeNull();
    // exactly 30d is allowed.
    const ok = await reserveCumulativeSpend({ ...base, windowSeconds: 2_592_000, amount: 1 });
    expect(ok.ok).toBe(true);
  });
});

describeRedis("windowed invoke count (#206 maxCalls + callWindow wiring)", () => {
  test("count starts at 0, increments per recorded invoke, and reads back", async () => {
    const base = {
      agentId: AGENT,
      operationKey: "wallet.transfer",
      windowSeconds: 3600,
      max: 3,
    };
    expect(await getWindowedInvokeCount(base)).toBe(0);
    await recordWindowedInvoke(base);
    expect(await getWindowedInvokeCount(base)).toBe(1);
    await recordWindowedInvoke(base);
    await recordWindowedInvoke(base);
    expect(await getWindowedInvokeCount(base)).toBe(3);
    // At the cap, a further record does not grow the count past max (reserve
    // rejects), and the read reports max so the policy denies.
    await recordWindowedInvoke(base);
    expect(await getWindowedInvokeCount(base)).toBe(3);
  });

  test("count ages out at the window edge", async () => {
    const base = {
      agentId: AGENT,
      operationKey: "wallet.transfer",
      windowSeconds: 100,
      max: 10,
    };
    const t0 = Date.now();
    await recordWindowedInvoke({ ...base, now: t0 - 101_000 });
    // 101s old => aged out => count at t0 is 0.
    expect(await getWindowedInvokeCount({ ...base, now: t0 })).toBe(0);
  });

  test("over-retention count window returns null (fail closed)", async () => {
    expect(
      await getWindowedInvokeCount({
        agentId: AGENT,
        operationKey: "wallet.transfer",
        windowSeconds: 2_592_001,
        max: 3,
      }),
    ).toBeNull();
  });
});

describeRedis("distinct caps on the same scope are independent buckets (codex P2)", () => {
  test("same scope+currency but different windows do NOT share a bucket", async () => {
    // Two caps: (agent, USD, 1h, max 1M) and (agent, USD, 24h, max 1M). A reserve
    // against the 1h cap must NOT show up in the 24h cap's sum, and vice versa.
    const shortCap = {
      agentId: AGENT,
      scope: "agent" as const,
      scopeKey: "",
      currency: "USD",
      windowSeconds: 3600,
      max: 1_000_000,
    };
    const longCap = { ...shortCap, windowSeconds: 86400 };
    const r = await reserveCumulativeSpend({ ...shortCap, amount: 400_000 });
    expect(r.ok).toBe(true);
    // the long-window cap's bucket is independent => its prior sum is still 0.
    const longSnap = await getCumulativeSpendSum(longCap);
    expect(longSnap?.sum).toBe(0);
    // and the short cap sees its own 400k.
    const shortSnap = await getCumulativeSpendSum(shortCap);
    expect(shortSnap?.sum).toBe(400_000);
  });
});

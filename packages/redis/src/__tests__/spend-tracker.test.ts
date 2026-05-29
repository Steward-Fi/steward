import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { disconnectRedis, getRedis } from "../client.js";
import {
  checkSpendLimit,
  getSpend,
  getSpendByHost,
  isoWeek,
  recordSpend,
  reserveSpend,
  settleReservedSpend,
} from "../spend-tracker.js";

const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;

const TEST_AGENT = `test-agent-${Date.now()}`;
const TEST_TENANT = "test-tenant-1";

beforeEach(async () => {
  if (!runRedis) return;
  // Clean up test keys
  const redis = getRedis();
  let cursor = "0";
  do {
    const [newCursor, keys] = await redis.scan(
      cursor,
      "MATCH",
      `spend:${TEST_AGENT}:*`,
      "COUNT",
      100,
    );
    cursor = newCursor;
    if (keys.length > 0) await redis.del(...keys);
  } while (cursor !== "0");
});

afterAll(async () => {
  if (!runRedis) return;
  await disconnectRedis();
});

describe("isoWeek (ISO-8601)", () => {
  const at = (s: string) => isoWeek(new Date(s));

  test("2026-01-01 is in ISO week 2026-W01 (Thursday)", () => {
    expect(at("2026-01-01T00:00:00Z")).toEqual({ isoYear: 2026, isoWeek: 1 });
  });

  test("year boundary 2025-12-29..2026-01-04 is one contiguous ISO week", () => {
    // Mon 2025-12-29 through Sun 2026-01-04 all belong to ISO week-year 2026, W01.
    for (const d of [
      "2025-12-29",
      "2025-12-30",
      "2025-12-31",
      "2026-01-01",
      "2026-01-02",
      "2026-01-03",
      "2026-01-04",
    ]) {
      expect(at(`${d}T12:00:00Z`)).toEqual({ isoYear: 2026, isoWeek: 1 });
    }
  });

  test("2025-12-28 (Sunday) is the last week of ISO 2025", () => {
    expect(at("2025-12-28T00:00:00Z")).toEqual({ isoYear: 2025, isoWeek: 52 });
  });

  test("mid-year date 2026-06-15 is W25", () => {
    expect(at("2026-06-15T00:00:00Z")).toEqual({ isoYear: 2026, isoWeek: 25 });
  });
});

describeRedis("Spend Tracker", () => {
  test("records and queries spend", async () => {
    await recordSpend(TEST_AGENT, TEST_TENANT, 0.05, "api.openai.com");
    await recordSpend(TEST_AGENT, TEST_TENANT, 0.03, "api.openai.com");

    const daySpend = await getSpend(TEST_AGENT, "day");
    expect(daySpend).toBeCloseTo(0.08, 4);

    const weekSpend = await getSpend(TEST_AGENT, "week");
    expect(weekSpend).toBeCloseTo(0.08, 4);

    const monthSpend = await getSpend(TEST_AGENT, "month");
    expect(monthSpend).toBeCloseTo(0.08, 4);
  });

  test("tracks per-host breakdown", async () => {
    await recordSpend(TEST_AGENT, TEST_TENANT, 0.1, "api.openai.com");
    await recordSpend(TEST_AGENT, TEST_TENANT, 0.05, "api.anthropic.com");
    await recordSpend(TEST_AGENT, TEST_TENANT, 0.02, "api.openai.com");

    const byHost = await getSpendByHost(TEST_AGENT, "day");
    expect(byHost["api.openai.com"]).toBeCloseTo(0.12, 4);
    expect(byHost["api.anthropic.com"]).toBeCloseTo(0.05, 4);
  });

  test("checks spend limit — under limit", async () => {
    await recordSpend(TEST_AGENT, TEST_TENANT, 10.0, "api.openai.com");

    const result = await checkSpendLimit(TEST_AGENT, 50.0, "day");
    expect(result.allowed).toBe(true);
    expect(result.spent).toBeCloseTo(10.0, 2);
    expect(result.reserved).toBe(0);
    expect(result.effectiveSpent).toBeCloseTo(10.0, 2);
    expect(result.remaining).toBeCloseTo(40.0, 2);
  });

  test("checks spend limit — over limit", async () => {
    await recordSpend(TEST_AGENT, TEST_TENANT, 55.0, "api.openai.com");

    const result = await checkSpendLimit(TEST_AGENT, 50.0, "day");
    expect(result.allowed).toBe(false);
    expect(result.spent).toBeCloseTo(55.0, 2);
    expect(result.remaining).toBe(0);
  });

  test("zero cost is ignored, negative throws", async () => {
    await recordSpend(TEST_AGENT, TEST_TENANT, 0, "api.unknown.com");
    // A sign error upstream must not silently floor to a free spend.
    await expect(recordSpend(TEST_AGENT, TEST_TENANT, -1, "api.unknown.com")).rejects.toThrow();
    await expect(reserveSpend(TEST_AGENT, TEST_TENANT, -1, { day: 1 })).rejects.toThrow();
    await expect(
      recordSpend(TEST_AGENT, TEST_TENANT, Number.NaN, "api.unknown.com"),
    ).rejects.toThrow();

    const spend = await getSpend(TEST_AGENT, "day");
    expect(spend).toBe(0);
  });

  test("concurrent reservations cannot exceed the cap", async () => {
    // limit $1, each reserves $0.4 → at most 2 may succeed (0.8 ≤ 1.0).
    const results = await Promise.allSettled(
      Array.from({ length: 5 }, () => reserveSpend(TEST_AGENT, TEST_TENANT, 0.4, { day: 1 })),
    );
    const ok = results.filter((r) => r.status === "fulfilled").length;
    expect(ok).toBe(2);

    const snap = await checkSpendLimit(TEST_AGENT, 1, "day");
    expect(snap.effectiveSpent).toBeLessThanOrEqual(1);
    expect(snap.reserved).toBeCloseTo(0.8, 4);
  });

  test("high precision costs are conservatively tracked", async () => {
    // $0.000123 per request × 100 requests = $0.0123
    for (let i = 0; i < 100; i++) {
      await recordSpend(TEST_AGENT, TEST_TENANT, 0.000123, "api.openai.com");
    }

    const spend = await getSpend(TEST_AGENT, "day");
    // Positive costs round up to the smallest enforcement unit so micro-calls
    // cannot round down to free spend.
    expect(spend).toBeCloseTo(0.02, 2);
  });

  test("reserved spend counts against limits until settled", async () => {
    const reservation = await reserveSpend(TEST_AGENT, TEST_TENANT, 0.4, { day: 1 });
    expect(reservation.reservedUsd).toBeCloseTo(0.4, 4);
    expect(reservation.buckets).toHaveLength(1);
    expect(reservation.buckets[0]?.key).toContain(`spend:${TEST_AGENT}:day:`);

    const reserved = await checkSpendLimit(TEST_AGENT, 1, "day");
    expect(reserved.allowed).toBe(true);
    expect(reserved.spent).toBe(0);
    expect(reserved.reserved).toBeCloseTo(0.4, 4);
    expect(reserved.effectiveSpent).toBeCloseTo(0.4, 4);

    await settleReservedSpend(
      TEST_AGENT,
      TEST_TENANT,
      reservation.reservedUsd,
      0.25,
      "api.openai.com",
      reservation.periods,
      reservation.buckets,
    );

    const settled = await checkSpendLimit(TEST_AGENT, 1, "day");
    expect(settled.spent).toBeCloseTo(0.25, 4);
    expect(settled.reserved).toBe(0);
    expect(settled.remaining).toBeCloseTo(0.75, 4);
  });
});

import { afterAll, beforeEach, describe, expect, test } from "bun:test";
import { getAggregationSnapshot, recordAggregationEvent } from "../aggregation-tracker.js";
import { disconnectRedis, getRedis } from "../client.js";

// Gated like the other Redis-backed suites: requires a live Redis (the tracker
// uses server-side Lua over sorted sets, which cannot be faithfully faked).
const runRedis = process.env.STEWARD_REDIS_TESTS === "1";
const describeRedis = runRedis ? describe : describe.skip;

const TEST_PREFIX = "agg";

function agentId(suffix: string): string {
  return `test-agent-${suffix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
}

beforeEach(async () => {
  if (!runRedis) return;
  const redis = getRedis();
  let cursor = "0";
  do {
    const [newCursor, keys] = await redis.scan(
      cursor,
      "MATCH",
      `${TEST_PREFIX}:test-agent-*`,
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

describeRedis("aggregation tracker", () => {
  test("value_sum accumulates exact bigint over the agent window", async () => {
    const agent = agentId("value");
    const now = Date.now();
    await recordAggregationEvent({
      agentId: agent,
      to: "0xabc",
      chainId: 8453,
      valueRaw: (3n * 10n ** 18n).toString(),
      timestamp: now - 1000,
    });
    await recordAggregationEvent({
      agentId: agent,
      to: "0xdef",
      chainId: 8453,
      valueRaw: (2n * 10n ** 18n).toString(),
      timestamp: now - 500,
    });

    const sum = await getAggregationSnapshot(
      { agentId: agent, metric: "value_sum", windowSeconds: 86400, scope: "agent", scopeKey: "" },
      now,
    );
    expect(sum).toBe(5n * 10n ** 18n);
  });

  test("tx_count counts events in the agent window", async () => {
    const agent = agentId("count");
    const now = Date.now();
    for (let i = 0; i < 4; i++) {
      await recordAggregationEvent({
        agentId: agent,
        to: "0xabc",
        chainId: 8453,
        valueRaw: "1",
        timestamp: now - i * 100,
      });
    }
    const count = await getAggregationSnapshot(
      { agentId: agent, metric: "tx_count", windowSeconds: 3600, scope: "agent", scopeKey: "" },
      now,
    );
    expect(count).toBe(4n);
  });

  test("window boundary is half-open (now - S*1000, now]: event exactly at edge excluded", async () => {
    const agent = agentId("boundary");
    const now = Date.now();
    const windowSeconds = 3600;
    // Event exactly at the window start (now - windowMs) must be EXCLUDED.
    await recordAggregationEvent({
      agentId: agent,
      to: "0xabc",
      chainId: 8453,
      valueRaw: "100",
      timestamp: now - windowSeconds * 1000,
    });
    // Event one ms inside the window must be INCLUDED.
    await recordAggregationEvent({
      agentId: agent,
      to: "0xabc",
      chainId: 8453,
      valueRaw: "7",
      timestamp: now - windowSeconds * 1000 + 1,
    });

    const sum = await getAggregationSnapshot(
      { agentId: agent, metric: "value_sum", windowSeconds, scope: "agent", scopeKey: "" },
      now,
    );
    expect(sum).toBe(7n);
  });

  test("per_recipient scope isolates sums by recipient", async () => {
    const agent = agentId("recipient");
    const now = Date.now();
    const alice = "0xAlIcE000000000000000000000000000000000a";
    const bob = "0xb0b0000000000000000000000000000000000b0b";
    await recordAggregationEvent({
      agentId: agent,
      to: alice,
      chainId: 8453,
      valueRaw: "10",
      timestamp: now - 100,
    });
    await recordAggregationEvent({
      agentId: agent,
      to: bob,
      chainId: 8453,
      valueRaw: "999",
      timestamp: now - 100,
    });

    const aliceSum = await getAggregationSnapshot(
      {
        agentId: agent,
        metric: "value_sum",
        windowSeconds: 86400,
        scope: "per_recipient",
        scopeKey: alice.toLowerCase(),
      },
      now,
    );
    expect(aliceSum).toBe(10n);
  });

  test("per_chain scope isolates counts by chain", async () => {
    const agent = agentId("chain");
    const now = Date.now();
    await recordAggregationEvent({
      agentId: agent,
      to: "0xabc",
      chainId: 8453,
      valueRaw: "1",
      timestamp: now - 100,
    });
    await recordAggregationEvent({
      agentId: agent,
      to: "0xabc",
      chainId: 42161,
      valueRaw: "1",
      timestamp: now - 100,
    });
    const baseCount = await getAggregationSnapshot(
      {
        agentId: agent,
        metric: "tx_count",
        windowSeconds: 3600,
        scope: "per_chain",
        scopeKey: "8453",
      },
      now,
    );
    expect(baseCount).toBe(1n);
  });

  test("unique_recipients dedupes repeated recipients within the window", async () => {
    const agent = agentId("unique");
    const now = Date.now();
    const alice = "0xalice00000000000000000000000000000000a1";
    for (let i = 0; i < 3; i++) {
      await recordAggregationEvent({
        agentId: agent,
        to: alice,
        chainId: 8453,
        valueRaw: "1",
        timestamp: now - i * 10,
      });
    }
    await recordAggregationEvent({
      agentId: agent,
      to: "0xbob000000000000000000000000000000000b0b",
      chainId: 8453,
      valueRaw: "1",
      timestamp: now - 5,
    });
    const unique = await getAggregationSnapshot(
      {
        agentId: agent,
        metric: "unique_recipients",
        windowSeconds: 86400,
        scope: "agent",
        scopeKey: "",
      },
      now,
    );
    expect(unique).toBe(2n);
  });

  test("non-positive window returns null (caller fails closed)", async () => {
    const agent = agentId("badwindow");
    const snap = await getAggregationSnapshot(
      { agentId: agent, metric: "tx_count", windowSeconds: 0, scope: "agent", scopeKey: "" },
      Date.now(),
    );
    expect(snap).toBeNull();
  });

  test("invalid valueRaw on record throws (no silent free spend)", async () => {
    await expect(
      recordAggregationEvent({
        agentId: agentId("bad"),
        to: "0xabc",
        chainId: 8453,
        valueRaw: "-5",
      }),
    ).rejects.toThrow();
  });
});

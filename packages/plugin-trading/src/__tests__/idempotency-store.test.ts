import { describe, expect, it } from "bun:test";
import type { IoredisLike } from "@stwd/redis";
import { DurableIdempotencyStore } from "../routes/idempotency";

/**
 * SEC-043: trade/operator idempotency records must be DURABLE — backed by
 * Redis when a client is available so a restart or a second replica still
 * dedups a retried withdraw/order — with the bounded in-memory map as the
 * dev/single-replica fallback.
 */

type TestRecord = { status: number; body: unknown };

/** Minimal in-memory IoredisLike double (records raw set args for assertions). */
function fakeRedis() {
  const data = new Map<string, string>();
  const setCalls: Array<{ key: string; ttlMs?: number; condition?: string }> = [];
  const client = {
    get: async (key: string) => data.get(key) ?? null,
    set: async (...args: unknown[]) => {
      const key = args[0] as string;
      const value = args[1] as string;
      const mode = args[2] as string | undefined;
      const ttlMs = mode === "PX" ? (args[3] as number) : undefined;
      const condition = args[4] as string | undefined;
      setCalls.push({ key, ttlMs, condition });
      if (condition === "NX" && data.has(key)) return null;
      data.set(key, value);
      return "OK";
    },
    eval: async (
      script: string,
      _numKeys: number,
      key: string,
      token: string,
      ...args: unknown[]
    ) => {
      const raw = data.get(key);
      if (!raw) return 0;
      const current = JSON.parse(raw) as { state?: string; claimToken?: string };
      if (current.state !== "pending" || current.claimToken !== token) return 0;
      if (script.includes('redis.call("DEL"')) {
        data.delete(key);
      } else {
        data.set(key, args[0] as string);
      }
      return 1;
    },
  } as unknown as IoredisLike;
  return { client, data, setCalls };
}

describe("DurableIdempotencyStore (SEC-043)", () => {
  it("replays a stored outcome across store instances sharing Redis (restart / second replica)", async () => {
    const { client } = fakeRedis();
    const replicaA = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade:operator",
      getRedisClient: () => client,
    });
    const checked = await replicaA.check("tenant:withdraw", "key-1", "hash-1");
    const first = await checked.claim?.();
    expect(first.record).toBeUndefined();
    expect(first.conflict).toBeUndefined();
    await first.store?.({ status: 200, body: { ok: true, data: { moved: true } } });

    // A fresh instance = a restarted process or a second replica. Its memory
    // map is empty; the replay must come from the durable record.
    const replicaB = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade:operator",
      getRedisClient: () => client,
    });
    const replay = await replicaB.check("tenant:withdraw", "key-1", "hash-1");
    expect(replay.record).toEqual({ status: 200, body: { ok: true, data: { moved: true } } });
    expect(replay.store).toBeUndefined();
  });

  it("flags a same-key/different-body reuse as a conflict (via Redis)", async () => {
    const { client } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const checked = await store.check("scope", "key-1", "hash-1");
    const first = await checked.claim?.();
    await first.store?.({ status: 502, body: { ok: false } });

    const conflict = await store.check("scope", "key-1", "hash-DIFFERENT");
    expect(conflict.conflict).toBe(true);
    expect(conflict.record).toBeUndefined();
    expect(conflict.store).toBeUndefined();
  });

  it("stores with the 24h TTL via PX", async () => {
    const { client, setCalls } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const initial = await store.check("scope", "key-1", "hash-1");
    const check = await initial.claim?.();
    await check.store?.({ status: 200, body: { ok: true } });
    expect(setCalls).toHaveLength(1);
    expect(setCalls[0]?.ttlMs).toBe(24 * 60 * 60 * 1000);
    expect(setCalls[0]?.condition).toBe("NX");
  });

  it("fails CLOSED when the Redis check errors (never executes without the dedup record)", async () => {
    const broken = {
      get: async () => {
        throw new Error("redis down");
      },
      set: async () => "OK",
    } as unknown as IoredisLike;
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => broken,
    });
    await expect(store.check("scope", "key-1", "hash-1")).rejects.toThrow("redis down");
  });

  it("reports a swallowed Redis store error so callers can require a durable fallback", async () => {
    const data = new Map<string, string>();
    const broken = {
      get: async () => null,
      set: async (key: string, value: string) => {
        data.set(key, value);
        return "OK";
      },
      eval: async () => {
        throw new Error("redis down");
      },
    } as unknown as IoredisLike;
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => broken,
    });
    const initial = await store.check("scope", "key-1", "hash-1");
    const check = await initial.claim?.();
    await expect(check.store?.({ status: 200, body: {} })).resolves.toBe(false);
  });

  it("falls back to bounded process-local memory without Redis (replay in-process only)", async () => {
    const noRedis = () => null;
    const storeA = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: noRedis,
    });
    const checked = await storeA.check("scope", "key-1", "hash-1");
    const first = await checked.claim?.();
    await first.store?.({ status: 200, body: { ok: true } });

    // Same process: replay works.
    const replay = await storeA.check("scope", "key-1", "hash-1");
    expect(replay.record).toEqual({ status: 200, body: { ok: true } });

    // A fresh instance (restart) does NOT see it — the documented fallback
    // limitation that Redis closes in production.
    const storeB = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: noRedis,
    });
    const missed = await storeB.check("scope", "key-1", "hash-1");
    expect(missed.record).toBeUndefined();
  });

  it("no key -> no dedup (unchanged wave-2 semantics)", async () => {
    const { client } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    expect(await store.check("scope", undefined, "hash-1")).toEqual({});
  });

  it("fails closed instead of evicting live records when the memory fallback is saturated", async () => {
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => null,
    });
    // Fill the fallback map to the 1_000-entry cap with LIVE records.
    for (let i = 0; i < 1_000; i++) {
      const checked = await store.check("scope", `flood-${i}`, `hash-${i}`);
      const claim = await checked.claim?.();
      await claim?.store?.({ status: 200, body: { ok: true, i } });
    }
    // A new key must be refused — shedding the oldest live record would
    // silently re-enable a duplicate fund movement on its retry.
    const overflow = await store.check("scope", "flood-overflow", "hash-overflow");
    await expect(overflow.claim?.()).rejects.toThrow("saturated with live records");

    // …and the oldest record is still intact: its retry replays, never re-executes.
    const replay = await store.check("scope", "flood-0", "hash-0");
    expect(replay.record).toEqual({ status: 200, body: { ok: true, i: 0 } });
  });

  it("preserves an in-flight claim when completed records saturate the memory fallback", async () => {
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => null,
    });
    const inFlight = await store.check("scope", "in-flight", "in-flight-hash");
    expect((await inFlight.claim?.())?.store).toBeDefined();

    for (let i = 0; i < 999; i++) {
      const checked = await store.check("scope", `completed-${i}`, `hash-${i}`);
      await (await checked.claim?.())?.store?.({ status: 200, body: { i } });
    }

    const overflow = await store.check("scope", "overflow", "overflow-hash");
    await expect(overflow.claim?.()).rejects.toThrow("saturated with live records");

    // Losing this pending marker would allow a retry to claim the key and
    // execute the external movement a second time while the first is ongoing.
    const retry = await store.check("scope", "in-flight", "in-flight-hash");
    expect(retry.inProgress).toBe(true);
    expect(retry.claim).toBeUndefined();
  });

  it("still sweeps expired entries before refusing a new claim", async () => {
    const realNow = Date.now;
    const t0 = realNow();
    let fakeNow = t0;
    Date.now = () => fakeNow;
    try {
      const store = new DurableIdempotencyStore<TestRecord>({
        namespace: "trade",
        getRedisClient: () => null,
      });
      for (let i = 0; i < 1_000; i++) {
        const checked = await store.check("scope", `old-${i}`, `hash-${i}`);
        await (await checked.claim?.())?.store?.({ status: 200, body: { i } });
      }
      // 25h later every entry is past the 24h TTL; the expired-only sweep must
      // free the map so a new claim succeeds (no false saturation).
      fakeNow = t0 + 25 * 60 * 60 * 1000;
      const checked = await store.check("scope", "new-key", "new-hash");
      const claim = await checked.claim?.();
      expect(claim?.store).toBeDefined();
    } finally {
      Date.now = realNow;
    }
  });

  it("atomically admits only one concurrent replica for the same key", async () => {
    const { client } = fakeRedis();
    const replicaA = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const replicaB = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const [checkA, checkB] = await Promise.all([
      replicaA.check("scope", "same-key", "same-body"),
      replicaB.check("scope", "same-key", "same-body"),
    ]);
    const [claimA, claimB] = await Promise.all([checkA.claim?.(), checkB.claim?.()]);
    expect([claimA?.store !== undefined, claimB?.store !== undefined].filter(Boolean)).toHaveLength(
      1,
    );
    expect([claimA?.inProgress, claimB?.inProgress].filter(Boolean)).toHaveLength(1);
  });

  it("releases a pre-execution claim so a corrected retry can execute", async () => {
    const { client } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const initial = await store.check("scope", "key-1", "hash-1");
    const owned = await initial.claim?.();
    await owned?.release?.();
    const retry = await store.check("scope", "key-1", "hash-1");
    expect((await retry.claim?.())?.store).toBeDefined();
  });

  it("fails closed on a malformed durable record instead of overwriting it", async () => {
    const { client, data, setCalls } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    const initial = await store.check("scope", "key-1", "hash-1");
    await initial.claim?.();
    const durableKey = setCalls[0]?.key;
    expect(durableKey).toMatch(/^idempotency:trade:[a-f0-9]{64}$/);
    data.set(durableKey!, "not-json");
    await expect(store.check("scope", "key-1", "hash-1")).rejects.toThrow(
      "Malformed durable idempotency record",
    );
  });

  it("uses collision-safe opaque keys for delimiter-containing tenant scopes", async () => {
    const { client, setCalls } = fakeRedis();
    const store = new DurableIdempotencyStore<TestRecord>({
      namespace: "trade",
      getRedisClient: () => client,
    });
    await (await store.check("tenant:a", "b:key", "hash-1")).claim?.();
    await (await store.check("tenant", "a:b:key", "hash-2")).claim?.();
    expect(setCalls).toHaveLength(2);
    expect(setCalls[0]?.key).not.toBe(setCalls[1]?.key);
    expect(setCalls[0]?.key).toMatch(/^idempotency:trade:[a-f0-9]{64}$/);
    expect(setCalls[0]?.key).not.toContain("tenant");
    expect(setCalls[0]?.key).not.toContain("b:key");
  });

  it("fails closed in production when durable Redis idempotency is unavailable", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalAcknowledgement = process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    try {
      const store = new DurableIdempotencyStore<TestRecord>({
        namespace: "trade",
        getRedisClient: () => null,
      });
      await expect(store.check("scope", "key-1", "hash-1")).rejects.toThrow(
        "Trading idempotency requires Redis in production",
      );
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalAcknowledgement === undefined) {
        delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
      } else {
        process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = originalAcknowledgement;
      }
    }
  });

  it("fails closed in the Workers runtime even when NODE_ENV is unset", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalRuntime = process.env.STEWARD_RUNTIME;
    const originalAcknowledgement = process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    delete process.env.NODE_ENV;
    process.env.STEWARD_RUNTIME = "workers";
    delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    try {
      const store = new DurableIdempotencyStore<TestRecord>({
        namespace: "trade",
        getRedisClient: () => null,
      });
      await expect(store.check("scope", "key-1", "hash-1")).rejects.toThrow(
        "Trading idempotency requires Redis in production",
      );
    } finally {
      if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = originalNodeEnv;
      if (originalRuntime === undefined) delete process.env.STEWARD_RUNTIME;
      else process.env.STEWARD_RUNTIME = originalRuntime;
      if (originalAcknowledgement === undefined) {
        delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
      } else {
        process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY = originalAcknowledgement;
      }
    }
  });
});

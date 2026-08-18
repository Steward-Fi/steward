import { describe, expect, it } from "bun:test";
import type { IoredisLike } from "@stwd/redis";
import { DurableIdempotencyStore } from "../routes/idempotency";

type TestRecord = { status: number; body: unknown };

/** Minimal Redis double with real SET NX and owner-CAS completion semantics. */
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
    eval: async (_script: string, _numKeys: number, ...args: Array<string | number>) => {
      const [key, expected, replacement] = args as [string, string, string, number];
      if (data.get(key) !== expected) return 0;
      data.set(key, replacement);
      return 1;
    },
  } as unknown as IoredisLike;
  return { client, data, setCalls };
}

function makeStore(client: IoredisLike | null, namespace = "trade") {
  return new DurableIdempotencyStore<TestRecord>({
    namespace,
    getRedisClient: () => client,
  });
}

describe("DurableIdempotencyStore (SEC-043)", () => {
  it("replays a completed outcome across restarts / replicas", async () => {
    const { client } = fakeRedis();
    const replicaA = makeStore(client, "trade:operator");
    expect(await replicaA.check("tenant:withdraw", "key-1", "hash-1")).toEqual({});
    const claim = await replicaA.reserve("tenant:withdraw", "key-1", "hash-1");
    expect(claim.store).toBeFunction();
    await claim.store?.({ status: 200, body: { ok: true, data: { moved: true } } });

    const replicaB = makeStore(client, "trade:operator");
    const replay = await replicaB.check("tenant:withdraw", "key-1", "hash-1");
    expect(replay.record).toEqual({ status: 200, body: { ok: true, data: { moved: true } } });
    expect(replay.store).toBeUndefined();
  });

  it("atomically permits only one concurrent claimant across replicas", async () => {
    const { client } = fakeRedis();
    const replicaA = makeStore(client);
    const replicaB = makeStore(client);
    const [a, b] = await Promise.all([
      replicaA.reserve("scope", "same-key", "same-hash"),
      replicaB.reserve("scope", "same-key", "same-hash"),
    ]);
    expect([a, b].filter((result) => result.store)).toHaveLength(1);
    expect([a, b].filter((result) => result.pending)).toHaveLength(1);
  });

  it("keeps retries fail-closed after a crash before completion", async () => {
    const { client } = fakeRedis();
    const replicaA = makeStore(client);
    const claim = await replicaA.reserve("scope", "key-1", "hash-1");
    expect(claim.store).toBeFunction();

    // Simulate process death: never invoke store(). A restarted replica sees
    // the durable processing marker and must not receive execution ownership.
    const replicaB = makeStore(client);
    expect(await replicaB.check("scope", "key-1", "hash-1")).toEqual({ pending: true });
    expect(await replicaB.reserve("scope", "key-1", "hash-1")).toEqual({ pending: true });
  });

  it("flags same-key/different-body reuse while processing or completed", async () => {
    const { client } = fakeRedis();
    const store = makeStore(client);
    const claim = await store.reserve("scope", "key-1", "hash-1");
    expect((await store.reserve("scope", "key-1", "different")).conflict).toBe(true);
    await claim.store?.({ status: 502, body: { ok: false } });
    expect((await store.check("scope", "key-1", "different")).conflict).toBe(true);
  });

  it("claims with a 24h PX TTL and NX", async () => {
    const { client, setCalls } = fakeRedis();
    const store = makeStore(client);
    await store.reserve("scope", "key-1", "hash-1");
    expect(setCalls).toHaveLength(1);
    expect(setCalls[0]).toMatchObject({
      ttlMs: 24 * 60 * 60 * 1000,
      condition: "NX",
    });
    expect(setCalls[0]?.key).toMatch(/^idempotency:trade:[a-f0-9]{64}$/);
  });

  it("fails closed on Redis read/reservation errors and malformed durable state", async () => {
    const readBroken = {
      get: async () => {
        throw new Error("redis down");
      },
    } as unknown as IoredisLike;
    await expect(makeStore(readBroken).check("scope", "key-1", "hash-1")).rejects.toThrow(
      "redis down",
    );

    const reserveBroken = {
      get: async () => null,
      set: async () => {
        throw new Error("redis down");
      },
    } as unknown as IoredisLike;
    await expect(makeStore(reserveBroken).reserve("scope", "key-1", "hash-1")).rejects.toThrow(
      "redis down",
    );

    const malformed = fakeRedis();
    await makeStore(malformed.client).reserve("scope", "key-1", "hash-1");
    const malformedKey = malformed.setCalls[0]?.key;
    malformed.data.set(malformedKey!, "not-json");
    await expect(makeStore(malformed.client).check("scope", "key-1", "hash-1")).rejects.toThrow(
      "malformed",
    );
  });

  it("leaves the processing marker in place when completion persistence fails", async () => {
    const { client, data, setCalls } = fakeRedis();
    const brokenCompletion = {
      ...client,
      eval: async () => {
        throw new Error("redis down");
      },
    } as IoredisLike;
    const store = makeStore(brokenCompletion);
    const claim = await store.reserve("scope", "key-1", "hash-1");
    await expect(claim.store?.({ status: 200, body: {} })).resolves.toBeUndefined();
    expect(JSON.parse(data.get(setCalls[0]!.key) ?? "{}").state).toBe("processing");
    expect((await store.check("scope", "key-1", "hash-1")).pending).toBe(true);
  });

  it("atomically suppresses concurrent requests in the memory fallback", async () => {
    const store = makeStore(null);
    const [a, b] = await Promise.all([
      store.reserve("scope", "key-1", "hash-1"),
      store.reserve("scope", "key-1", "hash-1"),
    ]);
    expect([a, b].filter((result) => result.store)).toHaveLength(1);
    expect([a, b].filter((result) => result.pending)).toHaveLength(1);
    const owner = a.store ? a : b;
    await owner.store?.({ status: 200, body: { ok: true } });
    expect((await store.check("scope", "key-1", "hash-1")).record).toEqual({
      status: 200,
      body: { ok: true },
    });
  });

  it("no key leaves the request outside idempotency", async () => {
    const { client } = fakeRedis();
    const store = makeStore(client);
    expect(await store.check("scope", undefined, "hash-1")).toEqual({});
    expect(await store.reserve("scope", undefined, "hash-1")).toEqual({});
  });

  it("uses opaque collision-safe keys for delimiter-containing scopes", async () => {
    const { client, setCalls } = fakeRedis();
    const store = makeStore(client);
    await store.reserve("tenant:a", "b:key", "hash-1");
    await store.reserve("tenant", "a:b:key", "hash-2");
    expect(setCalls).toHaveLength(2);
    expect(setCalls[0]?.key).not.toBe(setCalls[1]?.key);
    expect(setCalls[0]?.key).not.toContain("tenant");
    expect(setCalls[0]?.key).not.toContain("b:key");
  });

  it("fails closed in production when durable Redis idempotency is unavailable", async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    const originalAcknowledgement = process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY;
    try {
      await expect(makeStore(null).check("scope", "key-1", "hash-1")).rejects.toThrow(
        "Durable Redis idempotency is required",
      );
      await expect(makeStore(null).reserve("scope", "key-1", "hash-1")).rejects.toThrow(
        "Durable Redis idempotency is required",
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
});

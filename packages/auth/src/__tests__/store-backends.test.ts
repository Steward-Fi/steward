import { describe, expect, it } from "bun:test";

import {
  buildBackend,
  MemoryBackend,
  NamespacedStoreBackend,
  RedisBackend,
  type RedisLike,
  type StoreBackend,
} from "../store-backends";

function redisLike(overrides: Partial<RedisLike> = {}): RedisLike {
  const store = new Map<string, string>();
  return {
    set: async (key, value) => {
      store.set(key, value);
      return "OK";
    },
    get: async (key) => store.get(key) ?? null,
    getdel: async (key) => {
      const value = store.get(key) ?? null;
      store.delete(key);
      return value;
    },
    del: async (...keys) => {
      let removed = 0;
      for (const key of keys) if (store.delete(key)) removed += 1;
      return removed;
    },
    eval: async (_script, keys, key, ...args) => {
      const [guardKey, expected, desired, _ttl, guardExpected] =
        keys === 2 ? args : [undefined, ...args];
      if (guardKey !== undefined && store.get(String(guardKey)) !== guardExpected) return 0;
      const current = store.get(String(key));
      if (current !== expected && current !== desired) return 0;
      store.set(String(key), String(desired));
      return 1;
    },
    ...overrides,
  };
}

describe("buildBackend Redis smoke test", () => {
  it("accepts a Redis client that supports GETDEL", async () => {
    const { source } = await buildBackend("challenge", redisLike(), false);
    expect(source).toBe("redis");
  });

  it("falls back when the Redis client lacks GETDEL (Redis < 6.2)", async () => {
    const client = redisLike({ getdel: undefined });
    const { source } = await buildBackend("challenge", client, false);
    expect(source).toBe("memory");
  });

  it("falls back when the Redis client throws", async () => {
    const client = redisLike({
      set: async () => {
        throw new Error("connection refused");
      },
    });
    const { source } = await buildBackend("challenge", client, false);
    expect(source).toBe("memory");
  });
});

describe("NamespacedStoreBackend", () => {
  it("applies staged transitions atomically and idempotently across reconstructed stores", async () => {
    const backend = new MemoryBackend();
    const first = new NamespacedStoreBackend(backend, "email");
    const second = new NamespacedStoreBackend(backend, "email");
    await first.set("challenge", "staged", 60_000);
    expect(await second.transition("challenge", "staged", "active", 60_000)).toBe(true);
    expect(await first.transition("challenge", "staged", "active", 60_000)).toBe(true);
    expect(await first.transition("challenge", "staged", "other", 60_000)).toBe(false);
    expect(await second.get("challenge")).toBe("active");
    backend.destroy();
  });

  it("uses an idempotent atomic Redis transition", async () => {
    const store = new RedisBackend(redisLike(), "test:");
    await store.set("challenge", "staged", 60_000);
    expect(await store.transition("challenge", "staged", "active", 60_000)).toBe(true);
    expect(await store.transition("challenge", "staged", "active", 60_000)).toBe(true);
    expect(await store.transition("challenge", "staged", "other", 60_000)).toBe(false);
  });

  it("binds transitions to an exact live guard in memory and Redis", async () => {
    for (const store of [new MemoryBackend(), new RedisBackend(redisLike(), "test:")]) {
      await store.set("challenge", "staged", 60_000);
      await store.set("target", "newest", 60_000);
      expect(
        await store.transition("challenge", "staged", "active", 60_000, {
          key: "target",
          expected: "superseded",
        }),
      ).toBe(false);
      expect(await store.get("challenge")).toBe("staged");
      expect(
        await store.transition("challenge", "staged", "active", 60_000, {
          key: "target",
          expected: "newest",
        }),
      ).toBe(true);
      expect(await store.get("challenge")).toBe("active");
      if (store instanceof MemoryBackend) store.destroy();
    }
  });

  it("shares values across reconstructed stores in the same namespace", async () => {
    const backend = new MemoryBackend();
    const first = new NamespacedStoreBackend(backend, "wallet-link");
    const reconstructed = new NamespacedStoreBackend(backend, "wallet-link");

    await first.set("challenge", "signed-value", 60_000);

    expect(await reconstructed.get("challenge")).toBe("signed-value");
    backend.destroy();
  });

  it("isolates identical keys even when namespace boundaries are ambiguous", async () => {
    const backend = new MemoryBackend();
    const first = new NamespacedStoreBackend(backend, "wallet");
    const second = new NamespacedStoreBackend(backend, "wallet:link");

    await first.set("link:challenge", "first", 60_000);
    await second.set("challenge", "second", 60_000);

    expect(await first.get("link:challenge")).toBe("first");
    expect(await second.get("challenge")).toBe("second");
    backend.destroy();
  });

  it("preserves atomic replay rejection across reconstructed stores", async () => {
    const backend = new MemoryBackend();
    const first = new NamespacedStoreBackend(backend, "oauth-link");
    const reconstructed = new NamespacedStoreBackend(backend, "oauth-link");
    await first.set("state", "proof", 60_000);

    const results = await Promise.all([first.consume("state"), reconstructed.consume("state")]);

    expect(results.filter((value) => value === "proof")).toHaveLength(1);
    expect(results.filter((value) => value === null)).toHaveLength(1);
    backend.destroy();
  });

  it("forwards the exact TTL and collision-safe key to the shared backend", async () => {
    const writes: Array<{ key: string; value: string; ttlMs: number }> = [];
    const backend: StoreBackend = {
      set: async (key, value, ttlMs) => {
        writes.push({ key, value, ttlMs });
      },
      setIfNotExists: async () => true,
      get: async () => null,
      consume: async () => null,
      transition: async () => false,
      delete: async () => undefined,
    };
    const store = new NamespacedStoreBackend(backend, "oauth-link");

    await store.set("state", "bound-proof", 123_456);

    expect(writes).toEqual([{ key: "10:oauth-link:state", value: "bound-proof", ttlMs: 123_456 }]);
  });

  it("propagates backend consume failures without replaying or falling back", async () => {
    let consumeCalls = 0;
    const backend: StoreBackend = {
      set: async () => undefined,
      setIfNotExists: async () => true,
      get: async () => null,
      consume: async () => {
        consumeCalls += 1;
        throw new Error("durable backend unavailable");
      },
      transition: async () => false,
      delete: async () => undefined,
    };
    const store = new NamespacedStoreBackend(backend, "wallet-link");

    await expect(store.consume("challenge")).rejects.toThrow("durable backend unavailable");
    expect(consumeCalls).toBe(1);
  });
});

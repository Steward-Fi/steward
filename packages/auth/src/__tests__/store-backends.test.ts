import { describe, expect, it } from "bun:test";

import { buildBackend, type RedisLike } from "../store-backends";

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

import { describe, expect, test } from "bun:test";
import type { Redis as UpstashRedis } from "@upstash/redis";
import { createUpstashIoredisAdapter, type IoredisLike } from "../upstash-adapter.js";

/**
 * Regression test for GitHub issue #100 — the Upstash ioredis adapter was
 * missing `getdel`, so RedisBackend.consume() (the atomic single-use primitive
 * for SIWE nonces, OAuth codes/state, MFA recovery/TOTP/SMS challenges, and
 * Telegram login) threw on the Cloudflare Workers driver (REDIS_DRIVER=upstash),
 * 500-ing every single-use-token auth flow.
 *
 * The fake below mimics real @upstash/redis semantics: get/getdel auto-
 * deserialize any value that looks like JSON (so a stored JSON object comes
 * back as an object, not a string). The adapter must normalize that back to a
 * string — consumeSiweNonce() stores JSON.stringify(record) and then
 * JSON.parse(raw)s the consumed value, so a deserialized object would break it.
 */

function makeFakeUpstash(): { client: UpstashRedis; store: Map<string, string> } {
  const store = new Map<string, string>();

  // Mirror Upstash's auto-deserialization: JSON-looking strings come back parsed.
  const deserialize = <T>(raw: string | undefined): T | null => {
    if (raw === undefined) return null;
    try {
      return JSON.parse(raw) as T;
    } catch {
      return raw as unknown as T;
    }
  };

  const client = {
    async set(key: string, value: string): Promise<string | null> {
      store.set(key, value);
      return "OK";
    },
    async get<T>(key: string): Promise<T | null> {
      return deserialize<T>(store.get(key));
    },
    async getdel<T>(key: string): Promise<T | null> {
      const raw = store.get(key);
      store.delete(key);
      return deserialize<T>(raw);
    },
    async del(...keys: string[]): Promise<number> {
      let removed = 0;
      for (const k of keys) {
        if (store.delete(k)) removed += 1;
      }
      return removed;
    },
  } as unknown as UpstashRedis;

  return { client, store };
}

/**
 * Faithful inline copy of packages/auth/src/store-backends.ts RedisBackend's
 * single-use contract. @stwd/auth is not a dependency of @stwd/redis, so we
 * reproduce the exact consume() behavior here to exercise it over the adapter
 * without a cross-package import. Keep this in sync with the real RedisBackend.
 */
interface RedisLikeForConsume {
  get(key: string): Promise<string | null>;
  getdel?(key: string): Promise<string | null>;
  del(...keys: string[]): Promise<number>;
}

async function consumeViaBackend(
  client: RedisLikeForConsume,
  prefix: string,
  key: string,
): Promise<string | null> {
  if (client.getdel) {
    return client.getdel(prefix + key);
  }
  throw new Error("Redis backend does not support atomic GETDEL token consumption");
}

describe("upstash adapter — getdel (issue #100)", () => {
  test("adapter exposes getdel as a function", () => {
    const { client } = makeFakeUpstash();
    const adapter: IoredisLike = createUpstashIoredisAdapter(client);
    expect(typeof adapter.getdel).toBe("function");
  });

  test("getdel returns the prior value once, then null (atomic single-use)", async () => {
    const { client } = makeFakeUpstash();
    const adapter = createUpstashIoredisAdapter(client);

    await adapter.set("k", "one-time-secret");

    expect(await adapter.getdel("k")).toBe("one-time-secret");
    // Second consume must miss — the value was atomically deleted.
    expect(await adapter.getdel("k")).toBeNull();
  });

  test("getdel returns null for a missing key", async () => {
    const { client } = makeFakeUpstash();
    const adapter = createUpstashIoredisAdapter(client);
    expect(await adapter.getdel("nope")).toBeNull();
  });

  test("getdel returns a JSON-object value as a string so callers can JSON.parse it", async () => {
    const { client } = makeFakeUpstash();
    const adapter = createUpstashIoredisAdapter(client);

    // This is exactly what setSiweNonce stores: JSON.stringify(record).
    const record = { allowedDomains: ["example.com"], originHost: "example.com" };
    await adapter.set("siwe:nonce", JSON.stringify(record));

    const raw = await adapter.getdel("siwe:nonce");
    expect(typeof raw).toBe("string");
    // consumeSiweNonce does JSON.parse(raw) — this must not throw.
    expect(JSON.parse(raw as string)).toEqual(record);
  });

  test("RedisBackend.consume() over the adapter returns the stored value (not throws)", async () => {
    const { client } = makeFakeUpstash();
    const adapter = createUpstashIoredisAdapter(client);
    const prefix = "auth:siwe-nonce:";

    const record = { allowedDomains: ["example.com"] };
    await adapter.set(prefix + "nonce-123", JSON.stringify(record));

    const consumed = await consumeViaBackend(adapter, prefix, "nonce-123");
    expect(consumed).not.toBeNull();
    expect(JSON.parse(consumed as string)).toEqual(record);

    // Single-use: a second consume returns null.
    expect(await consumeViaBackend(adapter, prefix, "nonce-123")).toBeNull();
  });

  test("a backend without getdel still throws the documented error (contract stays explicit)", async () => {
    const clientWithoutGetdel: RedisLikeForConsume = {
      async get() {
        return null;
      },
      async del() {
        return 0;
      },
      // getdel intentionally absent
    };

    await expect(consumeViaBackend(clientWithoutGetdel, "auth:", "k")).rejects.toThrow(
      "Redis backend does not support atomic GETDEL token consumption",
    );
  });
});

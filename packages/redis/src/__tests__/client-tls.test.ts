/**
 * SEC-032 regression tests. Redis carries spend-limit state, rate-limit state,
 * policy cache, and auth KV (SIWE nonces); in production the client must
 * refuse cleartext redis:// transport unless the operator explicitly opts out,
 * matching the assertDatabaseUrlTls() posture in @stwd/db.
 */

import { afterEach, describe, expect, test } from "bun:test";
import {
  assertRedisUrlTls,
  assertUpstashRestUrlTls,
  getRedis,
  setRedisClientResolverForRuntime,
} from "../client";

const originalNodeEnv = process.env.NODE_ENV;
const originalOverride = process.env.STEWARD_ALLOW_INSECURE_REDIS;

afterEach(() => {
  setRedisClientResolverForRuntime(null);
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  if (originalOverride === undefined) delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
  else process.env.STEWARD_ALLOW_INSECURE_REDIS = originalOverride;
});

describe("runtime-bound Redis authority", () => {
  test("returns only the client selected by the current runtime resolver", () => {
    const scoped = { ping: async () => "PONG" } as unknown as ReturnType<typeof getRedis>;
    setRedisClientResolverForRuntime(() => scoped);
    expect(getRedis()).toBe(scoped);
  });

  test("fails closed instead of falling back to a process singleton", () => {
    setRedisClientResolverForRuntime(() => null);
    expect(() => getRedis()).toThrow("Request-bound Redis client is unavailable");
  });
});

describe("redis transport security (SEC-032)", () => {
  test("rejects cleartext redis:// to a remote host in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("redis://redis.example.internal:6379")).toThrow("rediss://");
    expect(() => assertRedisUrlTls("redis://:secret@10.0.0.5:6379/0")).toThrow("rediss://");
  });

  test("accepts rediss:// in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("rediss://:secret@redis.example.internal:6380")).not.toThrow();
  });

  test("exempts localhost cleartext even in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("redis://localhost:6379")).not.toThrow();
    expect(() => assertRedisUrlTls("redis://127.0.0.1:6379")).not.toThrow();
    expect(() => assertRedisUrlTls("redis://[::1]:6379")).not.toThrow();
  });

  test("honors the explicit insecure override with a warning", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_INSECURE_REDIS = "true";
    expect(() => assertRedisUrlTls("redis://redis.example.internal:6379")).not.toThrow();
  });

  test("fails closed when a production URL cannot be parsed", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("not a url")).toThrow("valid URL");
  });

  test("rejects non-redis schemes", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("http://redis.example.internal:6379")).toThrow("scheme");
  });

  test("does not restrict non-production environments", () => {
    process.env.NODE_ENV = "development";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertRedisUrlTls("redis://redis.example.internal:6379")).not.toThrow();
  });
});

describe("upstash REST transport security (SEC-032)", () => {
  test("rejects cleartext http:// to a remote host in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("http://us1-example.upstash.io")).toThrow("https://");
  });

  test("accepts https:// in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("https://us1-example.upstash.io")).not.toThrow();
  });

  test("exempts loopback http:// even in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("http://localhost:8079")).not.toThrow();
    expect(() => assertUpstashRestUrlTls("http://127.0.0.1:8079")).not.toThrow();
    expect(() => assertUpstashRestUrlTls("http://[::1]:8079")).not.toThrow();
  });

  test("honors the explicit insecure override with a warning", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_INSECURE_REDIS = "true";
    expect(() => assertUpstashRestUrlTls("http://us1-example.upstash.io")).not.toThrow();
  });

  test("fails closed when a production URL cannot be parsed", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("not a url")).toThrow("valid URL");
  });

  test("invalid URLs remain invalid even with the insecure override", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_INSECURE_REDIS = "true";
    expect(() => assertUpstashRestUrlTls("not a url")).toThrow("valid URL");
  });

  test("rejects non-HTTP schemes even with the insecure override", () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("redis://us1-example.upstash.io")).toThrow("scheme");
    process.env.STEWARD_ALLOW_INSECURE_REDIS = "true";
    expect(() => assertUpstashRestUrlTls("ftp://us1-example.upstash.io")).toThrow("scheme");
  });

  test("does not restrict non-production environments", () => {
    process.env.NODE_ENV = "development";
    delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
    expect(() => assertUpstashRestUrlTls("http://us1-example.upstash.io")).not.toThrow();
    expect(() => assertUpstashRestUrlTls("ftp://us1-example.upstash.io")).toThrow("scheme");
  });

  test("uses the caller-provided environment instead of ambient process state", () => {
    process.env.NODE_ENV = "development";
    expect(() =>
      assertUpstashRestUrlTls("http://us1-example.upstash.io", { NODE_ENV: "production" }),
    ).toThrow("https://");
    expect(() =>
      assertRedisUrlTls("redis://redis.example.internal:6379", { NODE_ENV: "production" }),
    ).toThrow("rediss://");
  });
});

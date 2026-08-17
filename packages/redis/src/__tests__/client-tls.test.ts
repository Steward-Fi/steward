/**
 * SEC-032 regression tests. Redis carries spend-limit state, rate-limit state,
 * policy cache, and auth KV (SIWE nonces); in production the client must
 * refuse cleartext redis:// transport unless the operator explicitly opts out,
 * matching the assertDatabaseUrlTls() posture in @stwd/db.
 */

import { afterEach, describe, expect, test } from "bun:test";
import { assertRedisUrlTls } from "../client";

const originalNodeEnv = process.env.NODE_ENV;
const originalOverride = process.env.STEWARD_ALLOW_INSECURE_REDIS;

afterEach(() => {
  if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = originalNodeEnv;
  if (originalOverride === undefined) delete process.env.STEWARD_ALLOW_INSECURE_REDIS;
  else process.env.STEWARD_ALLOW_INSECURE_REDIS = originalOverride;
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

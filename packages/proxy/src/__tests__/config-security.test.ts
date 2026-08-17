import { afterEach, describe, expect, test } from "bun:test";

import { configuredProxyCorsOrigins, isProxyDevMode, positiveIntegerEnv } from "../config";

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  process.env = { ...ORIGINAL_ENV };
});

describe("security configuration", () => {
  test("production cannot enable the permissive proxy development mode", () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_PROXY_DEV_MODE = "true";
    expect(isProxyDevMode()).toBe(false);

    process.env.NODE_ENV = "development";
    expect(isProxyDevMode()).toBe(true);
  });

  test("CORS is disabled by default and accepts canonical HTTP(S) origins", () => {
    delete process.env.STEWARD_PROXY_CORS_ORIGINS;
    expect(configuredProxyCorsOrigins()).toEqual([]);

    process.env.STEWARD_PROXY_CORS_ORIGINS = "https://dashboard.example.com,http://localhost:3000";
    expect(configuredProxyCorsOrigins()).toEqual([
      "https://dashboard.example.com",
      "http://localhost:3000",
    ]);
  });

  test("rejects wildcard and non-origin CORS values", () => {
    for (const value of [
      "*",
      "https://dashboard.example.com/path",
      "https://user@example.com",
      "https://dashboard.example.com?mode=dev",
      "javascript:alert(1)",
    ]) {
      process.env.STEWARD_PROXY_CORS_ORIGINS = value;
      expect(() => configuredProxyCorsOrigins()).toThrow("STEWARD_PROXY_CORS_ORIGINS");
    }
  });

  test("positive integer configuration rejects fractions, infinity, and overflow", () => {
    for (const value of ["1.5", "Infinity", "65536"]) {
      process.env.TEST_POSITIVE_INTEGER = value;
      expect(() => positiveIntegerEnv("TEST_POSITIVE_INTEGER", 1, 65535)).toThrow(
        "TEST_POSITIVE_INTEGER",
      );
    }
  });
});

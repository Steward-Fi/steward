import { afterEach, describe, expect, it } from "bun:test";
import { closeDb } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL,
  REDIS_URL: process.env.REDIS_URL,
  REDIS_DRIVER: process.env.REDIS_DRIVER,
  STEWARD_PGLITE_MEMORY: process.env.STEWARD_PGLITE_MEMORY,
  STEWARD_MASTER_PASSWORD: process.env.STEWARD_MASTER_PASSWORD,
  STEWARD_KDF_SALT: process.env.STEWARD_KDF_SALT,
};

function restoreEnv(key: keyof typeof ORIGINAL_ENV) {
  const value = ORIGINAL_ENV[key];
  if (value === undefined) delete process.env[key];
  else process.env[key] = value;
}

describe("auth rate-limit headers", () => {
  afterEach(async () => {
    await closeDb();
    restoreEnv("NODE_ENV");
    restoreEnv("STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL");
    restoreEnv("REDIS_URL");
    restoreEnv("REDIS_DRIVER");
    restoreEnv("STEWARD_PGLITE_MEMORY");
    restoreEnv("STEWARD_MASTER_PASSWORD");
    restoreEnv("STEWARD_KDF_SALT");
  });

  it("emits standard and legacy headers on auth-specific 429 responses", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    delete process.env.REDIS_URL;
    delete process.env.REDIS_DRIVER;
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "auth-rate-limit-master";
    process.env.STEWARD_KDF_SALT =
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    const { app } = await import("../app");

    const response = await app.request("/auth/nonce");

    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBe("60");
    expect(response.headers.get("ratelimit-limit")).toBe("30");
    expect(response.headers.get("ratelimit-remaining")).toBe("0");
    expect(response.headers.get("ratelimit-reset")).toBe("60");
    expect(response.headers.get("ratelimit-policy")).toBe("30;w=60");
    expect(response.headers.get("x-ratelimit-limit")).toBe("30");
    expect(response.headers.get("x-ratelimit-remaining")).toBe("0");
    expect(response.headers.get("x-ratelimit-reset")).toBe("60");

    const body = (await response.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Too many nonce requests");
  });
});

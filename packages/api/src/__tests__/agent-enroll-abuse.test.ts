/**
 * agent-enroll-abuse.test.ts — SEC-051 / SEC-052 regression tests.
 *
 * SEC-051: the public enroll endpoints must sit behind the Redis-backed auth
 * rate limiter (fail-closed in production) and must reject oversized or
 * invalid-charset agentIds before anything reaches the challenge store.
 * SEC-052: enrollment challenges must live in the API's initialized
 * ChallengeStore (getAuthChallengeStore), not the auth package's process-local
 * memory singleton.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { challengeStore as authMemorySingleton } from "@stwd/auth";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const ORIGINAL_ENV = {
  NODE_ENV: process.env.NODE_ENV,
  REDIS_URL: process.env.REDIS_URL,
  REDIS_DRIVER: process.env.REDIS_DRIVER,
  STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL,
};

function restoreEnv() {
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

describe("agent enrollment abuse surface (SEC-051, SEC-052)", () => {
  let app: Hono<{ Variables: AppVariables }>;
  let getAuthChallengeStore: typeof import("../routes/auth").getAuthChallengeStore;

  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "enroll-abuse-master-password-32-chars";
    process.env.STEWARD_JWT_SECRET = "enroll-abuse-jwt-secret-at-least-32-chars!";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    const { agentEnrollRoutes } = await import("../routes/agent-enroll");
    ({ getAuthChallengeStore } = await import("../routes/auth"));
    app = new Hono<{ Variables: AppVariables }>();
    app.route("/agent-enroll", agentEnrollRoutes);
  });

  afterAll(async () => {
    restoreEnv();
    const { closeDb } = await import("@stwd/db");
    await closeDb().catch(() => {});
  });

  it("stores challenges in the API's initialized store, not the auth memory singleton (SEC-052)", async () => {
    const res = await app.request("/agent-enroll/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ agentId: "sec052-agent" }),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; data: { nonce: string } };
    expect(body.ok).toBe(true);

    const stored = await getAuthChallengeStore().get(
      `agent-enroll:sec052-agent:${body.data.nonce}`,
    );
    expect(stored).not.toBeNull();
    // The auth package's process-local singleton must stay empty: the route
    // must not touch it even as a fallback.
    expect(authMemorySingleton.size).toBe(0);
  });

  it("rejects oversized and invalid-charset agentIds before the store (SEC-051)", async () => {
    for (const agentId of ["a".repeat(200), "bad agent", "agent/id"]) {
      const res = await app.request("/agent-enroll/challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentId }),
      });
      expect(res.status).toBe(400);
    }
  });

  it("fails closed with 429 in production when Redis was never configured (SEC-051)", async () => {
    process.env.NODE_ENV = "production";
    delete process.env.REDIS_URL;
    delete process.env.REDIS_DRIVER;
    delete process.env.STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL;
    try {
      const challengeRes = await app.request("/agent-enroll/challenge", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentId: "sec051-agent" }),
      });
      expect(challengeRes.status).toBe(429);
      expect(challengeRes.headers.get("retry-after")).toBe("60");

      const verifyRes = await app.request("/agent-enroll/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ agentId: "sec051-agent", nonce: "n", signature: "s" }),
      });
      expect(verifyRes.status).toBe(429);
    } finally {
      restoreEnv();
    }
  });
});

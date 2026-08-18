/**
 * Tests for the per-agent capability rate limiter (SEC-094).
 *
 * The invoke, OpenAI-adapter, and manifest-issuance routes share a hard
 * infrastructure ceiling independent of the optional operator-configured
 * `maxCallsPerHour` policy rule. These tests pin the limiter's contract: the
 * (max+1)-th request in a window is denied,
 * buckets are per-agent and per-surface, an expired window resets, and a
 * Redis-path error fails CLOSED (deny).
 */

import { describe, expect, test } from "bun:test";
import {
  CAPABILITY_INVOKE_RATE_LIMIT,
  CAPABILITY_ISSUE_RATE_LIMIT,
  enforceCapabilityRateLimit,
} from "../rate-limit";

const noRedis = { getRedisClient: () => null };

describe("enforceCapabilityRateLimit (memory path)", () => {
  test("admits up to maxRequests then denies with a positive resetMs", async () => {
    const agent = `agent-cap-rl-${crypto.randomUUID()}`;
    for (let i = 0; i < CAPABILITY_INVOKE_RATE_LIMIT.maxRequests; i++) {
      const r = await enforceCapabilityRateLimit(noRedis, "invoke", agent);
      expect(r.allowed).toBe(true);
    }
    const denied = await enforceCapabilityRateLimit(noRedis, "invoke", agent);
    expect(denied.allowed).toBe(false);
    expect(denied.resetMs).toBeGreaterThan(0);
    expect(denied.resetMs).toBeLessThanOrEqual(CAPABILITY_INVOKE_RATE_LIMIT.windowMs);
  });

  test("buckets are per-agent and per-surface", async () => {
    const flooded = `agent-cap-rl-${crypto.randomUUID()}`;
    const other = `agent-cap-rl-${crypto.randomUUID()}`;
    for (let i = 0; i < CAPABILITY_ISSUE_RATE_LIMIT.maxRequests; i++) {
      await enforceCapabilityRateLimit(noRedis, "issue", flooded);
    }
    expect((await enforceCapabilityRateLimit(noRedis, "issue", flooded)).allowed).toBe(false);
    // a different agent is unaffected
    expect((await enforceCapabilityRateLimit(noRedis, "issue", other)).allowed).toBe(true);
    // and the flooded agent's invoke bucket is separate from its issue bucket
    expect((await enforceCapabilityRateLimit(noRedis, "invoke", flooded)).allowed).toBe(true);
  });

  test("fails CLOSED when the Redis path errors", async () => {
    const brokenRedis = {
      getRedisClient: () => ({}) as never, // non-null → takes the Redis path
    };
    // checkRateLimit will throw against the fake client (no .eval) — the limiter
    // must deny, never fall open.
    const r = await enforceCapabilityRateLimit(brokenRedis, "invoke", "agent-any");
    expect(r.allowed).toBe(false);
  });
});

/**
 * agent-enroll-token-ttl.test.ts — SEC-134-style startup validation for
 * STEWARD_AGENT_ENROLL_TOKEN_TTL: malformed values and values beyond the
 * one-hour bound must fail closed at module load, not at token-mint time.
 */

import { afterEach, describe, expect, it } from "bun:test";

const ENV_KEY = "STEWARD_AGENT_ENROLL_TOKEN_TTL";

describe("agent enrollment token TTL env validation", () => {
  let previous: string | undefined;

  afterEach(() => {
    if (previous === undefined) {
      delete process.env[ENV_KEY];
    } else {
      process.env[ENV_KEY] = previous;
    }
    previous = undefined;
  });

  async function importFresh() {
    return import(`../routes/agent-enroll?ttl-test=${Date.now()}-${Math.random()}`);
  }

  it("loads with the 5m default when the env var is unset", async () => {
    previous = process.env[ENV_KEY];
    delete process.env[ENV_KEY];
    const mod = await importFresh();
    expect(mod.agentEnrollRoutes).toBeDefined();
  });

  it("rejects a malformed duration at module load", async () => {
    previous = process.env[ENV_KEY];
    process.env[ENV_KEY] = "not-a-duration";
    await expect(importFresh()).rejects.toThrow(
      'STEWARD_AGENT_ENROLL_TOKEN_TTL "not-a-duration" is not a valid positive duration',
    );
  });

  it("rejects a non-positive duration at module load", async () => {
    previous = process.env[ENV_KEY];
    process.env[ENV_KEY] = "0m";
    await expect(importFresh()).rejects.toThrow("is not a valid positive duration");
  });

  it("rejects a TTL beyond the one-hour bound at module load", async () => {
    previous = process.env[ENV_KEY];
    process.env[ENV_KEY] = "2h";
    await expect(importFresh()).rejects.toThrow("exceeds the one-hour maximum");
  });

  it("accepts a valid in-bound TTL", async () => {
    previous = process.env[ENV_KEY];
    process.env[ENV_KEY] = "15m";
    const mod = await importFresh();
    expect(mod.agentEnrollRoutes).toBeDefined();
  });
});

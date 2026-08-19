/**
 * worker-boot-validation.test.ts — SEC-134 startup validation must also run on
 * the Cloudflare Workers boot path (worker.ts), not only the Bun entry. A
 * Workers deploy with a weak/missing JWT secret or a malformed
 * AGENT_TOKEN_EXPIRY must fail closed at cold start.
 */

import { afterEach, describe, expect, it } from "bun:test";
import { signAgentToken } from "@stwd/auth/jwt";
import { decodeJwt, jwtVerify } from "jose";
import worker, { hydrateProcessEnv } from "../worker";

/**
 * Keys this file mutates: bindings hydrateProcessEnv copies onto the global
 * process.env, plus ambient suite values (see test-preload.ts) that some cases
 * must clear to simulate a misconfigured deployment. All restored after each
 * test.
 */
const MANAGED_KEYS = [
  "STEWARD_RUNTIME",
  "NODE_ENV",
  "STEWARD_JWT_SECRET",
  "STEWARD_SESSION_SECRET",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_DB_MODE",
  "STEWARD_PGLITE_MEMORY",
  "AGENT_TOKEN_EXPIRY",
] as const;

describe("workers boot JWT env validation (SEC-134)", () => {
  const saved = new Map<string, string | undefined>();

  afterEach(() => {
    for (const key of MANAGED_KEYS) {
      const prior = saved.get(key);
      if (prior === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = prior;
      }
    }
    saved.clear();
  });

  function snapshotEnv(): void {
    for (const key of MANAGED_KEYS) saved.set(key, process.env[key]);
  }

  it("rejects a short JWT secret at cold start in production", async () => {
    snapshotEnv();
    await expect(
      worker.fetch(
        new Request("https://workers.test/"),
        { NODE_ENV: "production", STEWARD_JWT_SECRET: "short", DATABASE_DRIVER: "bogus" },
        {},
      ),
    ).rejects.toThrow("at least 32 characters in production");
  });

  it("rejects a missing JWT secret at cold start in production", async () => {
    snapshotEnv();
    // The suite preload supplies ambient test secrets and embedded-mode
    // markers; a "missing secret" deployment must clear them all, or
    // getJwtSecret would legitimately fall back to them.
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_SESSION_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    await expect(
      worker.fetch(
        new Request("https://workers.test/"),
        { NODE_ENV: "production", DATABASE_DRIVER: "bogus" },
        {},
      ),
    ).rejects.toThrow("STEWARD_JWT_SECRET is required in production");
  });

  it("rejects a malformed AGENT_TOKEN_EXPIRY at cold start", async () => {
    snapshotEnv();
    await expect(
      worker.fetch(
        new Request("https://workers.test/"),
        {
          STEWARD_JWT_SECRET: "workers-boot-test-secret-32-chars-long!!",
          AGENT_TOKEN_EXPIRY: "not-a-duration",
          DATABASE_DRIVER: "bogus",
        },
        {},
      ),
    ).rejects.toThrow('AGENT_TOKEN_EXPIRY "not-a-duration" is not a valid positive duration');
  });

  it("validates concurrent request bindings before either database selection", async () => {
    snapshotEnv();
    const shortSecret = worker.fetch(
      new Request("https://workers.test/short-secret"),
      { NODE_ENV: "production", STEWARD_JWT_SECRET: "short", DATABASE_DRIVER: "bogus" },
      {},
    );
    const malformedExpiry = worker.fetch(
      new Request("https://workers.test/malformed-expiry"),
      {
        STEWARD_JWT_SECRET: "workers-boot-test-secret-32-chars-long!!",
        AGENT_TOKEN_EXPIRY: "not-a-duration",
        DATABASE_DRIVER: "bogus",
      },
      {},
    );

    await expect(shortSecret).rejects.toThrow("at least 32 characters in production");
    await expect(malformedExpiry).rejects.toThrow(
      'AGENT_TOKEN_EXPIRY "not-a-duration" is not a valid positive duration',
    );
  });

  it("uses the current Worker expiry binding when minting after module initialization", async () => {
    snapshotEnv();
    const firstSecret = "workers-first-rotated-secret-at-least-32-chars";
    const rotatedSecret = "workers-second-rotated-secret-at-least-32-chars";
    hydrateProcessEnv({
      STEWARD_JWT_SECRET: firstSecret,
      AGENT_TOKEN_EXPIRY: "1h",
      DATABASE_URL: "unused",
    });
    const firstToken = await signAgentToken({ agentId: "worker-agent", tenantId: "worker-tenant" });
    const first = decodeJwt(firstToken);
    hydrateProcessEnv({
      STEWARD_JWT_SECRET: rotatedSecret,
      AGENT_TOKEN_EXPIRY: "5m",
      DATABASE_URL: "unused",
    });
    const rotatedToken = await signAgentToken({
      agentId: "worker-agent",
      tenantId: "worker-tenant",
    });
    const rotated = decodeJwt(rotatedToken);

    expect((first.exp ?? 0) - (first.iat ?? 0)).toBe(3600);
    expect((rotated.exp ?? 0) - (rotated.iat ?? 0)).toBe(300);
    await expect(
      jwtVerify(firstToken, new TextEncoder().encode(firstSecret)),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(rotatedToken, new TextEncoder().encode(rotatedSecret)),
    ).resolves.toBeDefined();
    await expect(jwtVerify(rotatedToken, new TextEncoder().encode(firstSecret))).rejects.toThrow();
  });

  it("validates scheduled security bindings before opening any database handle", async () => {
    snapshotEnv();
    let waitUntilCalls = 0;
    await expect(
      worker.scheduled(
        {},
        {
          NODE_ENV: "production",
          STEWARD_JWT_SECRET: "short",
          DATABASE_DRIVER: "bogus",
          DATABASE_URL: "postgresql://credential-canary@worker.invalid/steward",
        },
        {
          waitUntil() {
            waitUntilCalls += 1;
          },
        },
      ),
    ).rejects.toThrow("at least 32 characters in production");
    expect(waitUntilCalls).toBe(0);
  });
});

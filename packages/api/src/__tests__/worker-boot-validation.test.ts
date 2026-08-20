/**
 * worker-boot-validation.test.ts — SEC-134 startup validation must also run on
 * the Cloudflare Workers boot path (worker.ts), not only the Bun entry. A
 * Workers deploy with a weak/missing JWT secret or a malformed
 * AGENT_TOKEN_EXPIRY must fail closed at cold start.
 */

import { afterEach, describe, expect, it } from "bun:test";
import { signAgentToken, signIdentityJwtPayload } from "@stwd/auth/jwt";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { decodeJwt, decodeProtectedHeader, exportPKCS8, generateKeyPair, jwtVerify } from "jose";
import worker, { hydrateProcessEnv, withWorkerJwtAuthority } from "../worker";

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
  "STEWARD_OIDC_JWKS_MAX_AGE_MS",
  "STEWARD_IDENTITY_JWT_ALG",
  "STEWARD_IDENTITY_JWT_PRIVATE_KEY",
  "STEWARD_IDENTITY_JWT_KID",
  "STEWARD_IDENTITY_JWT_ISSUER",
  "STEWARD_IDENTITY_JWT_AUDIENCE",
  "APP_URL",
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

  it("rejects missing and short canonical deployment JWT roots before database selection", async () => {
    snapshotEnv();
    delete process.env.STEWARD_JWT_SECRET;
    delete process.env.STEWARD_SESSION_SECRET;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_DB_MODE;
    delete process.env.STEWARD_PGLITE_MEMORY;
    const canonicalBindings = {
      NODE_ENV: "production",
      SKIP_MIGRATIONS: "1",
      DATABASE_DRIVER: "canonical-database-must-not-be-selected",
      REDIS_DRIVER: "upstash",
    };
    const missing = expect(
      worker.fetch(
        new Request("https://workers.test/canonical-missing-jwt"),
        canonicalBindings,
        {},
      ),
    ).rejects.toThrow("STEWARD_JWT_SECRET is required in production");
    const short = expect(
      worker.fetch(
        new Request("https://workers.test/canonical-short-jwt"),
        { ...canonicalBindings, STEWARD_JWT_SECRET: "short" },
        {},
      ),
    ).rejects.toThrow("at least 32 characters in production");

    await Promise.all([missing, short]);
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
    const shortSecret = expect(
      worker.fetch(
        new Request("https://workers.test/short-secret"),
        { NODE_ENV: "production", STEWARD_JWT_SECRET: "short", DATABASE_DRIVER: "bogus" },
        {},
      ),
    ).rejects.toThrow("at least 32 characters in production");
    const malformedExpiry = expect(
      worker.fetch(
        new Request("https://workers.test/malformed-expiry"),
        {
          STEWARD_JWT_SECRET: "workers-boot-test-secret-32-chars-long!!",
          AGENT_TOKEN_EXPIRY: "not-a-duration",
          DATABASE_DRIVER: "bogus",
        },
        {},
      ),
    ).rejects.toThrow('AGENT_TOKEN_EXPIRY "not-a-duration" is not a valid positive duration');

    await Promise.all([shortSecret, malformedExpiry]);
  });

  it("keeps nested Worker request snapshots isolated from missing global values", async () => {
    snapshotEnv();
    process.env.STEWARD_OIDC_JWKS_MAX_AGE_MS = "global-poison";
    const secret = "workers-runtime-snapshot-secret-at-least-32-chars";
    let nestedRejection: Promise<void> | undefined;
    const nestedContext = Object.defineProperty({}, "waitUntil", {
      get() {
        throw new Error(
          `nested snapshot: ${String(runtimeEnvironmentValue("STEWARD_OIDC_JWKS_MAX_AGE_MS"))}`,
        );
      },
    });
    const firstContext = Object.defineProperty({}, "waitUntil", {
      get() {
        const nestedRequest = worker.fetch(
          new Request("https://workers.test/runtime-snapshot-missing"),
          { STEWARD_JWT_SECRET: secret, DATABASE_DRIVER: "bogus" },
          nestedContext,
        );
        nestedRejection = nestedRequest.then(
          () => {
            throw new Error("nested Worker request unexpectedly succeeded");
          },
          (error) => {
            expect(String(error)).toContain("nested snapshot: undefined");
          },
        );
        throw new Error(
          `first snapshot: ${String(runtimeEnvironmentValue("STEWARD_OIDC_JWKS_MAX_AGE_MS"))}`,
        );
      },
    });

    const firstRejection = expect(
      worker.fetch(
        new Request("https://workers.test/runtime-snapshot-first"),
        {
          STEWARD_JWT_SECRET: secret,
          STEWARD_OIDC_JWKS_MAX_AGE_MS: "60000",
          DATABASE_DRIVER: "bogus",
        },
        firstContext,
      ),
    ).rejects.toThrow("first snapshot: 60000");
    await firstRejection;
    if (!nestedRejection) throw new Error("nested Worker request did not run");
    await nestedRejection;
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

  it("isolates JWT secret and default TTL across overlapping Worker invocations", async () => {
    snapshotEnv();
    const firstEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "workers-overlap-first-secret-at-least-32-chars",
      AGENT_TOKEN_EXPIRY: "1h",
      DATABASE_URL: "unused-first",
    };
    const secondEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "workers-overlap-second-secret-at-least-32-chars",
      AGENT_TOKEN_EXPIRY: "5m",
      DATABASE_URL: "unused-second",
    };
    let markFirstReady!: () => void;
    let releaseFirst!: () => void;
    const firstReady = new Promise<void>((resolve) => {
      markFirstReady = resolve;
    });
    const firstBarrier = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const firstMint = withWorkerJwtAuthority(firstEnv, async () => {
      hydrateProcessEnv(firstEnv);
      markFirstReady();
      await firstBarrier;
      return signAgentToken({ agentId: "worker-first", tenantId: "worker-tenant" });
    });
    await firstReady;

    let secondToken: string;
    try {
      secondToken = await withWorkerJwtAuthority(secondEnv, async () => {
        // This is the hostile interleaving: overwrite the isolate-wide mirror
        // while the first invocation is suspended before it mints.
        hydrateProcessEnv(secondEnv);
        return signAgentToken({ agentId: "worker-second", tenantId: "worker-tenant" });
      });
    } finally {
      releaseFirst();
    }
    const firstToken = await firstMint;
    const first = decodeJwt(firstToken);
    const second = decodeJwt(secondToken);

    expect((first.exp ?? 0) - (first.iat ?? 0)).toBe(3600);
    expect((second.exp ?? 0) - (second.iat ?? 0)).toBe(300);
    await expect(
      jwtVerify(firstToken, new TextEncoder().encode(firstEnv.STEWARD_JWT_SECRET)),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(secondToken, new TextEncoder().encode(secondEnv.STEWARD_JWT_SECRET)),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(firstToken, new TextEncoder().encode(secondEnv.STEWARD_JWT_SECRET)),
    ).rejects.toThrow();
    await expect(
      jwtVerify(secondToken, new TextEncoder().encode(firstEnv.STEWARD_JWT_SECRET)),
    ).rejects.toThrow();
  });

  it("isolates asymmetric identity signing authority across overlapping Worker invocations", async () => {
    snapshotEnv();
    const firstKeys = await generateKeyPair("RS256", { extractable: true });
    const secondKeys = await generateKeyPair("RS256", { extractable: true });
    const firstEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "workers-identity-first-hmac-secret-at-least-32-chars",
      STEWARD_IDENTITY_JWT_ALG: "RS256",
      STEWARD_IDENTITY_JWT_PRIVATE_KEY: await exportPKCS8(firstKeys.privateKey),
      STEWARD_IDENTITY_JWT_KID: "worker-identity-first",
      STEWARD_IDENTITY_JWT_ISSUER: "https://first.identity.test",
      STEWARD_IDENTITY_JWT_AUDIENCE: "first-audience",
      DATABASE_URL: "unused-first",
    };
    const secondEnv = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "workers-identity-second-hmac-secret-at-least-32-chars",
      STEWARD_IDENTITY_JWT_ALG: "RS256",
      STEWARD_IDENTITY_JWT_PRIVATE_KEY: await exportPKCS8(secondKeys.privateKey),
      STEWARD_IDENTITY_JWT_KID: "worker-identity-second",
      STEWARD_IDENTITY_JWT_ISSUER: "https://second.identity.test",
      STEWARD_IDENTITY_JWT_AUDIENCE: "second-audience",
      DATABASE_URL: "unused-second",
    };
    let markFirstReady!: () => void;
    let releaseFirst!: () => void;
    const firstReady = new Promise<void>((resolve) => {
      markFirstReady = resolve;
    });
    const firstBarrier = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });

    const firstMint = withWorkerJwtAuthority(firstEnv, async () => {
      hydrateProcessEnv(firstEnv);
      markFirstReady();
      await firstBarrier;
      return signIdentityJwtPayload({ sub: "worker-first" });
    });
    await firstReady;

    let secondToken: string;
    try {
      secondToken = await withWorkerJwtAuthority(secondEnv, async () => {
        hydrateProcessEnv(secondEnv);
        return signIdentityJwtPayload({ sub: "worker-second" });
      });
    } finally {
      releaseFirst();
    }
    const firstToken = await firstMint;

    expect(decodeProtectedHeader(firstToken)).toMatchObject({
      alg: "RS256",
      kid: firstEnv.STEWARD_IDENTITY_JWT_KID,
    });
    expect(decodeProtectedHeader(secondToken)).toMatchObject({
      alg: "RS256",
      kid: secondEnv.STEWARD_IDENTITY_JWT_KID,
    });
    await expect(
      jwtVerify(firstToken, firstKeys.publicKey, {
        issuer: firstEnv.STEWARD_IDENTITY_JWT_ISSUER,
        audience: firstEnv.STEWARD_IDENTITY_JWT_AUDIENCE,
      }),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(secondToken, secondKeys.publicKey, {
        issuer: secondEnv.STEWARD_IDENTITY_JWT_ISSUER,
        audience: secondEnv.STEWARD_IDENTITY_JWT_AUDIENCE,
      }),
    ).resolves.toBeDefined();
    await expect(jwtVerify(firstToken, secondKeys.publicKey)).rejects.toThrow();
    await expect(jwtVerify(secondToken, firstKeys.publicKey)).rejects.toThrow();
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

/**
 * worker-boot-validation.test.ts — SEC-134 startup validation must also run on
 * the Cloudflare Workers boot path (worker.ts), not only the Bun entry. A
 * Workers deploy with a weak/missing JWT secret or a malformed
 * AGENT_TOKEN_EXPIRY must fail closed at cold start.
 */

import { afterEach, describe, expect, it } from "bun:test";
import { signAgentToken } from "@stwd/auth/jwt";
import { runtimeEnvironmentFlag, withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { decodeJwt, jwtVerify } from "jose";
import { configuredDefaultTenantId } from "../routes/auth";
import { buildTenantSecurityChecklist } from "../routes/tenant-config";
import { getRateLimitMaxRequests, getRateLimitWindowMs } from "../services/context";
import { resolveRequestSecurityPosture } from "../services/request-security-config";
import { validateWebhookUrl } from "../services/webhook-url";
import worker from "../worker";

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
  "STEWARD_ALLOW_INSECURE_WEBHOOK_URLS",
  "STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION",
  "STEWARD_DEFAULT_TENANT_ID",
  "STEWARD_RATE_LIMIT_WINDOW_MS",
  "STEWARD_RATE_LIMIT_MAX_REQUESTS",
  "STEWARD_REQUIRE_REQUEST_EXPIRY",
  "STEWARD_REQUIRE_AUTH_SIGNATURE",
  "STEWARD_REQUEST_SIGNING_SECRETS",
  "STEWARD_REQUEST_SIGNING_SECRET",
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

  it("rejects a production Worker without a machine request-signing root", async () => {
    snapshotEnv();
    delete process.env.STEWARD_REQUEST_SIGNING_SECRETS;
    delete process.env.STEWARD_REQUEST_SIGNING_SECRET;
    await expect(
      worker.fetch(
        new Request("https://workers.test/"),
        {
          NODE_ENV: "production",
          STEWARD_JWT_SECRET: "workers-boot-test-secret-32-chars-long!!",
          DATABASE_DRIVER: "bogus",
        },
        {},
      ),
    ).rejects.toThrow("STEWARD_REQUEST_SIGNING_SECRETS");
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

  it("uses the current Worker expiry binding when minting after module initialization", async () => {
    snapshotEnv();
    const firstSecret = "workers-first-rotated-secret-at-least-32-chars";
    const rotatedSecret = "workers-second-rotated-secret-at-least-32-chars";
    const firstToken = await withRuntimeEnvironment(
      {
        STEWARD_JWT_SECRET: firstSecret,
        AGENT_TOKEN_EXPIRY: "1h",
        DATABASE_URL: "unused",
      },
      () => signAgentToken({ agentId: "worker-agent", tenantId: "worker-tenant" }),
    );
    const first = decodeJwt(firstToken);
    const rotatedToken = await withRuntimeEnvironment(
      {
        STEWARD_JWT_SECRET: rotatedSecret,
        AGENT_TOKEN_EXPIRY: "5m",
        DATABASE_URL: "unused",
      },
      () => signAgentToken({ agentId: "worker-agent", tenantId: "worker-tenant" }),
    );
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

  it("keeps hostile concurrent post-await security bindings request-local", async () => {
    snapshotEnv();
    process.env.STEWARD_ALLOW_INSECURE_WEBHOOK_URLS = "true";
    process.env.STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION = "true";
    process.env.STEWARD_REQUIRE_REQUEST_EXPIRY = "true";
    process.env.STEWARD_REQUIRE_AUTH_SIGNATURE = "true";

    const firstSecret = "workers-concurrent-first-secret-at-least-32-chars";
    const secondSecret = "workers-concurrent-second-secret-at-least-32-chars";
    let markSecondReady!: () => void;
    let releaseSecond!: () => void;
    const secondReady = new Promise<void>((resolve) => {
      markSecondReady = resolve;
    });
    const secondCanRead = new Promise<void>((resolve) => {
      releaseSecond = resolve;
    });

    async function readRequestSettings() {
      const token = await signAgentToken({ agentId: "worker-agent", tenantId: "worker-tenant" });
      const checklist = buildTenantSecurityChecklist("worker-tenant", undefined, [], [], []);
      return {
        token,
        tenantId: configuredDefaultTenantId(),
        rateWindowMs: getRateLimitWindowMs(),
        rateMax: getRateLimitMaxRequests(),
        insecureWebhookError: validateWebhookUrl("http://public.example.test/hook"),
        walletSendEnabled: runtimeEnvironmentFlag("STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION"),
        posture: resolveRequestSecurityPosture(),
        checklist: Object.fromEntries(
          checklist.items
            .filter((item) => ["request-expiry", "authorization-signatures"].includes(item.id))
            .map((item) => [item.id, { status: item.status, description: item.description }]),
        ),
      };
    }

    const first = withRuntimeEnvironment(
      {
        STEWARD_JWT_SECRET: firstSecret,
        AGENT_TOKEN_EXPIRY: "1h",
        STEWARD_DEFAULT_TENANT_ID: "tenant-first",
        STEWARD_RATE_LIMIT_WINDOW_MS: "1000",
        STEWARD_RATE_LIMIT_MAX_REQUESTS: "7",
        STEWARD_ALLOW_INSECURE_WEBHOOK_URLS: "true",
        STEWARD_ALLOW_GLOBAL_WALLET_SEND_TRANSACTION: "true",
        STEWARD_REQUIRE_REQUEST_EXPIRY: "true",
        STEWARD_REQUIRE_AUTH_SIGNATURE: "true",
        STEWARD_REQUEST_SIGNING_SECRET: "request-signing-secret",
      },
      async () => {
        await secondReady;
        const settings = await readRequestSettings();
        releaseSecond();
        return settings;
      },
    );
    const second = withRuntimeEnvironment(
      {
        STEWARD_JWT_SECRET: secondSecret,
        AGENT_TOKEN_EXPIRY: "5m",
        STEWARD_DEFAULT_TENANT_ID: "tenant-second",
        STEWARD_RATE_LIMIT_WINDOW_MS: "2000",
        STEWARD_RATE_LIMIT_MAX_REQUESTS: "9",
      },
      async () => {
        markSecondReady();
        await secondCanRead;
        return readRequestSettings();
      },
    );

    const [firstSettings, secondSettings] = await Promise.all([first, second]);
    expect(firstSettings).toMatchObject({
      tenantId: "tenant-first",
      rateWindowMs: 1000,
      rateMax: 7,
      insecureWebhookError: null,
      walletSendEnabled: true,
      posture: { requestExpiryRequired: true, authorizationSignatureRequired: true },
      checklist: {
        "request-expiry": {
          status: "pass",
          description:
            "Every sensitive request requires an expiry or timestamp freshness header in production.",
        },
        "authorization-signatures": {
          status: "pass",
          description:
            "Sensitive machine requests require X-Steward-Signature and have an env, app-client, or tenant signing key available; public browser auth and verified user sessions under /user are exempt unless explicitly forced.",
        },
      },
    });
    expect(secondSettings).toMatchObject({
      tenantId: "tenant-second",
      rateWindowMs: 2000,
      rateMax: 9,
      insecureWebhookError: "url must use https",
      walletSendEnabled: false,
      posture: { requestExpiryRequired: false, authorizationSignatureRequired: false },
      checklist: {
        "request-expiry": {
          status: "warning",
          description:
            "Sensitive mutating requests validate freshness headers when present but do not require them.",
        },
        "authorization-signatures": {
          status: "warning",
          description:
            "Authorization signatures are verified when present but are not required by this deployment posture.",
        },
      },
    });
    await expect(
      jwtVerify(firstSettings.token, new TextEncoder().encode(firstSecret)),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(secondSettings.token, new TextEncoder().encode(secondSecret)),
    ).resolves.toBeDefined();
    await expect(
      jwtVerify(firstSettings.token, new TextEncoder().encode(secondSecret)),
    ).rejects.toThrow();
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

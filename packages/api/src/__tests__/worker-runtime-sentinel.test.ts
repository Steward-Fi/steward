import { expect, spyOn, test } from "bun:test";
import * as databaseModule from "@stwd/db";
import {
  __resetAuditHmacKeyCacheForTests,
  getDb,
  tenants,
  waitUntilRequestDatabaseTask,
} from "@stwd/db";
import { createPGLiteDb } from "@stwd/db/pglite";
import {
  __resetWorkerRlsReadinessForTests,
  __setWorkerInitForTests,
  ensureWorkerRlsReady,
  hydrateProcessEnv,
  runWorkerGoogleCredentialLifecycleSweep,
  runWorkerRlsGuardedTask,
  runWorkerUpstreamCredentialLeaseSweep,
  runWorkerXCredentialLifecycleSweep,
  withWorkerRequestDatabase,
  default as worker,
} from "../worker";

test("Worker RLS readiness is authority-keyed, retryable, and gates work", async () => {
  __resetWorkerRlsReadinessForTests();
  const requestDb = { marker: "rls-readiness" } as unknown as ReturnType<typeof getDb>;
  const baseEnv = {
    DATABASE_URL: "postgresql://worker.invalid/steward-a",
    DATABASE_DRIVER: "neon-websocket",
    NODE_ENV: "production",
    STEWARD_APP_DATABASE_ROLE: "steward_app",
    STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
  };
  let assertions = 0;
  let work = 0;
  let rejectOnce = true;
  const assertReady = async (
    db: ReturnType<typeof getDb>,
    options: { expectedRole: string; expectedPlatformRole: string },
  ) => {
    assertions += 1;
    expect((db as unknown as { marker: string }).marker).toBe("rls-readiness");
    expect(options).toEqual({
      expectedRole: "steward_app",
      expectedPlatformRole: "steward_platform",
    });
    if (rejectOnce) {
      rejectOnce = false;
      throw new Error("unsafe role");
    }
  };
  const createHandle = () => ({
    driver: "neon-websocket" as const,
    db: requestDb as never,
    async close() {},
  });

  await expect(
    withWorkerRequestDatabase(
      baseEnv,
      () => runWorkerRlsGuardedTask(baseEnv, async () => void (work += 1), assertReady as never),
      { createHandle },
    ),
  ).rejects.toThrow("unsafe role");
  expect(work).toBe(0);

  await withWorkerRequestDatabase(
    baseEnv,
    () => runWorkerRlsGuardedTask(baseEnv, async () => void (work += 1), assertReady as never),
    { createHandle },
  );
  await withWorkerRequestDatabase(
    baseEnv,
    () => ensureWorkerRlsReady(baseEnv, assertReady as never),
    {
      createHandle,
    },
  );
  expect(assertions).toBe(2);
  expect(work).toBe(1);

  const rotatedEnv = { ...baseEnv, DATABASE_URL: "postgresql://worker.invalid/steward-b" };
  await withWorkerRequestDatabase(
    rotatedEnv,
    () => ensureWorkerRlsReady(rotatedEnv, assertReady as never),
    { createHandle },
  );
  expect(assertions).toBe(3);
  __resetWorkerRlsReadinessForTests();
});

test("Worker hydration cannot be overridden by a STEWARD_RUNTIME binding", () => {
  const previous = process.env.STEWARD_RUNTIME;
  try {
    hydrateProcessEnv({
      DATABASE_URL: "postgresql://worker.invalid/steward",
      STEWARD_RUNTIME: "bun",
    });
    expect(process.env.STEWARD_RUNTIME).toBe("workers");
  } finally {
    if (previous === undefined) delete process.env.STEWARD_RUNTIME;
    else process.env.STEWARD_RUNTIME = previous;
  }
});

test("Worker request database is exact, request-owned, and always closed", async () => {
  const requestDb = { marker: "worker-request" } as unknown as ReturnType<typeof getDb>;
  let closes = 0;
  const createHandle = () => ({
    driver: "neon-websocket" as const,
    db: requestDb as never,
    async close() {
      closes += 1;
    },
  });
  const env = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-websocket",
  };

  expect(
    await withWorkerRequestDatabase(
      env,
      async () => {
        await Promise.resolve();
        expect(getDb()).not.toBe(requestDb);
        expect((getDb() as unknown as { marker: string }).marker).toBe("worker-request");
        return "ok";
      },
      { createHandle },
    ),
  ).toBe("ok");
  expect(closes).toBe(1);

  await expect(
    withWorkerRequestDatabase(
      env,
      async () => {
        expect((getDb() as unknown as { marker: string }).marker).toBe("worker-request");
        throw new Error("handler failed");
      },
      { createHandle },
    ),
  ).rejects.toThrow("handler failed");
  expect(closes).toBe(2);
});

test("Worker HTTP mode binds an exact request database without a persistent handle", async () => {
  let created = 0;
  const requestDb = { marker: "worker-http-request" } as unknown as ReturnType<typeof getDb>;
  const result = await withWorkerRequestDatabase(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      DATABASE_DRIVER: "neon-http",
      NODE_ENV: "test",
    },
    async () => {
      await Promise.resolve();
      expect(getDb()).not.toBe(requestDb);
      expect((getDb() as unknown as { marker: string }).marker).toBe("worker-http-request");
      return "http";
    },
    {
      createHttpDb: () => requestDb,
      createHandle: () => {
        created += 1;
        throw new Error("must not create socket handle");
      },
    },
  );
  expect(result).toBe("http");
  expect(created).toBe(0);
});

test("Worker request membrane preserves real Drizzle query execution", async () => {
  const { db: pgliteDb, client } = await createPGLiteDb("memory://");
  try {
    const rows = await withWorkerRequestDatabase(
      {
        DATABASE_URL: "postgresql://worker.invalid/steward",
        DATABASE_DRIVER: "neon-http",
        NODE_ENV: "test",
      },
      () => getDb().select({ id: tenants.id }).from(tenants).limit(1),
      { createHttpDb: () => pgliteDb },
    );
    expect(Array.isArray(rows)).toBe(true);
  } finally {
    await client.close();
  }
});

test("Worker database selection rejects missing or unsupported drivers", async () => {
  for (const DATABASE_DRIVER of [undefined, "", "postgres-js", "bogus"]) {
    await expect(
      withWorkerRequestDatabase(
        { DATABASE_URL: "postgresql://worker.invalid/steward", DATABASE_DRIVER },
        async () => "unreachable",
      ),
    ).rejects.toThrow("WORKER_DATABASE_DRIVER_UNSUPPORTED");
  }
});

test("Worker HTTP mode fails closed unless non-production is explicit", async () => {
  for (const NODE_ENV of [undefined, "", "production", "staging"]) {
    await expect(
      withWorkerRequestDatabase(
        {
          DATABASE_URL: "postgresql://worker.invalid/steward",
          DATABASE_DRIVER: "neon-http",
          NODE_ENV,
        },
        async () => "unreachable",
        { createHttpDb: () => ({}) as never },
      ),
    ).rejects.toThrow("WORKER_DATABASE_DRIVER_NOT_TRANSACTIONAL");
  }
});

test("cold Worker cron rejects a hostile database role before starting sweeps", async () => {
  const hostileDb = {
    async execute() {
      return [
        {
          current_user: "hostile_owner",
          session_user: "hostile_owner",
          rolsuper: true,
          rolbypassrls: true,
          owns_rls_relation: true,
        },
      ];
    },
  } as unknown as ReturnType<typeof getDb>;
  let databases = 0;
  let closes = 0;
  const createDbSpy = spyOn(databaseModule, "createNeonTransactionDbForRequest").mockImplementation(
    () => {
      databases += 1;
      return {
        driver: "neon-websocket",
        db: hostileDb as never,
        async close() {
          closes += 1;
        },
      };
    },
  );
  let scheduledWork!: Promise<unknown>;
  const env = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-websocket",
    NODE_ENV: "production",
    STEWARD_APP_DATABASE_ROLE: "steward_app",
    STEWARD_PLATFORM_DATABASE_ROLE: "steward_platform",
    STEWARD_JWT_SECRET: "worker-hostile-role-secret-at-least-32-chars",
  };
  const previousEnv = new Map(Object.keys(env).map((key) => [key, process.env[key]] as const));
  __setWorkerInitForTests(null);
  __resetWorkerRlsReadinessForTests();
  try {
    await worker.scheduled({}, env, {
      waitUntil(promise) {
        scheduledWork = promise;
      },
    });
    await expect(scheduledWork).rejects.toThrow("RLS_DEPLOYMENT_ROLE_UNSAFE");
    expect(databases).toBe(1);
    expect(closes).toBe(1);
  } finally {
    __setWorkerInitForTests(null);
    __resetWorkerRlsReadinessForTests();
    createDbSpy.mockRestore();
    for (const [key, value] of previousEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("Worker cron gives every autonomous sweep its own request database", async () => {
  const upstreamScheduler = await import("../services/upstream-credential-lease-scheduler");
  const googleScheduler = await import("../services/provider-google-lifecycle-scheduler");
  const xScheduler = await import("../services/provider-x-lifecycle-scheduler");
  const seen: string[] = [];
  let databaseCount = 0;
  const createDbSpy = spyOn(databaseModule, "createDbForRequest").mockImplementation(() => {
    databaseCount += 1;
    return { marker: `cron-db-${databaseCount}` } as unknown as ReturnType<typeof getDb>;
  });
  const upstreamSpy = spyOn(
    upstreamScheduler,
    "runUpstreamCredentialLeaseSweep",
  ).mockImplementation(async () => {
    await Promise.resolve();
    seen.push((getDb() as unknown as { marker: string }).marker);
    return { unknown: 0, revoked: 0, attention: 0, expired: 0 };
  });
  const googleSpy = spyOn(
    googleScheduler,
    "runGoogleCredentialLifecycleRecoverySweep",
  ).mockImplementation(async () => {
    await Promise.resolve();
    seen.push((getDb() as unknown as { marker: string }).marker);
    return {} as never;
  });
  const xSpy = spyOn(xScheduler, "runXCredentialLifecycleRecoverySweep").mockImplementation(
    async () => {
      await Promise.resolve();
      seen.push((getDb() as unknown as { marker: string }).marker);
      return {} as never;
    },
  );
  let scheduledWork!: Promise<unknown>;
  const env = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-http",
    NODE_ENV: "test",
    STEWARD_JWT_SECRET: "worker-cron-test-secret-at-least-32-chars",
    STEWARD_PLUGINS: "capabilities",
    GOOGLE_PROVIDER_CLIENT_ID: "google-client",
    GOOGLE_PROVIDER_CLIENT_SECRET: "google-secret",
    X_CLIENT_ID: "x-client",
    X_CLIENT_SECRET: "x-secret",
    STEWARD_MASTER_PASSWORD: "worker-cron-master-password",
  };
  const previousEnv = new Map(Object.keys(env).map((key) => [key, process.env[key]] as const));

  try {
    __setWorkerInitForTests(Promise.resolve());
    await worker.scheduled({}, env, {
      waitUntil(promise) {
        scheduledWork = promise;
      },
    });
    await scheduledWork;
  } finally {
    __setWorkerInitForTests(null);
    createDbSpy.mockRestore();
    upstreamSpy.mockRestore();
    googleSpy.mockRestore();
    xSpy.mockRestore();
    for (const [key, value] of previousEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }

  expect(databaseCount).toBe(4);
  expect(seen.sort()).toEqual(["cron-db-2", "cron-db-3", "cron-db-4"]);
});

test("configured webhook work retains its request database until Worker cleanup", async () => {
  const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
  const previousDatabaseUrl = process.env.DATABASE_URL;
  process.env.STEWARD_MASTER_PASSWORD = "worker-webhook-test-master-password";
  process.env.DATABASE_URL = "postgresql://worker.invalid/steward";
  let dispatchWebhook: typeof import("../services/webhook-dispatch").dispatchWebhook;
  let encryptedSecret: string;
  let WebhookDispatcher: typeof import("@stwd/webhooks").WebhookDispatcher;
  try {
    ({ dispatchWebhook } = await import("../services/webhook-dispatch"));
    const webhooks = await import("@stwd/webhooks");
    WebhookDispatcher = webhooks.WebhookDispatcher;
    encryptedSecret = webhooks.encryptWebhookSecret("worker-webhook-signing-secret");
  } catch (error) {
    if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
    throw error;
  } finally {
    if (previousDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = previousDatabaseUrl;
  }
  let releaseDelivery!: () => void;
  const deliveryGate = new Promise<void>((resolve) => {
    releaseDelivery = resolve;
  });
  let closes = 0;
  let deliveryFinished = false;
  const requestDb = {
    marker: "worker-webhook",
    select: () => ({
      from: () => ({
        where: async () => [
          {
            id: "worker-webhook-config",
            tenantId: "tenant-worker-webhook",
            url: "https://1.1.1.1/steward-webhook",
            secret: encryptedSecret,
            events: ["tx.signed"],
            enabled: true,
            maxRetries: 0,
            retryBackoffMs: 0,
          },
        ],
      }),
    }),
    insert: () => ({
      values: () => ({ returning: async () => [{ id: "worker-webhook-delivery" }] }),
    }),
    update: () => ({
      set: () => ({
        where: () => ({ returning: async () => [{ id: "worker-webhook-delivery" }] }),
      }),
    }),
  } as unknown as ReturnType<typeof getDb>;
  let deferredCleanup!: Promise<unknown>;
  const dispatchSpy = spyOn(WebhookDispatcher.prototype, "dispatch").mockImplementation(
    async () => {
      await deliveryGate;
      deliveryFinished = (getDb() as unknown as { marker: string }).marker === "worker-webhook";
      return { success: true, attempts: 1, deliveredAt: new Date() };
    },
  );
  const owner = withWorkerRequestDatabase(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      DATABASE_DRIVER: "neon-websocket",
    },
    async () => {
      dispatchWebhook("tenant-worker-webhook", "agent-worker-webhook", "tx_signed", {});
      return new Response("accepted");
    },
    {
      createHandle: () => ({
        driver: "neon-websocket" as const,
        db: requestDb as never,
        async close() {
          expect(deliveryFinished).toBe(true);
          closes += 1;
        },
      }),
      waitUntil(promise) {
        deferredCleanup = promise;
      },
    },
  );

  try {
    expect((await owner).status).toBe(200);
    expect(deliveryFinished).toBe(false);
    expect(closes).toBe(0);
    releaseDelivery();
    await deferredCleanup;
    expect(deliveryFinished).toBe(true);
    expect(closes).toBe(1);
  } finally {
    dispatchSpy.mockRestore();
    if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
  }
});

test("best-effort audit work retains its request database until Worker cleanup", async () => {
  const { trackAuditEvent } = await import("../services/audit");
  const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
  process.env.STEWARD_AUDIT_HMAC_KEY = "a".repeat(64);
  __resetAuditHmacKeyCacheForTests();
  try {
    let releaseAudit!: () => void;
    const auditGate = new Promise<void>((resolve) => {
      releaseAudit = resolve;
    });
    let auditTransactionFinished = false;
    let auditGateConsumed = false;
    let closes = 0;
    const requestDb = {
      marker: "worker-audit",
      transaction: async (callback: (tx: { execute: () => Promise<unknown[]> }) => Promise<void>) =>
        callback({
          execute: async () => {
            if (!auditGateConsumed) {
              auditGateConsumed = true;
              await auditGate;
              auditTransactionFinished =
                (getDb() as unknown as { marker: string }).marker === "worker-audit";
            }
            return [];
          },
        }),
    } as unknown as ReturnType<typeof getDb>;
    let deferredCleanup!: Promise<unknown>;

    const response = await withWorkerRequestDatabase(
      {
        DATABASE_URL: "postgresql://worker.invalid/steward",
        DATABASE_DRIVER: "neon-websocket",
      },
      async () => {
        void trackAuditEvent({
          tenantId: "tenant-worker-audit",
          actorType: "system",
          action: "system.worker.audit_registration_test",
          metadata: {},
        });
        return new Response("accepted");
      },
      {
        createHandle: () => ({
          driver: "neon-websocket" as const,
          db: requestDb as never,
          async close() {
            expect(auditTransactionFinished).toBe(true);
            closes += 1;
          },
        }),
        waitUntil(promise) {
          deferredCleanup = promise;
        },
      },
    );

    expect(response.status).toBe(200);
    expect(auditTransactionFinished).toBe(false);
    expect(closes).toBe(0);
    releaseAudit();
    await deferredCleanup;
    expect(auditTransactionFinished).toBe(true);
    expect(closes).toBe(1);
  } finally {
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    __resetAuditHmacKeyCacheForTests();
  }
});

test("Worker closes a deferred database exactly once when waitUntil registration fails", async () => {
  const requestDb = { marker: "worker-wait-until-failure" } as unknown as ReturnType<typeof getDb>;
  let closes = 0;

  await expect(
    withWorkerRequestDatabase(
      {
        DATABASE_URL: "postgresql://worker.invalid/steward",
        DATABASE_DRIVER: "neon-websocket",
      },
      async () => {
        await waitUntilRequestDatabaseTask(async () => {});
        return "response";
      },
      {
        createHandle: () => ({
          driver: "neon-websocket" as const,
          db: requestDb as never,
          async close() {
            closes += 1;
          },
        }),
        waitUntil() {
          throw new Error("waitUntil registration failed");
        },
      },
    ),
  ).rejects.toThrow("waitUntil registration failed");
  expect(closes).toBe(1);

  await expect(
    withWorkerRequestDatabase(
      {
        DATABASE_URL: "postgresql://worker.invalid/steward",
        DATABASE_DRIVER: "neon-websocket",
      },
      async () => {
        void waitUntilRequestDatabaseTask(async () => {});
        throw new Error("handler failed");
      },
      {
        createHandle: () => ({
          driver: "neon-websocket" as const,
          db: requestDb as never,
          async close() {
            closes += 1;
          },
        }),
        waitUntil() {
          throw new Error("waitUntil registration failed");
        },
      },
    ),
  ).rejects.toThrow("handler failed");
  expect(closes).toBe(2);
});

test("Worker reports deferred close failures through waitUntil without delaying its response", async () => {
  const requestDb = { marker: "worker-close-failure" } as unknown as ReturnType<typeof getDb>;
  let closes = 0;
  let deferredCleanup!: Promise<unknown>;

  const response = await withWorkerRequestDatabase(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      DATABASE_DRIVER: "neon-websocket",
    },
    async () => new Response("accepted"),
    {
      createHandle: () => ({
        driver: "neon-websocket" as const,
        db: requestDb as never,
        async close() {
          closes += 1;
          throw new Error("database password canary");
        },
      }),
      waitUntil(promise) {
        deferredCleanup = promise;
      },
    },
  );

  expect(response.status).toBe(200);
  await expect(deferredCleanup).rejects.toThrow("WORKER_DATABASE_CLOSE_FAILED");
  expect(closes).toBe(1);
});

test("Worker socket cleanup diagnostics are fixed and cannot replace handler errors", async () => {
  const requestDb = { marker: "worker-request" } as unknown as ReturnType<typeof getDb>;
  const createHandle = () => ({
    driver: "neon-websocket" as const,
    db: requestDb as never,
    async close() {
      throw new Error("socket secret canary");
    },
  });
  const env = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-websocket",
  };
  await expect(withWorkerRequestDatabase(env, async () => "ok", { createHandle })).rejects.toThrow(
    "WORKER_DATABASE_CLOSE_FAILED",
  );
  await expect(
    withWorkerRequestDatabase(
      env,
      async () => {
        throw new Error("handler failed");
      },
      { createHandle },
    ),
  ).rejects.toThrow("handler failed");
});

test("Worker scheduled recovery processes pre-existing leases when capabilities are enabled", async () => {
  let calls = 0;
  const result = await runWorkerUpstreamCredentialLeaseSweep(
    { DATABASE_URL: "postgresql://worker.invalid/steward" },
    {
      capabilitiesEnabled: true,
      sweep: async () => {
        calls += 1;
        return { unknown: 1, revoked: 2, attention: 0, expired: 3 };
      },
    },
  );
  expect(calls).toBe(1);
  expect(result).toEqual({ unknown: 1, revoked: 2, attention: 0, expired: 3 });
});

test("Worker scheduled recovery is inert without the capabilities plugin", async () => {
  let calls = 0;
  const result = await runWorkerUpstreamCredentialLeaseSweep(
    { DATABASE_URL: "postgresql://worker.invalid/steward" },
    {
      capabilitiesEnabled: false,
      sweep: async () => {
        calls += 1;
        return { unknown: 0, revoked: 0, attention: 0, expired: 0 };
      },
    },
  );
  expect(calls).toBe(0);
  expect(result).toBeNull();
});

test("Worker cron runs Google lifecycle recovery when provider credentials are configured", async () => {
  let calls = 0;
  const result = await runWorkerGoogleCredentialLifecycleSweep(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      GOOGLE_PROVIDER_CLIENT_ID: "provider-client",
      GOOGLE_PROVIDER_CLIENT_SECRET: "provider-secret",
      STEWARD_MASTER_PASSWORD: "worker-master",
    },
    {
      sweep: async () => {
        calls += 1;
        return { processed: 2, adopted: 1, revoked: 1, attention: 0, remaining: false };
      },
    },
  );
  expect(calls).toBe(1);
  expect(result).toEqual({ processed: 2, adopted: 1, revoked: 1, attention: 0, remaining: false });
});

test("Worker cron runs X lifecycle recovery when provider credentials are configured", async () => {
  let calls = 0;
  const result = await runWorkerXCredentialLifecycleSweep(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      X_CLIENT_ID: "provider-client",
      X_CLIENT_SECRET: "provider-secret",
      STEWARD_MASTER_PASSWORD: "worker-master",
    },
    {
      sweep: async () => {
        calls += 1;
        return { processed: 2, adopted: 1, revoked: 0, attention: 1, remaining: false };
      },
    },
  );
  expect(calls).toBe(1);
  expect(result).toEqual({
    processed: 2,
    adopted: 1,
    revoked: 0,
    attention: 1,
    remaining: false,
  });
});

test("Worker X lifecycle recovery is inert when the provider is unavailable", async () => {
  let calls = 0;
  const result = await runWorkerXCredentialLifecycleSweep(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      STEWARD_MASTER_PASSWORD: "worker-master",
    },
    {
      sweep: async () => {
        calls += 1;
        return {};
      },
    },
  );
  expect(calls).toBe(0);
  expect(result).toBeNull();
});

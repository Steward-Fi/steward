import { expect, spyOn, test } from "bun:test";
import { adapterRegistry } from "@stwd/adapters";
import { MemoryBackend } from "@stwd/auth";
import * as databaseModule from "@stwd/db";
import {
  __resetAuditHmacKeyCacheForTests,
  getDb,
  tenants,
  waitUntilRequestDatabaseTask,
} from "@stwd/db";
import { createPGLiteDb } from "@stwd/db/pglite";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { isPGLiteRuntime } from "../services/context";
import { isRuntimeVaultRpcMethodAllowed } from "../services/custody-runtime";
import { getConfiguredVault } from "../services/vault-factory";
import {
  __setWorkerComposedAppForTests,
  __setWorkerInitForTests,
  runWorkerGoogleCredentialLifecycleSweep,
  runWorkerUpstreamCredentialLeaseSweep,
  runWorkerXCredentialLifecycleSweep,
  withWorkerRequestDatabase,
  withWorkerRuntimeAuthority,
  default as worker,
} from "../worker";

test("user-link stores remain bound to overlapping request authorities", async () => {
  const authority = (token: string) => ({
    DATABASE_URL: `postgresql://worker.invalid/${token}`,
    DATABASE_DRIVER: "neon-http",
    NODE_ENV: "test",
    STEWARD_JWT_SECRET: `worker-${token}-jwt-secret-at-least-32-chars`,
    REDIS_DRIVER: "upstash",
    KV_REST_API_URL: `https://${token}.redis.invalid`,
    KV_REST_API_TOKEN: token,
  });
  const a = authority("authority-a");
  const b = authority("authority-b");
  const [userRoutes, authRoutes] = await withWorkerRuntimeAuthority(a, () =>
    Promise.all([import("../routes/user"), import("../routes/auth")]),
  );
  const {
    __consumeUserLinkChallengeForTests,
    __setUserLinkChallengeForTests,
    initUserLinkChallengeStores,
  } = userRoutes;
  const { authStoreAuthorityKey } = authRoutes;
  withWorkerRuntimeAuthority(a, () =>
    initUserLinkChallengeStores(new MemoryBackend(), authStoreAuthorityKey()),
  );
  withWorkerRuntimeAuthority(b, () =>
    initUserLinkChallengeStores(new MemoryBackend(), authStoreAuthorityKey()),
  );
  let releaseA!: () => void;
  const aBlocked = new Promise<void>((resolve) => {
    releaseA = resolve;
  });
  const pendingA = withWorkerRuntimeAuthority(a, async () => {
    await __setUserLinkChallengeForTests("wallet", "same", "a");
    await aBlocked;
    return __consumeUserLinkChallengeForTests("wallet", "same");
  });
  expect(
    await withWorkerRuntimeAuthority(b, async () => {
      await __setUserLinkChallengeForTests("wallet", "same", "b");
      return __consumeUserLinkChallengeForTests("wallet", "same");
    }),
  ).toBe("b");
  releaseA();
  expect(await pendingA).toBe("a");
  await expect(
    withWorkerRuntimeAuthority(authority("missing"), () =>
      __consumeUserLinkChallengeForTests("wallet", "same"),
    ),
  ).rejects.toThrow("not initialized for this authority");
});

test("mounted fetch and scheduled consumers retain hostile overlapping authorities", async () => {
  const upstreamScheduler = await import("../services/upstream-credential-lease-scheduler");
  const googleScheduler = await import("../services/provider-google-lifecycle-scheduler");
  const xScheduler = await import("../services/provider-x-lifecycle-scheduler");
  const createDbSpy = spyOn(databaseModule, "createDbForRequest").mockImplementation(
    () => ({ marker: "runtime-authority" }) as unknown as ReturnType<typeof getDb>,
  );
  let releaseFetch!: () => void;
  let fetchEntered!: () => void;
  const fetchBlocked = new Promise<void>((resolve) => {
    releaseFetch = resolve;
  });
  const fetchStarted = new Promise<void>((resolve) => {
    fetchEntered = resolve;
  });
  const scheduledProviders: string[] = [];
  const upstreamSpy = spyOn(upstreamScheduler, "runUpstreamCredentialLeaseSweep").mockResolvedValue(
    {
      unknown: 0,
      revoked: 0,
      attention: 0,
      expired: 0,
    },
  );
  const googleSpy = spyOn(
    googleScheduler,
    "runGoogleCredentialLifecycleRecoverySweep",
  ).mockImplementation(async () => {
    scheduledProviders.push(adapterRegistry.swap().provider);
    return {} as never;
  });
  const xSpy = spyOn(xScheduler, "runXCredentialLifecycleRecoverySweep").mockResolvedValue(
    {} as never,
  );
  __setWorkerInitForTests(Promise.resolve());
  __setWorkerComposedAppForTests({
    async fetch() {
      fetchEntered();
      await fetchBlocked;
      return new Response(adapterRegistry.swap().provider);
    },
  });
  const common = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-http",
    NODE_ENV: "test",
    STEWARD_JWT_SECRET: "worker-runtime-authority-secret-at-least-32-chars",
    GOOGLE_PROVIDER_CLIENT_ID: "runtime-google-client",
    GOOGLE_PROVIDER_CLIENT_SECRET: "runtime-google-secret",
  } as const;
  const processEnvironmentBefore = { ...process.env };
  try {
    const fetchResponse = worker.fetch(
      new Request("https://steward.test/consumer"),
      {
        ...common,
        STEWARD_SWAP_ADAPTER: "mock",
      },
      {},
    );
    await fetchStarted;
    let scheduledWork!: Promise<unknown>;
    await worker.scheduled(
      {},
      { ...common, STEWARD_SWAP_ADAPTER: "not-registered" },
      {
        waitUntil(promise) {
          scheduledWork = promise;
        },
      },
    );
    await scheduledWork;
    expect({ ...process.env }).toEqual(processEnvironmentBefore);
    releaseFetch();
    expect(await (await fetchResponse).text()).toBe("mock");
    expect(scheduledProviders).toEqual(["disabled"]);

    const missing = await worker.fetch(new Request("https://steward.test/missing"), common, {});
    // Explicit NODE_ENV=test retains the documented development mock fallback;
    // production binding-removal fail-closed behavior is covered by the mounted
    // adapter runtime suite with a production authority.
    expect(await missing.text()).toBe("mock");
    expect({ ...process.env }).toEqual(processEnvironmentBefore);
  } finally {
    releaseFetch();
    __setWorkerComposedAppForTests(null);
    __setWorkerInitForTests(null);
    createDbSpy.mockRestore();
    upstreamSpy.mockRestore();
    googleSpy.mockRestore();
    xSpy.mockRestore();
  }
});

test("Worker authority cannot mutate process.env or accept a runtime override", async () => {
  const processEnvironmentBefore = { ...process.env };
  await withWorkerRuntimeAuthority(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      STEWARD_RUNTIME: "bun",
    },
    async () => {
      expect(runtimeEnvironmentValue("STEWARD_RUNTIME")).toBe("workers");
      expect({ ...process.env }).toEqual(processEnvironmentBefore);
    },
  );
  expect({ ...process.env }).toEqual(processEnvironmentBefore);
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
  const createDbSpy = spyOn(databaseModule, "createDbForRequest").mockImplementation(() => {
    databases += 1;
    return hostileDb;
  });
  let scheduledWork!: Promise<unknown>;
  const env = {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-http",
    NODE_ENV: "test",
    STEWARD_APP_DATABASE_ROLE: "steward_app",
    STEWARD_JWT_SECRET: "worker-hostile-role-secret-at-least-32-chars",
  };
  const processEnvironmentBefore = { ...process.env };
  __setWorkerInitForTests(null);
  try {
    await worker.scheduled({}, env, {
      waitUntil(promise) {
        scheduledWork = promise;
      },
    });
    await expect(scheduledWork).rejects.toThrow("RLS_DEPLOYMENT_ROLE_UNSAFE");
    expect(databases).toBe(1);
    expect({ ...process.env }).toEqual(processEnvironmentBefore);
  } finally {
    __setWorkerInitForTests(null);
    createDbSpy.mockRestore();
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
  const processEnvironmentBefore = { ...process.env };

  try {
    __setWorkerInitForTests(Promise.resolve());
    await worker.scheduled({}, env, {
      waitUntil(promise) {
        scheduledWork = promise;
      },
    });
    await scheduledWork;
    expect({ ...process.env }).toEqual(processEnvironmentBefore);
  } finally {
    __setWorkerInitForTests(null);
    createDbSpy.mockRestore();
    upstreamSpy.mockRestore();
    googleSpy.mockRestore();
    xSpy.mockRestore();
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

test("overlapping scheduler invocations retain their own binding generation", async () => {
  let releaseFirst!: () => void;
  const firstEntered = Promise.withResolvers<void>();
  const firstRelease = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let disabledCalls = 0;

  const first = runWorkerGoogleCredentialLifecycleSweep(
    {
      DATABASE_URL: "postgresql://worker-a.invalid/steward",
      GOOGLE_PROVIDER_CLIENT_ID: "provider-a",
      GOOGLE_PROVIDER_CLIENT_SECRET: "secret-a",
    },
    {
      sweep: async () => {
        firstEntered.resolve();
        await firstRelease;
        return { generation: "a" };
      },
    },
  );
  await firstEntered.promise;
  const disabled = await runWorkerGoogleCredentialLifecycleSweep(
    {
      DATABASE_URL: "postgresql://worker-b.invalid/steward",
      GOOGLE_PROVIDER_CLIENT_ID: "provider-b",
      GOOGLE_PROVIDER_CLIENT_SECRET: "secret-b",
      STEWARD_GOOGLE_LIFECYCLE_SWEEPER: "false",
    },
    {
      sweep: async () => {
        disabledCalls += 1;
        return { generation: "b" };
      },
    },
  );
  releaseFirst();

  expect(disabled).toBeNull();
  expect(disabledCalls).toBe(0);
  expect(await first).toEqual({ generation: "a" });
  expect(
    await runWorkerGoogleCredentialLifecycleSweep(
      { DATABASE_URL: "postgresql://worker-missing.invalid/steward" },
      { sweep: async () => ({ generation: "missing" }) },
    ),
  ).toBeNull();
});

test("mounted requests isolate database, vault, and RPC authority across A -> B -> missing -> A", async () => {
  const createDbSpy = spyOn(databaseModule, "createDbForRequest").mockImplementation(
    (env) => ({ marker: env.DATABASE_URL }) as unknown as ReturnType<typeof databaseModule.getDb>,
  );
  const vaultIds = new WeakMap<object, number>();
  let nextVaultId = 1;
  let releaseA!: () => void;
  const aEntered = Promise.withResolvers<void>();
  const aRelease = new Promise<void>((resolve) => {
    releaseA = resolve;
  });
  const observe = () => {
    const requestDb = getDb() as unknown as { marker: string };
    const requestVault = getConfiguredVault() as unknown as object;
    let vaultId = vaultIds.get(requestVault);
    if (!vaultId) {
      vaultId = nextVaultId++;
      vaultIds.set(requestVault, vaultId);
    }
    return {
      database: requestDb.marker,
      vaultId,
      pglite: isPGLiteRuntime(),
      allowsA: isRuntimeVaultRpcMethodAllowed("eth_aOnly"),
      allowsB: isRuntimeVaultRpcMethodAllowed("eth_bOnly"),
    };
  };

  __setWorkerInitForTests(Promise.resolve());
  __setWorkerComposedAppForTests({
    async fetch(request) {
      const before = observe();
      if (new URL(request.url).pathname === "/a-overlap") {
        aEntered.resolve();
        await aRelease;
      }
      return Response.json({ before, after: observe() });
    },
  });

  const common = {
    DATABASE_DRIVER: "neon-http",
    NODE_ENV: "test",
    STEWARD_JWT_SECRET: "worker-mounted-authority-secret-at-least-32-chars",
  } as const;
  const authorityA = {
    ...common,
    DATABASE_URL: "postgresql://worker-a.invalid/steward",
    STEWARD_MASTER_PASSWORD: "mounted-authority-a",
    STEWARD_KDF_SALT: "a1".repeat(16),
    STEWARD_VAULT_RPC_ALLOWLIST: "eth_chainId,eth_aOnly",
  };
  const authorityB = {
    ...common,
    DATABASE_URL: "postgresql://worker-b.invalid/steward",
    STEWARD_DB_MODE: "pglite",
    STEWARD_MASTER_PASSWORD: "mounted-authority-b",
    STEWARD_KDF_SALT: "b2".repeat(16),
    STEWARD_VAULT_RPC_ALLOWLIST: "eth_chainId,eth_bOnly",
  };

  try {
    const pendingA = worker.fetch(new Request("https://steward.test/a-overlap"), authorityA, {});
    await aEntered.promise;
    const b = (await (
      await worker.fetch(new Request("https://steward.test/b"), authorityB, {})
    ).json()) as { before: ReturnType<typeof observe>; after: ReturnType<typeof observe> };
    await expect(
      worker.fetch(
        new Request("https://steward.test/missing"),
        {
          ...common,
          DATABASE_URL: "postgresql://worker-missing.invalid/steward",
          STEWARD_KDF_SALT: "c3".repeat(16),
        },
        {},
      ),
    ).rejects.toThrow("STEWARD_MASTER_PASSWORD is required");
    releaseA();
    const a = (await (await pendingA).json()) as {
      before: ReturnType<typeof observe>;
      after: ReturnType<typeof observe>;
    };
    const replayA = (await (
      await worker.fetch(new Request("https://steward.test/a-replay"), authorityA, {})
    ).json()) as { before: ReturnType<typeof observe>; after: ReturnType<typeof observe> };

    expect(a.before).toEqual(a.after);
    expect(a.before.database).toBe(authorityA.DATABASE_URL);
    expect(a.before.pglite).toBe(false);
    expect(a.before.allowsA).toBe(true);
    expect(a.before.allowsB).toBe(false);
    expect(b.before).toEqual(b.after);
    expect(b.before.database).toBe(authorityB.DATABASE_URL);
    expect(b.before.pglite).toBe(true);
    expect(b.before.allowsA).toBe(false);
    expect(b.before.allowsB).toBe(true);
    expect(b.before.vaultId).not.toBe(a.before.vaultId);
    expect(replayA.before.database).toBe(authorityA.DATABASE_URL);
    expect(replayA.before.allowsA).toBe(true);
    expect(replayA.before.allowsB).toBe(false);
    expect(replayA.before.vaultId).not.toBe(b.before.vaultId);
  } finally {
    releaseA();
    __setWorkerComposedAppForTests(null);
    __setWorkerInitForTests(null);
    createDbSpy.mockRestore();
  }
});

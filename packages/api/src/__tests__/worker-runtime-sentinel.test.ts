import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { getDb, tenants, waitUntilRequestDatabaseTask } from "@stwd/db";
import { createPGLiteDb } from "@stwd/db/pglite";
import {
  hydrateProcessEnv,
  runWorkerGoogleCredentialLifecycleSweep,
  runWorkerUpstreamCredentialLeaseSweep,
  runWorkerXCredentialLifecycleSweep,
  withWorkerRequestDatabase,
} from "../worker";

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

test("every autonomous recovery sweep owns its own request database", () => {
  const source = readFileSync(join(import.meta.dir, "../worker.ts"), "utf8");
  for (const sweep of [
    "runWorkerUpstreamCredentialLeaseSweep",
    "runWorkerGoogleCredentialLifecycleSweep",
    "runWorkerXCredentialLifecycleSweep",
  ]) {
    expect(source).toContain(`withWorkerRequestDatabase(env, () => ${sweep}(env))`);
  }
});

test("Worker drains fire-and-forget webhook work before closing its request pool", async () => {
  let releaseDelivery!: () => void;
  const deliveryGate = new Promise<void>((resolve) => {
    releaseDelivery = resolve;
  });
  let closes = 0;
  let deliveryFinished = false;
  const requestDb = { marker: "worker-webhook" } as unknown as ReturnType<typeof getDb>;
  const owner = withWorkerRequestDatabase(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      DATABASE_DRIVER: "neon-websocket",
    },
    async () => {
      // dispatchWebhook uses this same request-lifetime hook for its intentionally
      // unawaited configured delivery fan-out.
      void waitUntilRequestDatabaseTask(async () => {
        await deliveryGate;
        expect((getDb() as unknown as { marker: string }).marker).toBe("worker-webhook");
        deliveryFinished = true;
      });
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
    },
  );

  await Promise.resolve();
  expect(closes).toBe(0);
  releaseDelivery();
  expect((await owner).status).toBe(200);
  expect(deliveryFinished).toBe(true);
  expect(closes).toBe(1);

  const webhookSource = readFileSync(
    join(import.meta.dir, "../services/webhook-dispatch.ts"),
    "utf8",
  );
  expect(webhookSource).toContain("waitUntilRequestDatabaseTask(");
  const auditSource = readFileSync(join(import.meta.dir, "../services/audit.ts"), "utf8");
  expect(auditSource).toContain("waitUntilRequestDatabaseTask(");
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

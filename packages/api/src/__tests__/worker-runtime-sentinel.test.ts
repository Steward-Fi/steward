import { expect, test } from "bun:test";
import { getDb } from "@stwd/db";
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
        expect(getDb()).toBe(requestDb);
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
        expect(getDb()).toBe(requestDb);
        throw new Error("handler failed");
      },
      { createHandle },
    ),
  ).rejects.toThrow("handler failed");
  expect(closes).toBe(2);
});

test("Worker HTTP mode creates no persistent request handle", async () => {
  let created = 0;
  const result = await withWorkerRequestDatabase(
    {
      DATABASE_URL: "postgresql://worker.invalid/steward",
      DATABASE_DRIVER: "neon-http",
    },
    async () => "http",
    {
      createHandle: () => {
        created += 1;
        throw new Error("must not create socket handle");
      },
    },
  );
  expect(result).toBe("http");
  expect(created).toBe(0);
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

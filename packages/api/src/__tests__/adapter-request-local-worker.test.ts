import { afterAll, beforeAll, describe, expect, spyOn, test } from "bun:test";
import { type AdapterCategory, adapterRegistry, type BaseAdapter } from "@stwd/adapters";
import * as databaseModule from "@stwd/db";
import { Hono } from "hono";
import type { StewardApp } from "../plugin";
import type { AppVariables } from "../services/context";
import {
  __setWorkerComposedAppForTests,
  __setWorkerInitForTests,
  type Env,
  hydrateProcessEnv,
  default as worker,
} from "../worker";

const CATEGORIES = [
  "swap",
  "earn",
  "onramp",
  "offramp",
  "kyc",
  "tos",
  "custodial",
  "push",
  "bridge",
  "spark",
  "exchange",
] as const satisfies readonly AdapterCategory[];

const PROVIDER_A = "request-local-a-768";
const PROVIDER_B = "request-local-b-768";
const ENV_KEYS = [
  "DATABASE_URL",
  "DATABASE_DRIVER",
  "NODE_ENV",
  "STEWARD_RUNTIME",
  "STEWARD_JWT_SECRET",
  "STEWARD_MASTER_PASSWORD",
  "STEWARD_ALLOW_MOCK_ADAPTERS",
  ...CATEGORIES.map((category) => `STEWARD_${category.toUpperCase()}_ADAPTER`),
] as const;

type AdapterDescription = Record<AdapterCategory, { provider: string; enabled: boolean }>;

function implementation(category: AdapterCategory, generation: "a" | "b"): BaseAdapter {
  return { category, provider: `${generation}-${category}`, enabled: true };
}

function selections(provider: string): Record<string, string> {
  return Object.fromEntries(
    CATEGORIES.map((category) => [`STEWARD_${category.toUpperCase()}_ADAPTER`, provider]),
  );
}

function workerEnvironment(overrides: Record<string, string> = {}): Env {
  return {
    DATABASE_URL: "postgresql://worker.invalid/steward",
    DATABASE_DRIVER: "neon-websocket",
    NODE_ENV: "production",
    STEWARD_JWT_SECRET: "adapter-request-local-worker-secret-32-chars",
    ...overrides,
  };
}

async function requestAdapters(
  environment: Env,
  headers?: HeadersInit,
): Promise<{ response: Response; adapters: AdapterDescription }> {
  const response = await worker.fetch(
    new Request("https://steward.invalid/adapters", { headers }),
    environment,
    {},
  );
  const body = (await response.json()) as {
    ok: boolean;
    data: { adapters: AdapterDescription };
  };
  expect(response.status).toBe(200);
  expect(body.ok).toBe(true);
  return { response, adapters: body.data.adapters };
}

function expectGeneration(adapters: AdapterDescription, generation: "a" | "b"): void {
  for (const category of CATEGORIES) {
    expect(adapters[category]).toEqual({ provider: `${generation}-${category}`, enabled: true });
  }
}

function expectProvider(
  adapters: AdapterDescription,
  provider: "mock" | "disabled",
  enabled: boolean,
): void {
  for (const category of CATEGORIES) {
    expect(adapters[category]).toEqual({ provider, enabled });
  }
}

describe("request-local Worker adapter authority", () => {
  const previousEnvironment = new Map(ENV_KEYS.map((key) => [key, process.env[key]] as const));
  let databaseSpy: ReturnType<typeof spyOn>;
  let releaseRequestA!: () => void;
  let requestAStarted!: () => void;
  let requestAGate: Promise<void>;
  let requestAStart: Promise<void>;

  beforeAll(async () => {
    // These modules deliberately validate the Bun environment at import time.
    // The Worker request itself still gets its complete authority from bindings.
    process.env.DATABASE_URL = "postgresql://worker.invalid/steward";
    process.env.STEWARD_MASTER_PASSWORD = "adapter-request-local-worker-master-password";
    const [{ PluginHost }, { adapterRoutes }] = await Promise.all([
      import("../plugin"),
      import("../routes/adapters"),
    ]);
    const app = new Hono<{ Variables: AppVariables }>();
    app.use("/adapters", async (c, next) => {
      const before = adapterRegistry.swap().provider;
      if (c.req.header("x-pause-adapter-request") === "true") {
        requestAStarted();
        await requestAGate;
      }
      await next();
      c.header("x-adapter-before", before);
      c.header("x-adapter-after", adapterRegistry.swap().provider);
    });
    app.route("/adapters", adapterRoutes);

    const host = new PluginHost<{ adapterRegistry: typeof adapterRegistry }>();
    await host.register(
      app as StewardApp,
      { adapterRegistry },
      {
        name: "request-local-adapter-a",
        version: "1.0.0",
        adapters: CATEGORIES.map((category) => ({
          category,
          provider: PROVIDER_A,
          adapter: implementation(category, "a"),
        })),
      },
      {
        name: "request-local-adapter-b",
        version: "1.0.0",
        adapters: CATEGORIES.map((category) => ({
          category,
          provider: PROVIDER_B,
          adapter: implementation(category, "b"),
        })),
      },
    );

    databaseSpy = spyOn(databaseModule, "createNeonTransactionDbForRequest").mockImplementation(
      () => ({
        driver: "neon-websocket",
        db: { requestLocalAdapterTest: true } as never,
        async close() {},
      }),
    );
    __setWorkerInitForTests(Promise.resolve());
    __setWorkerComposedAppForTests(app);
  });

  afterAll(() => {
    __setWorkerComposedAppForTests(null);
    __setWorkerInitForTests(null);
    databaseSpy.mockRestore();
    // Clear the Worker's compatibility mirror bookkeeping, then put back the
    // exact Bun process environment this test observed on entry.
    hydrateProcessEnv({} as Env);
    for (const [key, value] of previousEnvironment) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  test("sequential A -> B -> missing rotation covers every plugin-registered category", async () => {
    const selectedA = await requestAdapters(workerEnvironment(selections(PROVIDER_A)));
    expectGeneration(selectedA.adapters, "a");

    const selectedB = await requestAdapters(workerEnvironment(selections(PROVIDER_B)));
    expectGeneration(selectedB.adapters, "b");

    const removed = await requestAdapters(workerEnvironment());
    expectProvider(removed.adapters, "disabled", false);

    const unknown = await requestAdapters(workerEnvironment(selections("removed-provider")));
    expectProvider(unknown.adapters, "disabled", false);
  });

  test("production mock access requires the exact current request acknowledgement", async () => {
    const acknowledged = await requestAdapters(
      workerEnvironment({
        STEWARD_ALLOW_MOCK_ADAPTERS: "true",
        ...selections("mock"),
      }),
    );
    expectProvider(acknowledged.adapters, "mock", true);

    const acknowledgementRemoved = await requestAdapters(workerEnvironment(selections("mock")));
    expectProvider(acknowledgementRemoved.adapters, "disabled", false);

    const selectionRemoved = await requestAdapters(
      workerEnvironment({ STEWARD_ALLOW_MOCK_ADAPTERS: "true" }),
    );
    expectProvider(selectionRemoved.adapters, "disabled", false);
  });

  test("hostile overlap retains A across suspension while B completes", async () => {
    requestAGate = new Promise<void>((resolve) => {
      releaseRequestA = resolve;
    });
    requestAStart = new Promise<void>((resolve) => {
      requestAStarted = resolve;
    });

    const pendingA = requestAdapters(workerEnvironment(selections(PROVIDER_A)), {
      "x-pause-adapter-request": "true",
    });
    await requestAStart;

    const selectedB = await requestAdapters(workerEnvironment(selections(PROVIDER_B)));
    expectGeneration(selectedB.adapters, "b");
    expect(selectedB.response.headers.get("x-adapter-before")).toBe("b-swap");
    expect(selectedB.response.headers.get("x-adapter-after")).toBe("b-swap");

    releaseRequestA();
    const selectedA = await pendingA;
    expectGeneration(selectedA.adapters, "a");
    expect(selectedA.response.headers.get("x-adapter-before")).toBe("a-swap");
    expect(selectedA.response.headers.get("x-adapter-after")).toBe("a-swap");
  });
});

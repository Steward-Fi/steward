/**
 * Request-bound adapter selection evidence at the two production integration
 * boundaries: mounted Hono routes and the Cloudflare Worker entry point.
 */

import { afterEach, describe, expect, it } from "bun:test";
import { adapterRegistry } from "@stwd/adapters";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { Hono } from "hono";
import { adapterRoutes } from "../routes/adapters";
import worker from "../worker";

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
] as const;

const MANAGED_KEYS = [
  "STEWARD_RUNTIME",
  "NODE_ENV",
  "STEWARD_JWT_SECRET",
  "STEWARD_ALLOW_MOCK_ADAPTERS",
  ...CATEGORIES.map((category) => `STEWARD_${category.toUpperCase()}_ADAPTER`),
] as const;

const savedEnvironment = new Map<string, string | undefined>();

function mockBindings(): Record<string, string> {
  return Object.fromEntries(
    CATEGORIES.map((category) => [`STEWARD_${category.toUpperCase()}_ADAPTER`, "mock"]),
  );
}

function expectSelection(
  selection: ReturnType<typeof adapterRegistry.describe>,
  provider: "mock" | "disabled",
  enabled: boolean,
): void {
  for (const category of CATEGORIES) {
    expect(selection[category]).toEqual({ provider, enabled });
  }
}

async function captureWorkerSelection(env: Record<string, string>) {
  let captured: ReturnType<typeof adapterRegistry.describe> | undefined;
  const context = Object.defineProperty({}, "waitUntil", {
    get() {
      captured = adapterRegistry.describe();
      throw new Error("adapter selection captured before database selection");
    },
  });
  await expect(
    worker.fetch(new Request("https://workers.test/adapters"), env as never, context),
  ).rejects.toThrow("adapter selection captured before database selection");
  if (!captured) throw new Error("Worker request did not expose its adapter selection");
  return captured;
}

describe("request-local adapter environment integration", () => {
  afterEach(() => {
    for (const [key, prior] of savedEnvironment) {
      if (prior === undefined) delete process.env[key];
      else process.env[key] = prior;
    }
    savedEnvironment.clear();
  });

  function snapshotEnvironment(): void {
    for (const key of MANAGED_KEYS) savedEnvironment.set(key, process.env[key]);
  }

  it("mounted routes stop exposing mocks on the next request after binding removal", async () => {
    const app = new Hono().route("/adapters", adapterRoutes);
    const allowed = await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_ALLOW_MOCK_ADAPTERS: "true",
        ...mockBindings(),
      },
      () => app.request("/adapters/"),
    );
    expect(allowed.status).toBe(200);
    const allowedBody = (await allowed.json()) as {
      data: { adapters: ReturnType<typeof adapterRegistry.describe> };
    };
    expectSelection(allowedBody.data.adapters, "mock", true);

    const removed = await withRuntimeEnvironment(
      { STEWARD_RUNTIME: "workers", NODE_ENV: "production" },
      () => app.request("/adapters/"),
    );
    expect(removed.status).toBe(200);
    const removedBody = (await removed.json()) as {
      data: { adapters: ReturnType<typeof adapterRegistry.describe> };
    };
    expectSelection(removedBody.data.adapters, "disabled", false);
  });

  it("the reused Worker isolate resolves mocks, then fails closed after binding removal", async () => {
    snapshotEnvironment();
    const common = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "worker-adapter-runtime-secret-at-least-32-chars",
      DATABASE_DRIVER: "bogus",
    };
    const allowed = await captureWorkerSelection({
      ...common,
      STEWARD_ALLOW_MOCK_ADAPTERS: "true",
      ...mockBindings(),
    });
    expectSelection(allowed, "mock", true);

    const removed = await captureWorkerSelection(common);
    expectSelection(removed, "disabled", false);
  });
});

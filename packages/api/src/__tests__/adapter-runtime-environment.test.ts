/**
 * Request-bound adapter selection evidence at the two production integration
 * boundaries: mounted Hono routes and the Cloudflare Worker entry point.
 */

import { afterEach, describe, expect, it } from "bun:test";
import { adapterRegistry } from "@stwd/adapters";
import {
  createWxmrBridgeAdapter,
  WXMR_MONERO_CHAIN_ID,
  WXMR_SOLANA_CHAIN_ID,
} from "@stwd/plugin-wxmr";
import { MONERO_ON_SOLANA } from "@stwd/shared";
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
const originalFetch = globalThis.fetch;

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
    globalThis.fetch = originalFetch;
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
      () => app.request("/adapters"),
    );
    expect(allowed.status).toBe(200);
    const allowedBody = (await allowed.json()) as {
      data: { adapters: ReturnType<typeof adapterRegistry.describe> };
    };
    expectSelection(allowedBody.data.adapters, "mock", true);

    const removed = await withRuntimeEnvironment(
      { STEWARD_RUNTIME: "workers", NODE_ENV: "production" },
      () => app.request("/adapters"),
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

  it("the mounted Worker keeps WXMR RPC authority request-local across A -> B -> A and removal", async () => {
    const provider = "worker-wxmr-authority-regression";
    adapterRegistry.registerFactory("bridge", provider, createWxmrBridgeAdapter);
    const observedUrls: string[] = [];
    let releaseSuspendedA: (() => void) | undefined;
    let suspendFirstA = true;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      observedUrls.push(url);
      if (url === "https://rpc-a.example.test/" && suspendFirstA) {
        suspendFirstA = false;
        return new Promise<Response>((resolve) => {
          releaseSuspendedA = () => resolve(new Response("unavailable", { status: 503 }));
        });
      }
      return new Response("unavailable", { status: 503 });
    }) as typeof fetch;

    const common = {
      NODE_ENV: "production",
      STEWARD_JWT_SECRET: "worker-adapter-runtime-secret-at-least-32-chars",
      DATABASE_DRIVER: "bogus",
      STEWARD_BRIDGE_ADAPTER: provider,
    };
    const quoteRequest = {
      fromChainId: WXMR_SOLANA_CHAIN_ID,
      toChainId: WXMR_MONERO_CHAIN_ID,
      fromToken: {
        address: MONERO_ON_SOLANA.address,
        symbol: "XMR",
        decimals: 12,
      },
      toToken: { address: "native", symbol: "XMR", decimals: 12 },
      amount: "1000000000000",
      recipient:
        "45AmZ2FRjuqZts5NGzb7ZXSNRuwS9MUqEeakpyEeSHsB5mywLwBzzq2cTsbJzTVUuLSHxtbfgKyZJVBqPffpP8fm79sjAcK",
      slippageBps: 0,
    } as const;

    async function capture(
      bindings: Record<string, string>,
      configured = true,
    ): Promise<{ providerOperation?: Promise<unknown> }> {
      let providerOperation: Promise<unknown> | undefined;
      const context = Object.defineProperty({}, "waitUntil", {
        get() {
          providerOperation = adapterRegistry.bridge().getQuote(quoteRequest);
          // Attach a handler before control returns to Worker.fetch so an
          // immediate upstream rejection cannot surface as an unhandled promise
          // while the test first observes the deliberate capture exception.
          void providerOperation.catch(() => undefined);
          throw new Error("provider operation captured inside Worker request authority");
        },
      });
      const workerRequest = worker.fetch(
        new Request("https://workers.test/adapters"),
        bindings as never,
        context,
      );
      await expect(workerRequest).rejects.toThrow(
        configured
          ? "provider operation captured inside Worker request authority"
          : "No bridge adapter is configured",
      );
      if (!configured) {
        expect(providerOperation).toBeUndefined();
        return {};
      }
      if (!providerOperation) throw new Error("Worker request did not invoke the provider");
      return { providerOperation };
    }

    const suspendedA = await capture({
      ...common,
      WXMR_SOLANA_RPC_URL: "https://rpc-a.example.test",
    });
    expect(releaseSuspendedA).toBeFunction();

    const overlappingB = await capture({
      ...common,
      WXMR_SOLANA_RPC_URL: "https://rpc-b.example.test",
    });
    await expect(overlappingB.providerOperation).rejects.toThrow();

    releaseSuspendedA?.();
    await expect(suspendedA.providerOperation).rejects.toThrow();

    const resumedA = await capture({
      ...common,
      WXMR_SOLANA_RPC_URL: "https://rpc-a.example.test",
    });
    await expect(resumedA.providerOperation).rejects.toThrow();
    expect(observedUrls).toEqual([
      "https://rpc-a.example.test/",
      "https://rpc-b.example.test/",
      "https://rpc-a.example.test/",
    ]);

    await capture(common, false);
    expect(observedUrls).toHaveLength(3);
  });
});

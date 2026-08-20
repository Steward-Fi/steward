import { describe, expect, test } from "bun:test";
import { withRuntimeEnvironment } from "@stwd/shared/runtime-env";
import { MockSwapAdapter, type SwapAdapter } from "../adapters/swap.js";
import { AdapterRegistry } from "../registry.js";
import { type AdapterCategory, AdapterNotConfiguredError, type BaseAdapter } from "../types.js";

const FRESH_TOKENS = {
  fromToken: { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" },
  toToken: { address: "0x4200000000000000000000000000000000000006" },
  amount: "1000",
  chainId: 8453,
};

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

function selectionEnvironment(provider: string): Record<string, string> {
  return Object.fromEntries(
    CATEGORIES.map((category) => [`STEWARD_${category.toUpperCase()}_ADAPTER`, provider]),
  );
}

function namedAdapter(category: AdapterCategory, provider: string): BaseAdapter {
  return { category, provider, enabled: true };
}

describe("AdapterRegistry resolution", () => {
  test("DEV (no NODE_ENV): returns working mocks", async () => {
    const reg = new AdapterRegistry({ env: {} });
    expect(reg.swap().provider).toBe("mock");
    expect(reg.swap().enabled).toBe(true);
    const quote = await reg.swap().getQuote(FRESH_TOKENS);
    expect(quote.amountOut).toBe("997");
  });

  test("PRODUCTION with nothing configured: FAILS CLOSED (disabled adapter)", () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    const swap = reg.swap();
    expect(swap.provider).toBe("disabled");
    expect(swap.enabled).toBe(false);
    // Every operation throws AdapterNotConfiguredError (synchronously — the Proxy
    // refuses the call before any promise is created).
    expect(() => swap.getQuote(FRESH_TOKENS)).toThrow(AdapterNotConfiguredError);
  });

  test("PRODUCTION every category fails closed", async () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    const described = reg.describe();
    for (const category of Object.keys(described) as (keyof typeof described)[]) {
      expect(described[category].enabled).toBe(false);
      expect(described[category].provider).toBe("disabled");
    }
  });

  test("PRODUCTION mock use requires the current category selection and acknowledgement", () => {
    const reg = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_ALLOW_MOCK_ADAPTERS: "true" },
    });
    expect(reg.swap()).toMatchObject({ provider: "disabled", enabled: false });

    const acknowledged = new AdapterRegistry({
      env: {
        NODE_ENV: "production",
        STEWARD_SWAP_ADAPTER: "mock",
        STEWARD_ALLOW_MOCK_ADAPTERS: "true",
      },
    });
    expect(acknowledged.swap()).toMatchObject({ provider: "mock", enabled: true });
  });

  test("PRODUCTION + env names an unknown provider: FAILS CLOSED (never silently mocks)", () => {
    const reg = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_SWAP_ADAPTER: "some-real-provider" },
    });
    const swap = reg.swap();
    expect(swap.enabled).toBe(false);
    expect(() => swap.getQuote(FRESH_TOKENS)).toThrow(AdapterNotConfiguredError);
  });

  test("DEV + env names an unknown provider: STILL fails closed (operator intent honored)", () => {
    const reg = new AdapterRegistry({ env: { STEWARD_SWAP_ADAPTER: "nonexistent" } });
    const swap = reg.swap();
    expect(swap.enabled).toBe(false);
    expect(() => swap.getQuote(FRESH_TOKENS)).toThrow(AdapterNotConfiguredError);
  });

  test("env explicitly selects 'mock' in production -> disabled unless allow flag set", () => {
    const reg = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_SWAP_ADAPTER: "mock" },
    });
    expect(reg.swap().enabled).toBe(false);
    expect(() => reg.swap().getQuote(FRESH_TOKENS)).toThrow(AdapterNotConfiguredError);
  });

  test("a registered real provider is selected by env even in production", async () => {
    const reg = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_SWAP_ADAPTER: "acme" },
    });
    const real = new MockSwapAdapter() as SwapAdapter; // stand-in for a real provider
    reg.register("swap", "acme", real);
    expect(reg.swap()).toBe(real);
    expect(reg.swap().enabled).toBe(true);
  });

  test("production requires an explicit binding even with one durable provider", () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    const real = new MockSwapAdapter() as SwapAdapter;
    reg.register("swap", "only", real);
    expect(reg.swap()).toMatchObject({ provider: "disabled", enabled: false });
  });

  test("late registration remains durable but does not replace production selection policy", () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    expect(reg.swap().enabled).toBe(false);
    const real = new MockSwapAdapter() as SwapAdapter;
    reg.register("swap", "late", real);
    expect(reg.swap().enabled).toBe(false);

    const selected = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_SWAP_ADAPTER: "late" },
    });
    selected.register("swap", "late", real);
    expect(selected.swap()).toBe(real);
  });

  test("describe() introspects all adapter categories", () => {
    const reg = new AdapterRegistry({ env: {} });
    const described = reg.describe();
    expect(Object.keys(described).sort()).toEqual(
      [
        "bridge",
        "custodial",
        "earn",
        "exchange",
        "kyc",
        "offramp",
        "onramp",
        "push",
        "spark",
        "swap",
        "tos",
      ].sort(),
    );
  });

  test("Worker binding removal disables every previously-allowed mock category immediately", () => {
    const requestRegistry = new AdapterRegistry();
    const allowed = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_ALLOW_MOCK_ADAPTERS: "true",
        ...selectionEnvironment("mock"),
      },
      () => requestRegistry.describe(),
    );
    for (const category of CATEGORIES) {
      expect(allowed[category]).toEqual({ provider: "mock", enabled: true });
    }

    const removed = withRuntimeEnvironment(
      { STEWARD_RUNTIME: "workers", NODE_ENV: "production" },
      () => requestRegistry.describe(),
    );
    for (const category of CATEGORIES) {
      expect(removed[category]).toEqual({ provider: "disabled", enabled: false });
    }

    const selectionRemovedButAckRemains = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_ALLOW_MOCK_ADAPTERS: "true",
      },
      () => requestRegistry.describe(),
    );
    for (const category of CATEGORIES) {
      expect(selectionRemovedButAckRemains[category]).toEqual({
        provider: "disabled",
        enabled: false,
      });
    }
  });

  test("all categories rotate durable providers A -> B and fail closed when selection disappears", () => {
    const requestRegistry = new AdapterRegistry();
    for (const category of CATEGORIES) {
      requestRegistry.register(
        category,
        "rotation-a",
        namedAdapter(category, `a-${category}`) as never,
      );
      requestRegistry.register(
        category,
        "rotation-b",
        namedAdapter(category, `b-${category}`) as never,
      );
    }

    const describeWith = (provider?: string) =>
      withRuntimeEnvironment(
        {
          STEWARD_RUNTIME: "workers",
          NODE_ENV: "production",
          ...(provider ? selectionEnvironment(provider) : {}),
        },
        () => requestRegistry.describe(),
      );
    const selectedA = describeWith("rotation-a");
    const selectedB = describeWith("rotation-b");
    const missing = describeWith("removed-provider");
    for (const category of CATEGORIES) {
      expect(selectedA[category]).toEqual({ provider: `a-${category}`, enabled: true });
      expect(selectedB[category]).toEqual({ provider: `b-${category}`, enabled: true });
      expect(missing[category]).toEqual({ provider: "disabled", enabled: false });
    }
  });

  test("hostile overlap keeps each suspended request on its immutable adapter authority", async () => {
    const requestRegistry = new AdapterRegistry();
    requestRegistry.register("swap", "overlap-a", namedAdapter("swap", "overlap-a") as never);
    requestRegistry.register("swap", "overlap-b", namedAdapter("swap", "overlap-b") as never);
    let releaseA!: () => void;
    const gate = new Promise<void>((resolve) => {
      releaseA = resolve;
    });
    let startedA!: () => void;
    const started = new Promise<void>((resolve) => {
      startedA = resolve;
    });

    const requestA = withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_SWAP_ADAPTER: "overlap-a",
      },
      async () => {
        expect(requestRegistry.swap().provider).toBe("overlap-a");
        startedA();
        await gate;
        expect(requestRegistry.swap().provider).toBe("overlap-a");
      },
    );
    await started;
    await withRuntimeEnvironment(
      {
        STEWARD_RUNTIME: "workers",
        NODE_ENV: "production",
        STEWARD_SWAP_ADAPTER: "overlap-b",
      },
      async () => {
        expect(requestRegistry.swap().provider).toBe("overlap-b");
        releaseA();
      },
    );
    await requestA;
  });

  test("Workers without NODE_ENV fail closed while Bun retains its development fallback", () => {
    const requestRegistry = new AdapterRegistry();
    expect(
      withRuntimeEnvironment({ STEWARD_RUNTIME: "workers" }, () => requestRegistry.swap().enabled),
    ).toBe(false);
    const bunRegistry = new AdapterRegistry({ env: {} });
    expect(bunRegistry.swap().provider).toBe("mock");
    expect(bunRegistry.swap().enabled).toBe(true);
  });
});

import { describe, expect, test } from "bun:test";
import { MockSwapAdapter, type SwapAdapter } from "../adapters/swap.js";
import { AdapterRegistry } from "../registry.js";
import { AdapterNotConfiguredError } from "../types.js";

const FRESH_TOKENS = {
  fromToken: { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48" },
  toToken: { address: "0x4200000000000000000000000000000000000006" },
  amount: "1000",
  chainId: 8453,
};

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

  test("PRODUCTION + STEWARD_ALLOW_MOCK_ADAPTERS=true: mocks allowed (staging escape hatch)", () => {
    const reg = new AdapterRegistry({
      env: { NODE_ENV: "production", STEWARD_ALLOW_MOCK_ADAPTERS: "true" },
    });
    expect(reg.swap().provider).toBe("mock");
    expect(reg.swap().enabled).toBe(true);
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

  test("a single registered provider without env disambiguation is used", () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    const real = new MockSwapAdapter() as SwapAdapter;
    reg.register("swap", "only", real);
    expect(reg.swap()).toBe(real);
  });

  test("register invalidates a previously-resolved (disabled) instance", async () => {
    const reg = new AdapterRegistry({ env: { NODE_ENV: "production" } });
    // Resolve once -> disabled and cached.
    expect(reg.swap().enabled).toBe(false);
    // Now register a real provider; the cache must be invalidated.
    const real = new MockSwapAdapter() as SwapAdapter;
    reg.register("swap", "late", real);
    expect(reg.swap()).toBe(real);
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
});

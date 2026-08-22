/**
 * plugin-host-adapters.test.ts — focused unit tests for the Phase 2d plugin
 * adapter contribution wiring.
 *
 * Covers the host's load-bearing guarantees for `adapters`:
 *   - a plugin-contributed adapter is REGISTERED into the injected adapter
 *     registry and RESOLVES (via the registry's own env-driven selection) to the
 *     plugin's adapter — proving the contribution reaches the real money-route
 *     resolution path without the host touching the registry's resolution logic;
 *   - FAIL-CLOSED on a `(category, provider)` collision (two plugins, or one
 *     plugin twice) — the host refuses to silently overwrite a registered adapter;
 *   - FAIL-CLOSED on an unknown category;
 *   - FAIL-CLOSED on a missing adapter instance;
 *   - back-compat: a plugin with NO `adapters` registers fine.
 *
 * The host is exercised with an INJECTED `AdapterRegistry` (with a controlled
 * env) so adapter resolution is hermetic and the test owns provider selection.
 */

import { describe, expect, it } from "bun:test";
import { AdapterRegistry } from "@stwd/adapters";
import type { AdapterContribution } from "@stwd/shared";
import type { StewardApp } from "../plugin";
import { PluginHost, PluginHostError } from "../plugin";

// A minimal stub app. The fake plugins never mount routes; we assert only on the
// adapter registry, so an `unknown`-cast is safe.
const app = {} as StewardApp;

/** A fake swap adapter that just echoes its provider name. */
function fakeSwapAdapter(provider: string) {
  return {
    category: "swap" as const,
    provider,
    enabled: true,
    async getQuote() {
      throw new Error("not implemented in test");
    },
    async buildSwap() {
      throw new Error("not implemented in test");
    },
  };
}

/** Build a plugin that contributes the given adapter contributions. */
function adapterPlugin(name: string, adapters: readonly AdapterContribution[]) {
  return { name, adapters };
}

/**
 * The minimal ctx the host's adapter wiring reads: an `adapterRegistry`. Built
 * around an injected {@link AdapterRegistry} with a controlled env so resolution
 * is hermetic.
 */
function ctxWith(registry: AdapterRegistry) {
  return { adapterRegistry: registry };
}

describe("PluginHost — adapter contributions (Phase 2d)", () => {
  it("registers a contributed adapter that resolves via the injected registry", async () => {
    // env selects the contributed provider for the swap category.
    const registry = new AdapterRegistry({
      env: { STEWARD_SWAP_ADAPTER: "test-swap" },
    });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "test-swap", adapter: fakeSwapAdapter("test-swap") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await host.register(app, ctx, plugin);

    // The registry resolves swap() to the plugin's contributed adapter (NOT the
    // built-in mock), proving the contribution reached the real resolution path.
    expect(registry.swap().provider).toBe("test-swap");

    // Diagnostics surface the contribution.
    expect(host.describe().adapterContributions.trading).toEqual(["swap::test-swap"]);
  });

  it("registers request-authority factories without retaining their results", async () => {
    const registry = new AdapterRegistry({ env: { STEWARD_SWAP_ADAPTER: "factory-swap" } });
    let generation = 0;
    const plugin = adapterPlugin("factory-plugin", [
      {
        category: "swap",
        provider: "factory-swap",
        createAdapter: () => fakeSwapAdapter(`factory-${++generation}`),
      },
    ]);

    await new PluginHost<typeof registry>().register(app, ctxWith(registry), plugin);
    expect(registry.swap().provider).toBe("factory-1");
    expect(registry.swap().provider).toBe("factory-2");
  });

  it("registers without env disambiguation when a single provider is contributed", async () => {
    // No STEWARD_SWAP_ADAPTER set; a single registered provider is used as-is.
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "solo-swap", adapter: fakeSwapAdapter("solo-swap") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await host.register(app, ctx, plugin);

    expect(registry.swap().provider).toBe("solo-swap");
  });

  it("FAILS CLOSED on a (category, provider) collision between two plugins", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const a = adapterPlugin("plugin-a", [
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("a") },
    ]);
    const b = adapterPlugin("plugin-b", [
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("b") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, a, b)).rejects.toThrow(PluginHostError);
  });

  it("FAILS CLOSED on a (category, provider) collision within one plugin", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("first") },
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("second") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
  });

  it("FAILS CLOSED on a collision across SEPARATE register() passes on one host", async () => {
    // SEC-093: the guard must be durable — a plugin registered in a LATER host
    // pass must not silently overwrite a pair an earlier pass registered (the
    // registry's own register() is a silent Map.set-overwrite).
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const a = adapterPlugin("plugin-a", [
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("a") },
    ]);
    const b = adapterPlugin("plugin-b", [
      { category: "swap", provider: "dup", adapter: fakeSwapAdapter("b") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await host.register(app, ctx, a);
    await expect(host.register(app, ctx, b)).rejects.toThrow(PluginHostError);
    // and the original adapter is still the registered one (no clobber).
    expect(registry.swap().provider).toBe("a");
  });

  it("FAILS CLOSED on a collision with an adapter registered OUTSIDE the host", async () => {
    // SEC-093: core code (or a previous host) may have registered the pair
    // directly on the shared registry — a plugin contribution for the same
    // (category, provider) must refuse to overwrite it.
    const registry = new AdapterRegistry({ env: {} });
    registry.register("swap", "core-swap", fakeSwapAdapter("core-swap"));
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "core-swap", adapter: fakeSwapAdapter("plugin") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
    expect(registry.swap().provider).toBe("core-swap");
  });

  it("FAILS CLOSED on an unknown adapter category", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "not-a-category", provider: "x", adapter: fakeSwapAdapter("x") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
  });

  it("FAILS CLOSED on a missing adapter instance", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      // adapter is null — fail closed rather than register a non-adapter.
      { category: "swap", provider: "x", adapter: null },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
  });

  it("FAILS CLOSED when a contribution supplies both an instance and a factory", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);
    const plugin = adapterPlugin("ambiguous", [
      {
        category: "swap",
        provider: "x",
        adapter: fakeSwapAdapter("x"),
        createAdapter: () => fakeSwapAdapter("x"),
      },
    ]);

    await expect(new PluginHost<typeof ctx>().register(app, ctx, plugin)).rejects.toThrow(
      PluginHostError,
    );
  });

  it("FAILS CLOSED on an empty provider name", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "   ", adapter: fakeSwapAdapter("x") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
  });

  it("FAILS CLOSED when a plugin contributes adapters but ctx has no registry", async () => {
    const ctx = {} as { adapterRegistry?: AdapterRegistry };

    const plugin = adapterPlugin("trading", [
      { category: "swap", provider: "x", adapter: fakeSwapAdapter("x") },
    ]);

    const host = new PluginHost<typeof ctx>();
    await expect(host.register(app, ctx, plugin)).rejects.toThrow(PluginHostError);
  });

  it("BACK-COMPAT: a plugin with no adapters registers fine", async () => {
    const registry = new AdapterRegistry({ env: {} });
    const ctx = ctxWith(registry);

    const plugin = { name: "no-adapters", register() {} };

    const host = new PluginHost<typeof ctx>();
    await host.register(app, ctx, plugin);

    expect(host.describe().plugins.map((p) => p.name)).toEqual(["no-adapters"]);
    expect(host.describe().adapterContributions).toEqual({});
  });
});

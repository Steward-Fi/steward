/**
 * plugin-host.test.ts — focused unit tests for the Phase 2a plugin host.
 *
 * Covers the host's load-bearing guarantees:
 *   - `dependsOn` topological ordering (a plugin registers AFTER its deps);
 *   - duplicate plugin-name rejection (fail closed);
 *   - missing-dependency rejection (fail closed) BEFORE any register runs;
 *   - dependency-cycle detection (fail closed);
 *   - declared `webhookEvents` are merged into the runtime registry (core ∪
 *     plugin-declared) and surfaced via diagnostics.
 *
 * The host is exercised with lightweight fake plugins + a stub app/ctx — it does
 * not touch the db/vault, so these tests are pure and fast.
 */

import { describe, expect, it } from "bun:test";
import { WebhookEventRegistry } from "@stwd/shared";
import type { StewardApp } from "../plugin";
import { PluginHost, PluginHostError } from "../plugin";

// A minimal stub app + ctx. The fake plugins below never touch them; we only
// assert on registration order + the event registry, so `unknown`-casts are safe.
const app = {} as StewardApp;
type Ctx = Record<string, never>;
const ctx: Ctx = {};

/** Build a no-op plugin that records its registration order into `log`. */
function recordingPlugin(
  name: string,
  log: string[],
  opts: { dependsOn?: readonly string[]; webhookEvents?: readonly string[]; version?: string } = {},
) {
  return {
    name,
    version: opts.version,
    dependsOn: opts.dependsOn,
    webhookEvents: opts.webhookEvents,
    register() {
      log.push(name);
    },
  };
}

describe("PluginHost — dependency ordering", () => {
  it("registers a plugin AFTER the plugins it depends on", async () => {
    const log: string[] = [];
    // declared order is intentionally reverse-topological to prove the host
    // reorders by dependsOn, not by declaration order.
    const c = recordingPlugin("c", log, { dependsOn: ["b"] });
    const b = recordingPlugin("b", log, { dependsOn: ["a"] });
    const a = recordingPlugin("a", log);

    const host = new PluginHost<Ctx>();
    await host.register(app, ctx, c, b, a);

    expect(log).toEqual(["a", "b", "c"]);
    expect(host.describe().plugins.map((p) => p.name)).toEqual(["a", "b", "c"]);
  });

  it("keeps independent plugins in declared order", async () => {
    const log: string[] = [];
    const x = recordingPlugin("x", log);
    const y = recordingPlugin("y", log);
    const z = recordingPlugin("z", log);

    const host = new PluginHost<Ctx>();
    await host.register(app, ctx, x, y, z);

    expect(log).toEqual(["x", "y", "z"]);
  });

  it("orders a diamond dependency correctly (dep visited once)", async () => {
    const log: string[] = [];
    // d depends on b and c; both depend on a. a must run first, d last, exactly
    // once each.
    const d = recordingPlugin("d", log, { dependsOn: ["b", "c"] });
    const c = recordingPlugin("c", log, { dependsOn: ["a"] });
    const b = recordingPlugin("b", log, { dependsOn: ["a"] });
    const a = recordingPlugin("a", log);

    const host = new PluginHost<Ctx>();
    await host.register(app, ctx, d, c, b, a);

    expect(log[0]).toBe("a");
    expect(log[log.length - 1]).toBe("d");
    expect(log.filter((n) => n === "a")).toHaveLength(1);
    expect(log.indexOf("b")).toBeLessThan(log.indexOf("d"));
    expect(log.indexOf("c")).toBeLessThan(log.indexOf("d"));
  });
});

describe("PluginHost — fail closed", () => {
  it("rejects duplicate plugin names", async () => {
    const log: string[] = [];
    const host = new PluginHost<Ctx>();
    await expect(
      host.register(app, ctx, recordingPlugin("dup", log), recordingPlugin("dup", log)),
    ).rejects.toBeInstanceOf(PluginHostError);
    // nothing should have registered.
    expect(log).toEqual([]);
  });

  it("rejects a missing dependency BEFORE registering anything", async () => {
    const log: string[] = [];
    const host = new PluginHost<Ctx>();
    const needsGhost = recordingPlugin("real", log, { dependsOn: ["ghost"] });

    await expect(host.register(app, ctx, needsGhost)).rejects.toBeInstanceOf(PluginHostError);
    // fail closed: the real plugin's register must NOT have run.
    expect(log).toEqual([]);
  });

  it("detects a dependency cycle", async () => {
    const log: string[] = [];
    const host = new PluginHost<Ctx>();
    const p1 = recordingPlugin("p1", log, { dependsOn: ["p2"] });
    const p2 = recordingPlugin("p2", log, { dependsOn: ["p1"] });

    await expect(host.register(app, ctx, p1, p2)).rejects.toBeInstanceOf(PluginHostError);
    expect(log).toEqual([]);
  });

  it("reports the missing dependency name in the error", async () => {
    const host = new PluginHost<Ctx>();
    const p = recordingPlugin("p", [], { dependsOn: ["absent-dep"] });
    await expect(host.register(app, ctx, p)).rejects.toThrow(/absent-dep/);
  });
});

describe("PluginHost — webhook event contribution", () => {
  it("merges declared webhookEvents into a fresh registry (core ∪ plugin)", async () => {
    // a registry seeded with one core event.
    const registry = new WebhookEventRegistry(["tx.pending"]);
    const host = new PluginHost<Ctx>(registry);

    const plugin = recordingPlugin("emitter", [], {
      webhookEvents: ["thing.created", "thing.failed"],
    });
    await host.register(app, ctx, plugin);

    // core event still valid.
    expect(registry.has("tx.pending")).toBe(true);
    // plugin-declared events now valid.
    expect(registry.has("thing.created")).toBe(true);
    expect(registry.has("thing.failed")).toBe(true);
    // an unknown event stays invalid.
    expect(registry.has("not.declared")).toBe(false);
  });

  it("surfaces contributions + loaded plugins via describe()", async () => {
    const registry = new WebhookEventRegistry(["tx.pending"]);
    const host = new PluginHost<Ctx>(registry);

    await host.register(
      app,
      ctx,
      recordingPlugin("alpha", [], { version: "1.2.3", webhookEvents: ["alpha.ping"] }),
      recordingPlugin("beta", [], { dependsOn: ["alpha"] }),
    );

    const diag = host.describe();
    expect(diag.plugins).toEqual([
      { name: "alpha", version: "1.2.3" },
      { name: "beta", version: undefined },
    ]);
    expect(diag.webhookEventContributions).toEqual({ alpha: ["alpha.ping"] });
    // the merged valid set includes both the core seed and the plugin event.
    expect(diag.webhookEvents).toContain("tx.pending");
    expect(diag.webhookEvents).toContain("alpha.ping");
  });

  it("registers events before running register hooks (events valid inside register)", async () => {
    const registry = new WebhookEventRegistry([]);
    const host = new PluginHost<Ctx>(registry);
    let sawOwnEventValid = false;

    const plugin = {
      name: "self-aware",
      webhookEvents: ["self.event"] as const,
      register() {
        // its own declared event must already be registered at register time.
        sawOwnEventValid = registry.has("self.event");
      },
    };

    await host.register(app, ctx, plugin);
    expect(sawOwnEventValid).toBe(true);
  });

  it("a plugin with no register hook still contributes its events", async () => {
    const registry = new WebhookEventRegistry([]);
    const host = new PluginHost<Ctx>(registry);

    // declarative-only plugin: no register() at all.
    const declarativeOnly = {
      name: "declarative-only",
      webhookEvents: ["declared.only"] as const,
    };
    await host.register(app, ctx, declarativeOnly);

    expect(registry.has("declared.only")).toBe(true);
    expect(host.describe().plugins).toEqual([{ name: "declarative-only", version: undefined }]);
  });
});

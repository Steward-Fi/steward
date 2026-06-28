/**
 * example-plugin.test.ts - the end-to-end proof that a plugin works through the
 * PUBLIC sdk surface alone.
 *
 * it registers `examplePlugin` via `registerPlugin` (re-exported by
 * @stwd/plugin-sdk) against a real hono app + an injected, hermetic context, then
 * asserts each contribution point landed:
 *   - the GET /example/ping route responds { ok: true };
 *   - the "example-business-hours" policy rule is registered + consulted (its
 *     evaluator returns a proper ContributedPolicyResult for its own type);
 *   - the "example.pinged" webhook event is in the merged registry;
 *   - the "push::example-push" adapter is registered into the injected registry;
 *   - the migration source is collected (id "example", isolated bookkeeping table).
 *
 * the context is built by hand (not via the live buildPluginContext) so the test
 * is hermetic - it injects a fresh AdapterRegistry + isolated webhook/policy
 * registries, mirroring the api host tests.
 */

import { describe, expect, it } from "bun:test";
import { AdapterRegistry } from "@stwd/adapters";
import { PluginHost, registerPlugin, type StewardApp } from "@stwd/plugin-sdk";
import { PolicyRuleRegistry } from "@stwd/policy-engine";
import { WebhookEventRegistry } from "@stwd/shared";
import { Hono } from "hono";
import { examplePlugin } from "../index";

/**
 * a minimal injected context. the example's `register` ignores ctx, and the host
 * only reads `ctx.adapterRegistry` for adapter wiring, so a fresh registry is the
 * only field the test must supply. cast through `unknown` because the test does
 * not stand up the full StewardAppContext (db/vault/...): the host's adapter path
 * is structural (`ctxAdapterRegistry`), it does not require the full shape.
 */
function buildTestCtx(registry: AdapterRegistry): unknown {
  return { adapterRegistry: registry };
}

describe("@stwd/plugin-example through the public sdk surface", () => {
  it("registers all contribution points and serves its route", async () => {
    const app = new Hono() as unknown as StewardApp;
    // env selects the example provider for the push category so resolution is
    // deterministic.
    const registry = new AdapterRegistry({ env: { STEWARD_PUSH_ADAPTER: "example-push" } });
    const eventRegistry = new WebhookEventRegistry(new Set<string>());
    const policyRegistry = new PolicyRuleRegistry();
    const ctx = buildTestCtx(registry);

    // register through the SDK's registerPlugin (not @stwd/api directly).
    const host = await registerPlugin(
      app as Parameters<typeof registerPlugin>[0],
      examplePlugin,
      ctx,
      eventRegistry,
      policyRegistry,
    );

    // ── 1. ROUTE ──────────────────────────────────────────────────────────────
    const res = await (app as unknown as Hono).request("/example/ping");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });

    // ── 2. POLICY RULE ─────────────────────────────────────────────────────────
    // the host registered the contributed evaluator for the plugin's own type.
    expect(policyRegistry.has("example-business-hours")).toBe(true);
    const evaluator = policyRegistry.get("example-business-hours");
    expect(evaluator).toBeDefined();
    // consult it as the engine would: a rule inside the window passes, outside
    // denies with a reason. the example reads `nowUtcHour` off the eval context.
    const passing = await evaluator?.evaluate(
      {
        id: "r1",
        type: "example-business-hours",
        enabled: true,
        config: { openHourUtc: 9, closeHourUtc: 17 },
      },
      { nowUtcHour: 12 } as never,
    );
    expect(passing?.passed).toBe(true);
    expect(passing?.policyId).toBe("r1");
    expect(passing?.type).toBe("example-business-hours");
    const denying = await evaluator?.evaluate(
      {
        id: "r2",
        type: "example-business-hours",
        enabled: true,
        config: { openHourUtc: 9, closeHourUtc: 17 },
      },
      { nowUtcHour: 3 } as never,
    );
    expect(denying?.passed).toBe(false);
    expect(typeof denying?.reason).toBe("string");

    // ── 3. WEBHOOK EVENT ────────────────────────────────────────────────────────
    expect(eventRegistry.has("example.pinged")).toBe(true);
    expect(host.describe().webhookEventContributions.example).toEqual(["example.pinged"]);

    // ── 4. ADAPTER ──────────────────────────────────────────────────────────────
    // resolves through the registry's own env-driven selection to the plugin's
    // provider, proving the contribution reached the real resolution path.
    expect(registry.push().provider).toBe("example-push");
    expect(host.describe().adapterContributions.example).toEqual(["push::example-push"]);

    // ── 5. MIGRATION SOURCE ─────────────────────────────────────────────────────
    // collected (not applied - applying needs a live db). diagnostics show the id
    // + the isolated per-plugin bookkeeping table.
    const migrations = host.describe().migrationSources.example;
    expect(migrations).toBeDefined();
    expect(migrations.id).toBe("example");
    expect(migrations.migrationsTable).toBe("__drizzle_migrations_plugin_example");
  });

  it("collects the migration source via a standalone host (migrate-only path)", () => {
    const host = new PluginHost<unknown>();
    host.collectMigrations(examplePlugin);
    const sources = host.pluginMigrationSources;
    expect(sources).toHaveLength(1);
    expect(sources[0]?.pluginName).toBe("example");
    expect(sources[0]?.source.id).toBe("example");
    // the folder path is absolute (resolved against the package), not relative.
    expect(sources[0]?.source.migrationsFolder.endsWith("/drizzle")).toBe(true);
  });
});

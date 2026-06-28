/**
 * @stwd/plugin-example - the smallest honest Steward plugin.
 *
 * this is the runnable hello-world that proves "anyone can write a plugin." it
 * exercises ALL of the plugin contract's contribution points in the minimal way,
 * importing ONLY from `@stwd/plugin-sdk` (the example is the forcing function for
 * the sdk's completeness: if the example needs a symbol, the sdk re-exports it).
 *
 * contribution points demonstrated:
 *   1. route       - `register(app, ctx)` mounts GET /example/ping -> { ok: true }.
 *   2. policy rule - a custom "example-business-hours" rule the engine evaluates.
 *   3. webhook     - declares the "example.pinged" event type.
 *   4. migration   - points at this package's own drizzle folder (one CREATE TABLE).
 *   5. adapter     - a trivial "push" provider ("example-push").
 *
 * to enable it, an operator registers it at the composition root:
 *
 *   import { buildPluginContext, registerPlugin } from "@stwd/plugin-sdk";
 *   import { examplePlugin } from "@stwd/plugin-example";
 *
 *   await registerPlugin(app, examplePlugin, buildPluginContext());
 *
 * the core never imports this package; everything the plugin needs is INJECTED via
 * the `ctx` the core hands `register`. that keeps the dependency one-directional.
 */

import { fileURLToPath } from "node:url";
import type {
  ContributedPolicyResult,
  ContributedPolicyRule,
  StewardApiPlugin,
  StewardApp,
  StewardAppContext,
} from "@stwd/plugin-sdk";

/**
 * the example plugin's migrations folder, resolved to an ABSOLUTE path at runtime.
 * the host applies it via the per-plugin migration runner; a relative path would
 * break depending on the process cwd, so it is resolved against this module.
 */
const MIGRATIONS_FOLDER = fileURLToPath(new URL("../drizzle", import.meta.url));

/**
 * config shape for the "example-business-hours" rule. trivially demonstrates a
 * plugin OWNING a rule type the core's closed policy union does not enumerate.
 */
interface ExampleBusinessHoursConfig {
  /** UTC hour (0-23) the window opens, inclusive. defaults to 0. */
  readonly openHourUtc?: number;
  /** UTC hour (0-23) the window closes, exclusive. defaults to 24. */
  readonly closeHourUtc?: number;
}

/**
 * read the request's UTC hour from the evaluator context if present, else fall
 * back to now. the example keeps this loose (the eval context is intentionally
 * `unknown` at the contract boundary) - a real plugin binds the engine's
 * `EvaluatorContext` and reads typed fields.
 */
function requestHourUtc(ctx: unknown): number {
  if (ctx && typeof ctx === "object" && "nowUtcHour" in ctx) {
    const h = (ctx as { nowUtcHour: unknown }).nowUtcHour;
    if (typeof h === "number" && Number.isInteger(h) && h >= 0 && h <= 23) return h;
  }
  return new Date().getUTCHours();
}

/**
 * the minimal "hello-world" plugin. typed `StewardApiPlugin` so it is bound to the
 * steward app, the injected context, and the policy engine's evaluator context.
 */
export const examplePlugin: StewardApiPlugin = {
  name: "example",
  version: "0.1.0",

  // 1. ROUTE - mount one trivial route using the injected ctx for nothing more
  //    than to prove the seam works. real plugins gate routes with ctx auth
  //    middleware (ctx.requireAgentJwt / ctx.operatorAuth / ctx.tenantAuth).
  register(app: StewardApp, _ctx: StewardAppContext): void {
    app.get("/example/ping", (c) => c.json({ ok: true }));
  },

  // 3. WEBHOOK - declare the event type this plugin emits. the host merges it
  //    into the runtime registry (core union ∪ plugin-declared) so the webhook
  //    config/dispatch path accepts it without the core's closed union knowing it.
  webhookEvents: ["example.pinged"],

  // 2. POLICY RULE - contribute a custom rule type. the host registers it into
  //    the policy engine's evaluator registry (fail-closed on a collision with a
  //    core rule type or another plugin's). the engine evaluates a rule of this
  //    `type` via `evaluate` and uses the returned ContributedPolicyResult.
  policyRules: [
    {
      type: "example-business-hours",
      description: "passes only inside a configured UTC hour window.",
      evaluate(rule: ContributedPolicyRule, evalCtx: unknown): ContributedPolicyResult {
        const config = rule.config as ExampleBusinessHoursConfig;
        const open = config.openHourUtc ?? 0;
        const close = config.closeHourUtc ?? 24;
        const hour = requestHourUtc(evalCtx);
        const passed = hour >= open && hour < close;
        return {
          policyId: rule.id,
          type: rule.type,
          passed,
          ...(passed ? {} : { reason: `outside business hours (${open}:00-${close}:00 UTC)` }),
        };
      },
    },
  ],

  // 4. MIGRATION - point at this package's own drizzle folder. the host applies
  //    it AFTER the core migrator, into a per-plugin namespaced bookkeeping table
  //    (drizzle.__drizzle_migrations_plugin_example), isolated from the core
  //    journal. one CREATE TABLE example_log.
  migrations: {
    id: "example",
    migrationsFolder: MIGRATIONS_FOLDER,
  },

  // 5. ADAPTER - contribute a trivial "push" provider. the adapter is typed
  //    `unknown` at the contract boundary (to avoid a contract -> adapters
  //    dependency cycle), so the example builds a structurally-valid PushAdapter
  //    WITHOUT importing @stwd/adapters. the host validates the category +
  //    provider + instance and registers it into the core adapter registry.
  adapters: [
    {
      category: "push",
      provider: "example-push",
      adapter: createExamplePushAdapter(),
    },
  ],
};

/**
 * a minimal, structurally-valid `push` adapter. it implements the push adapter's
 * shape (`category`/`provider`/`enabled` + a `send`) without importing the
 * concrete `PushAdapter` type, so the example stays sdk-only. it records nothing
 * real - it just acknowledges the send so the registry has a working provider.
 */
function createExamplePushAdapter() {
  return {
    category: "push" as const,
    provider: "example-push",
    enabled: true,
    async send(request: { readonly target: { readonly id: string } }): Promise<{
      ok: boolean;
      provider: string;
      subscriptionId: string;
      deliveredAt: number;
    }> {
      return {
        ok: true,
        provider: "example-push",
        subscriptionId: request.target.id,
        deliveredAt: Date.now(),
      };
    },
  };
}

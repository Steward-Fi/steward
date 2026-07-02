/**
 * compose.ts — the COMPOSITION ROOT that assembles the deployable Steward
 * server: the lean core (`createApp()`) plus the opt-in plugins this repo's own
 * deployment wants (currently: trading).
 *
 * WHY A SEPARATE COMPOSITION ROOT
 * -------------------------------
 * `app.ts`'s `createApp()` is the LEAN CORE: trading-free, with no dependency on
 * the trading stack. a third party importing `@stwd/api` and calling `createApp()`
 * gets exactly that. THIS repo's deployed server (index.ts / worker.ts /
 * embedded.ts) can run the SAME image LEAN (core only) or FULL (core + trading)
 * by environment: `composeApp()` consults `resolveEnabledPlugins()`
 * (`plugin-config.ts`, reading `STEWARD_PLUGINS` / legacy `STEWARD_ENABLE_TRADING`)
 * and only registers the trading plugin when it is enabled. that keeps the library
 * core lean, the deploy configurable, and — in FULL mode — behavior-identical to
 * the historical hardcoded composition.
 *
 * ORDERING (load-bearing — money rail)
 * ------------------------------------
 * the global idempotency middleware must run AFTER all per-route auth middleware
 * (it reads the auth-populated request context to decide replay-safety) and BEFORE
 * any route it should wrap (a route handler that returns a response ends the chain,
 * so a route registered before the idempotency `app.use("*")` would never be
 * idempotency-wrapped). so the required registration order is:
 *
 *   [global mw] -> [all auth mw: core + plugin] -> [idempotency] -> [all routes: core + plugin]
 *
 * a plugin contributes BOTH auth middleware (before idempotency) and routes (after
 * idempotency). a single `register(app, ctx)` can't straddle the idempotency
 * boundary, so we hand the plugin a DEFERRED-ROUTE app: `app.use(...)` registers
 * middleware immediately (lands before idempotency), while `app.route(...)` /
 * `app.get(...)` etc. are BUFFERED and flushed AFTER idempotency. this reproduces
 * the exact pre-refactor ordering (trade auth -> idempotency -> trade routes).
 */

import type { Hono } from "hono";
import { createApp, mountCoreIdempotencyAndRoutes } from "./app";
import { buildPluginContext, PluginHost, type StewardApp } from "./plugin";
import { resolveEnabledPlugins } from "./plugin-config";
import type { AppVariables } from "./services/context";
import { webhookEventRegistry } from "./services/webhook-events";

type RouteArgs = unknown[];

/**
 * A thin proxy over a hono app that lets a plugin register MIDDLEWARE eagerly
 * (`use`) while DEFERRING route registration (`route`, `get`, `post`, ...) until
 * the core has installed the global idempotency middleware. flushing the buffered
 * route calls afterwards yields the canonical order: plugin auth mw -> idempotency
 * -> plugin routes. only the surface a plugin's `register` uses is proxied.
 */
function makeDeferredRouteApp(app: StewardApp): {
  deferred: StewardApp;
  flush: () => void;
} {
  const buffered: Array<{
    method: "route" | "get" | "post" | "put" | "patch" | "delete";
    args: RouteArgs;
  }> = [];

  const deferred = new Proxy(app, {
    get(target, prop, receiver) {
      // Middleware is order-sensitive and must land BEFORE idempotency — register
      // it eagerly (pass through to the real app).
      if (prop === "use") {
        return (...args: RouteArgs) => (target.use as (...a: RouteArgs) => unknown)(...args);
      }
      // Route registration must land AFTER idempotency — buffer it.
      if (
        prop === "route" ||
        prop === "get" ||
        prop === "post" ||
        prop === "put" ||
        prop === "patch" ||
        prop === "delete"
      ) {
        return (...args: RouteArgs) => {
          buffered.push({ method: prop as (typeof buffered)[number]["method"], args });
          return deferred; // preserve chaining
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as StewardApp;

  const flush = () => {
    for (const { method, args } of buffered) {
      (app[method] as (...a: RouteArgs) => unknown)(...args);
    }
    buffered.length = 0;
  };

  return { deferred, flush };
}

/**
 * Build the fully-composed deployable Steward app: lean core + this repo's opt-in
 * plugins (trading), with the canonical middleware/route ordering preserved.
 *
 * the trading plugin is imported with a static, bundler-discoverable specifier
 * (so the deployed Worker bundle includes it); only this deploy-only composition
 * root references `@stwd/plugin-trading`. the lean core graph in `app.ts` / the
 * library entry `lib.ts` never reference it, so a consumer importing `@stwd/api`
 * stays trading-free.
 */
export async function composeApp(): Promise<Hono<{ Variables: AppVariables }>> {
  // which opt-in plugins this deploy enables (env-driven). LEAN = empty set
  // (core only); FULL = { "trading" }. resolveEnabledPlugins fails closed on an
  // unknown plugin name, so a typo'd STEWARD_PLUGINS aborts boot here rather than
  // silently shipping a wrong feature profile. composeApp reads process.env
  // directly (prod signature unchanged); the resolver itself is env-injectable
  // for tests, which set/restore process.env.STEWARD_PLUGINS around each case.
  const enabled = resolveEnabledPlugins();

  // 1) lean core: global mw + all core auth mw (NO idempotency, NO routes yet).
  const app = createApp();

  if (enabled.size === 0) {
    // LEAN MODE: no opt-in plugins to register. the deferred-route machinery only
    // exists to slot a plugin's auth mw before idempotency and its routes after;
    // with no plugins there is nothing to defer, so mount core idempotency +
    // core routes directly. ordering is identical to FULL minus the (absent)
    // plugin contributions: [global mw + core auth mw (createApp)] -> idempotency
    // -> core routes. no opt-in plugin module is imported in this path, so none
    // is ever evaluated in lean mode.
    mountCoreIdempotencyAndRoutes(app);
    return app;
  }

  // FULL MODE: register this deploy's enabled opt-in plugins. behavior-identical
  // to the historical hardcoded path for trading — same registration, same
  // ordering, same migrations — plus any other enabled plugin (capabilities).
  //
  // 2) plugin auth-middleware phase + buffered routes. each plugin's auth mw lands
  //    now, before idempotency; its routes are buffered for after.
  //
  // each opt-in plugin is imported with a STATIC, bundler-discoverable specifier so
  // Wrangler/esbuild include it in the Worker bundle (a non-analyzable dynamic
  // specifier would be omitted, and the Worker would fail at runtime with a
  // missing module on the first request). gating is on the EXECUTION (the
  // `enabled.has(...)` guards below), NOT on the import specifier — the literal
  // `import("@stwd/plugin-...")` strings are still statically analyzable so the
  // bundler always includes the modules; they are simply not EVALUATED when the
  // plugin is disabled. this is the DEPLOY-ONLY composition root, so it is allowed
  // to reference the plugins; the LIBRARY entry (lib.ts) does NOT re-export
  // composeApp, so a consumer importing `@stwd/api` never pulls a plugin into its
  // graph and the lean core stays plugin-free.
  const ctx = buildPluginContext();
  type ComposedPlugin = Parameters<PluginHost<typeof ctx>["register"]>[2];
  const plugins: ComposedPlugin[] = [];

  if (enabled.has("trading")) {
    const { tradingPlugin } = (await import("@stwd/plugin-trading")) as {
      tradingPlugin: ComposedPlugin;
    };
    plugins.push(tradingPlugin);
  }

  if (enabled.has("capabilities")) {
    // PARITY: gated by the SAME resolver as its migrations (see
    // runComposedPluginMigrations). the capabilities plugin also contributes the
    // `capability-intent` policy rule declaratively (plugin.policyRules); the host
    // registers it into the policy-engine evaluator registry BEFORE any route
    // runs, so the agent invoke path can evaluate capability-intent rules.
    const { capabilitiesPlugin } = (await import("@stwd/plugin-capabilities")) as {
      capabilitiesPlugin: ComposedPlugin;
    };
    plugins.push(capabilitiesPlugin);
  }

  const { deferred, flush } = makeDeferredRouteApp(app);

  // The plugin host composes the plugin(s): it orders by `dependsOn` (failing
  // closed on a missing/cyclic dep), merges each plugin's declared
  // `webhookEvents` into the SHARED process-wide registry the webhook config/
  // dispatch path consults (so a plugin's event type is accepted), registers each
  // plugin's declared `policyRules` into the policy-engine evaluator registry,
  // then runs each plugin's `register`. It registers onto the DEFERRED-ROUTE proxy
  // so the load-bearing ordering is preserved: plugin auth mw lands now (before
  // idempotency), plugin routes are buffered and flushed after.
  const host = new PluginHost<typeof ctx>(webhookEventRegistry);
  await host.register(deferred, ctx, ...plugins);

  // 3) core idempotency + core routes.
  mountCoreIdempotencyAndRoutes(app);

  // 4) flush the plugins' buffered routes (now AFTER idempotency).
  flush();

  return app;
}

/**
 * Apply this deploy's opt-in plugins' OWN migrations (Phase 2c), into per-plugin
 * NAMESPACED bookkeeping tables (`drizzle.__drizzle_migrations_plugin_<id>`),
 * totally isolated from the core's `drizzle.__drizzle_migrations` journal.
 *
 * ORDERING (load-bearing): the boot/migrate path MUST call this AFTER the core
 * migrator (`runMigrations()` from `@stwd/db`) has completed, so a plugin
 * migration may reference core tables via FK. This is the explicit migrate step
 * only — it is NEVER run implicitly per request. Plugin migrations run in
 * `dependsOn` order.
 *
 * This discovers the SAME opt-in plugins {@link composeApp} composes via the SAME
 * {@link resolveEnabledPlugins} resolver (PARITY: app-compose and
 * migration-compose always agree on the enabled set, so a plugin's routes and its
 * migrations are never orphaned — both-on or both-off). It does NOT mount
 * routes/middleware — it only collects each enabled plugin's declared migration
 * source and applies it. Fails closed (rejects) on the first plugin migration
 * error so the boot path can refuse to half-boot.
 *
 * @returns per-plugin results (id + the namespaced table its ledger was written
 *   to). Empty if no opt-in plugin is enabled / declares a migration source.
 */
export async function runComposedPluginMigrations(): Promise<
  Array<{ pluginName: string; id: string; migrationsTable: string }>
> {
  // PARITY with composeApp: resolve the SAME enabled set from the SAME resolver,
  // and collect migrations for EXACTLY the plugins composeApp registers. a plugin
  // that is disabled contributes NO migrations (its routes are also not mounted)
  // — the two paths can never drift (both-on or both-off, per plugin).
  const enabled = resolveEnabledPlugins();
  if (enabled.size === 0) {
    return [];
  }

  const ctx = buildPluginContext();
  type ComposedPlugin = Parameters<PluginHost<typeof ctx>["register"]>[2];
  const host = new PluginHost<typeof ctx>();

  if (enabled.has("trading")) {
    const { tradingPlugin } = (await import("@stwd/plugin-trading")) as {
      tradingPlugin: ComposedPlugin;
    };
    host.collectMigrations(tradingPlugin);
  }

  if (enabled.has("capabilities")) {
    const { capabilitiesPlugin } = (await import("@stwd/plugin-capabilities")) as {
      capabilitiesPlugin: ComposedPlugin;
    };
    host.collectMigrations(capabilitiesPlugin);
  }

  return host.runMigrations();
}

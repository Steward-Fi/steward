/**
 * compose.ts — the COMPOSITION ROOT that assembles the deployable Steward
 * server: the lean core (`createApp()`) plus the opt-in plugins this repo's own
 * deployment wants (currently: trading).
 *
 * WHY A SEPARATE COMPOSITION ROOT
 * -------------------------------
 * `app.ts`'s `createApp()` is the LEAN CORE: trading-free, with no dependency on
 * the trading stack. a third party importing `@stwd/api` and calling `createApp()`
 * gets exactly that. but THIS repo's deployed server (index.ts / worker.ts /
 * embedded.ts) DOES want trading, so it composes the core with the trading plugin
 * HERE, at the composition root. that keeps the library core lean while the deploy
 * stays full-featured.
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
import { buildPluginContext, registerPlugin, type StewardApp } from "./plugin";
import type { AppVariables } from "./services/context";

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
  const buffered: Array<{ method: "route" | "get" | "post" | "put" | "patch" | "delete"; args: RouteArgs }> = [];

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
 * the trading plugin is loaded LAZILY (dynamic import) so the lean core graph in
 * `app.ts` never statically references `@stwd/plugin-trading`; only this
 * composition root pulls it in.
 */
export async function composeApp(): Promise<Hono<{ Variables: AppVariables }>> {
  // 1) lean core: global mw + all core auth mw (NO idempotency, NO routes yet).
  const app = createApp();

  // 2) plugin auth-middleware phase + buffered routes. trade auth mw lands now,
  //    before idempotency; trade routes are buffered for after.
  //
  // the trading plugin is imported DYNAMICALLY + via a non-statically-analyzable
  // specifier so the lean core's type/build graph never references
  // `@stwd/plugin-trading` (the core must not depend on a plugin). the ctx the
  // core builds is structurally the shape the plugin's `register` expects.
  const ctx = buildPluginContext();
  const pluginSpecifier = "@stwd/plugin-trading";
  const { tradingPlugin } = (await import(pluginSpecifier)) as {
    tradingPlugin: Parameters<typeof registerPlugin<typeof ctx>>[1];
  };
  const { deferred, flush } = makeDeferredRouteApp(app);
  await registerPlugin(deferred, tradingPlugin, ctx);

  // 3) core idempotency + core routes.
  mountCoreIdempotencyAndRoutes(app);

  // 4) flush the plugin's buffered routes (now AFTER idempotency).
  flush();

  return app;
}

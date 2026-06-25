/**
 * plugin.ts — the lean-core + opt-in-plugin contract.
 *
 * steward is a lean open core (auth, wallet/vault, policy, proxy, webhooks) plus
 * opt-in plugins that a host registers onto the app at the composition root. the
 * core never imports a plugin; a plugin contributes routes/middleware through the
 * register seam, so the majority of installs that only want the core never pull a
 * plugin's transitive dependencies (smaller install, smaller supply-chain and
 * audit surface). trading is the first such plugin.
 *
 * `StewardPlugin` is intentionally generic and framework-agnostic here: it carries
 * no hono (or any http-framework) types so `@stwd/shared` keeps zero runtime deps.
 * the concrete app + context types are supplied by `@stwd/api` (see its
 * `StewardApiPlugin` / `StewardAppContext`), which is where the hono `app` and the
 * injected service context are bound. a third-party plugin author depends only on
 * `@stwd/api`'s exported plugin types, not on `@stwd/shared`'s generic shape, but
 * the generic lives here so the contract is owned by the core's type vocabulary.
 *
 * App  = the host application a plugin mounts onto (a hono app in @stwd/api).
 * Ctx  = the injected context the core hands the plugin: the shared service
 *        singletons (db, vault, policy engine, audit writer, ...) and the auth
 *        middleware a plugin needs to gate its own routes. injecting these is what
 *        lets a plugin live in its own package WITHOUT importing the core (no
 *        circular dependency: core does not import plugin, plugin does not import
 *        core).
 */
export interface StewardPlugin<App = unknown, Ctx = unknown> {
  /** stable identifier for the plugin, e.g. "trading". used in logs/diagnostics. */
  readonly name: string;
  /**
   * mount the plugin's routes + middleware onto `app`, using the injected `ctx`
   * for shared services and auth gates. may be async (e.g. to lazily resolve a
   * provider). called once, at the composition root, after the core is built.
   */
  register(app: App, ctx: Ctx): void | Promise<void>;
}

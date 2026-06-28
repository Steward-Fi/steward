/**
 * @stwd/plugin-sdk - the one import for writing a Steward plugin.
 *
 * a plugin contributes any of:
 *   - routes (via the `register(app, ctx)` hook)
 *   - policy rules (custom rule types the policy engine evaluates)
 *   - webhook events (event-type names the plugin emits)
 *   - db migrations (the plugin's own drizzle migrations folder)
 *   - provider adapters (a real swap/earn/onramp/push/... integration)
 *
 * each contribution is fail-closed: a plugin can never shadow a core policy rule
 * type, never write into the core migration journal, never silently overwrite a
 * registered adapter, and never register against a half-built dependency.
 *
 * this package is a thin FACADE. it re-exports the framework-agnostic contract
 * from `@stwd/shared` and the concrete, app-bound types + host runtime from
 * `@stwd/api`. an author depends on this ONE package and types their plugin as
 * `StewardApiPlugin`; an operator uses `registerPlugin` (or `PluginHost`) at the
 * composition root to mount it.
 *
 * see `@stwd/plugin-example` for a runnable hello-world that exercises all four
 * declarative contribution points plus a route through this surface alone.
 */

export type {
  LoadedPluginInfo,
  PluginHostDiagnostics,
  StewardApiPlugin,
  StewardApp,
  StewardAppContext,
} from "@stwd/api/plugin";

// ── the concrete, app-bound plugin type + host runtime (owned by @stwd/api) ───
//
// `StewardApiPlugin` is `StewardPlugin` bound to the steward hono app, the
// injected `StewardAppContext`, and the policy engine's evaluator context - this
// is the type an author annotates their plugin object with.
//
// `StewardApp` / `StewardAppContext` are the `app` / `ctx` a plugin's `register`
// hook receives. `buildPluginContext` builds that ctx at the composition root,
// and `registerPlugin` / `PluginHost` mount one or more plugins fail-closed.
export {
  buildPluginContext,
  PluginHost,
  PluginHostError,
  registerPlugin,
} from "@stwd/api/plugin";
// ── the generic, framework-agnostic contract (owned by @stwd/shared) ──────────
//
// these describe a contribution structurally so the contract carries no http
// framework or money-rail types. an author rarely binds these directly (the
// concrete `StewardApiPlugin` below already binds them to the steward app), but
// they are exported so an author can name a single contribution's shape.
export type {
  AdapterContribution,
  ContributedPolicyResult,
  ContributedPolicyRule,
  PluginMigrationSource,
  PolicyRuleContribution,
  StewardPlugin,
} from "@stwd/shared";

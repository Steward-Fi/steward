/**
 * plugin.ts — the lean-core + opt-in-plugin seam for the Steward app.
 *
 * WHY THIS EXISTS
 * ---------------
 * steward serves two audiences from one codebase: teams that want only the auth +
 * embedded-wallet + policy core, and teams that ALSO want agent trading (venue
 * execution + trade sessions). historically these were coupled: `@stwd/api`
 * hard-depended on the trading stack (`@stwd/trade-sessions`, `@stwd/venue-*`) and
 * the trade routes imported the venue adapters directly, so an auth-only install
 * still compiled + shipped the entire trading stack (the venue SDKs, ethers, clob
 * clients) — an unnecessary install-size, supply-chain, and audit-surface cost for
 * the majority of installs that never trade.
 *
 * the architecture here is a LEAN OPEN CORE (auth + vault + policy + proxy +
 * webhooks) plus OPT-IN PLUGINS that a host registers. trading is the first such
 * plugin (`@stwd/plugin-trading`). this mirrors the plugin model of mature
 * frameworks (fastify/vite/hono-style `app.register(plugin)`): take only what you
 * need, and anyone can write + register their own plugin.
 *
 * THE SEAM
 * --------
 * a plugin contributes hono routes + middleware via `register(app, ctx)`:
 *   - `app` is the steward hono app.
 *   - `ctx` is the {@link StewardAppContext} the core BUILDS and hands the plugin:
 *     the shared service singletons (db, vault, policy engine, price oracle, audit
 *     writer, token-status reader, redis client) and the auth middleware a plugin
 *     installs on its own routes (requireAgentJwt, operatorAuth, tenantAuth).
 *
 * injecting `ctx` is what lets a plugin live in its OWN package without importing
 * `@stwd/api`: the core does not import any plugin, and a plugin does not import the
 * core, so the dependency stays one-directional (no cycle). the core never depends
 * on a plugin's transitive deps.
 *
 * a third party registers a plugin at the composition root (the deployable server
 * entrypoint), NOT inside the core app:
 *
 *   import { createApp, buildPluginContext, registerPlugin } from "@stwd/api";
 *   import { tradingPlugin } from "@stwd/plugin-trading";
 *
 *   const app = createApp();                 // lean core, no trading
 *   await registerPlugin(app, tradingPlugin, buildPluginContext());
 *
 * that way `@stwd/api` itself stays trading-free for anyone importing it, while a
 * deploy that wants trading opts in by registering the plugin.
 */

import type { Hono } from "hono";
import type { StewardPlugin } from "@stwd/shared";
import { requireAgentJwt } from "./middleware/agent-jwt";
import { operatorAuth } from "./middleware/operator-auth";
import { getRedisClient } from "./middleware/redis";
import { getAgentTokenStatus } from "./services/agent-token-status";
import { writeAuditEvent } from "./services/audit";
import {
  type AppVariables,
  db,
  ensureAgentForTenant,
  getPolicySet,
  isValidAnyAddress,
  policyEngine,
  priceOracle,
  safeJsonParse,
  tenantAuth,
  vault,
} from "./services/context";

/** the steward app a plugin mounts onto: a hono app with the shared variables. */
export type StewardApp = Hono<{ Variables: AppVariables }>;

/**
 * The injected context the core hands a plugin's `register(app, ctx)`. Every
 * member is a CORE singleton/helper a plugin would otherwise have had to import
 * from `@stwd/api` (which would be a circular dependency for a plugin in its own
 * package). a plugin codes against this shape.
 *
 * NOTE: this interface is intentionally STRUCTURAL. a plugin package (e.g.
 * `@stwd/plugin-trading`) declares its own `StewardAppContext` with the same shape
 * and never imports this one — that is how the plugin avoids importing the core.
 * at the composition root, where both packages meet, typescript checks that the
 * context the core BUILDS ({@link buildPluginContext}) is assignable to the
 * plugin's expected shape.
 */
export interface StewardAppContext {
  db: typeof db;
  vault: typeof vault;
  policyEngine: typeof policyEngine;
  priceOracle: typeof priceOracle;
  ensureAgentForTenant: typeof ensureAgentForTenant;
  getPolicySet: typeof getPolicySet;
  safeJsonParse: typeof safeJsonParse;
  isValidAnyAddress: typeof isValidAnyAddress;
  writeAuditEvent: typeof writeAuditEvent;
  getAgentTokenStatus: typeof getAgentTokenStatus;
  getRedisClient: typeof getRedisClient;
  requireAgentJwt: typeof requireAgentJwt;
  operatorAuth: typeof operatorAuth;
  tenantAuth: typeof tenantAuth;
}

/** a steward plugin concretely bound to the hono app + the injected context. */
export type StewardApiPlugin = StewardPlugin<StewardApp, StewardAppContext>;

/**
 * Build the context the core injects into a plugin: bind every shared core
 * singleton + auth middleware into one object. called once at the composition
 * root and passed to {@link registerPlugin}.
 */
export function buildPluginContext(): StewardAppContext {
  return {
    db,
    vault,
    policyEngine,
    priceOracle,
    ensureAgentForTenant,
    getPolicySet,
    safeJsonParse,
    isValidAnyAddress,
    writeAuditEvent,
    getAgentTokenStatus,
    getRedisClient,
    requireAgentJwt,
    operatorAuth,
    tenantAuth,
  };
}

/**
 * Register a plugin onto the steward app, injecting the core context. thin
 * `app.register(plugin)`-style helper (the ctx is injected rather than discovered)
 * — calling it is how a host OPTS IN to a plugin at the composition root. may be
 * async because a plugin's `register` may be async.
 */
export async function registerPlugin<Ctx>(
  app: StewardApp,
  plugin: StewardPlugin<StewardApp, Ctx>,
  ctx: Ctx,
): Promise<void> {
  await plugin.register(app, ctx);
}

/**
 * @stwd/plugin-trading — the opt-in trading plugin for Steward.
 *
 * the steward core (`@stwd/api`) is lean: auth, wallet/vault, policy, proxy,
 * webhooks. trading (venue execution + trade sessions + operator fund-recovery)
 * is NOT in the core. it lives here, behind the `StewardPlugin` register seam,
 * so installs that only want the core never pull the venue SDKs (ethers, clob
 * clients, ...) — smaller install, smaller supply-chain + audit surface for the
 * majority of installs that never trade.
 *
 * a host enables trading by registering this plugin at its composition root:
 *
 *   import { registerPlugin } from "@stwd/api";
 *   import { tradingPlugin } from "@stwd/plugin-trading";
 *   await registerPlugin(app, tradingPlugin, ctx);
 *
 * the core does NOT import this package, and this package does NOT import the
 * core: the shared service singletons + auth middleware the trade routes need are
 * INJECTED via the `StewardAppContext` the core hands `register(app, ctx)`. that
 * keeps the dependency one-directional (no cycle).
 */

import type { AppVariables, StewardPlugin } from "@stwd/shared";
import type { Hono } from "hono";
import type { StewardAppContext } from "./context";
import { createOperatorRecoveryRoutes } from "./routes/operator-recovery";
import { createTradeRoutes } from "./routes/trade";

export type { StewardAppContext } from "./context";
export { createOperatorRecoveryRoutes } from "./routes/operator-recovery";
export { createTradeRoutes } from "./routes/trade";

/** the steward app the plugin mounts onto: a hono app with the shared variables. */
export type StewardApp = Hono<{ Variables: AppVariables }>;

/** a steward plugin concretely bound to the hono app + the injected context. */
export type StewardApiPlugin = StewardPlugin<StewardApp, StewardAppContext>;

/**
 * Operator fund-recovery path predicate. These trade paths use the OPERATOR gate
 * (platform key OR tenant-admin) rather than the agent-JWT gate. MOVED verbatim
 * from `@stwd/api`'s app.ts so the trade-routing knowledge lives with the trade
 * plugin. Exported so the plugin's own middleware (and tests) can branch on it.
 */
export const isOperatorRecoveryPath = (path: string): boolean =>
  path.endsWith("/close-all") ||
  path.endsWith("/withdraw") ||
  path.endsWith("/deposit") ||
  path.endsWith("/transfer") ||
  path.endsWith("/leverage") ||
  path.endsWith("/add-margin") ||
  path.endsWith("/approve-builder") ||
  path.endsWith("/usd-send");

/**
 * The trading plugin. `register(app, ctx)`:
 *   1. installs the trade-specific auth middleware (MOVED verbatim from app.ts):
 *        - the agent-JWT gate on the order endpoints,
 *        - the operator gate on fund-recovery paths,
 *        - the tenant gate on session management,
 *      for BOTH the unversioned (/trade) and versioned (/v1/trade) prefixes.
 *   2. mounts the trade routes + operator-recovery routes at /trade and /v1/trade.
 *
 * the order of mounts matches the pre-refactor app.ts exactly (trade routes first,
 * then operator-recovery routes, on each prefix), so routing precedence and thus
 * endpoint behavior is identical.
 */
export const tradingPlugin: StewardApiPlugin = {
  name: "trading",
  register(app, ctx) {
    const { requireAgentJwt, operatorAuth, tenantAuth } = ctx;

    // ── trade-specific auth middleware (verbatim from app.ts ~lines 172-182) ──
    app.use("/trade/hyperliquid/order", (c, next) => requireAgentJwt(c, next));
    app.use("/v1/trade/hyperliquid/order", (c, next) => requireAgentJwt(c, next));
    app.use("/trade", (c, next) => tenantAuth(c, next));
    app.use("/trade/*", (c, next) => {
      if (c.req.path.endsWith("/trade/hyperliquid/order")) return next();
      if (isOperatorRecoveryPath(c.req.path)) return operatorAuth(c, next);
      return tenantAuth(c, next);
    });
    app.use("/v1/trade", (c, next) => tenantAuth(c, next));
    app.use("/v1/trade/*", (c, next) => {
      if (c.req.path.endsWith("/v1/trade/hyperliquid/order")) return next();
      if (isOperatorRecoveryPath(c.req.path)) return operatorAuth(c, next);
      return tenantAuth(c, next);
    });

    // ── route mounts (verbatim order from app.ts) ─────────────────────────────
    const tradeRoutes = createTradeRoutes(ctx);
    const operatorRecoveryRoutes = createOperatorRecoveryRoutes(ctx);
    app.route("/trade", tradeRoutes);
    app.route("/v1/trade", tradeRoutes);
    app.route("/trade", operatorRecoveryRoutes);
    app.route("/v1/trade", operatorRecoveryRoutes);
  },
};

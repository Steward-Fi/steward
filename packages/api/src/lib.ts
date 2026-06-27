/**
 * lib.ts — the LIBRARY entry for `@stwd/api` (the `.` export).
 *
 * importing `@stwd/api` gives you the LEAN CORE building blocks + the plugin seam,
 * and DOES NOT boot a server (the Bun server boot lives in `index.ts`, the package
 * `main`, run directly as the deployable). a third party assembling their own
 * Steward app imports from here:
 *
 *   import { createApp, buildPluginContext, registerPlugin } from "@stwd/api";
 *   import { tradingPlugin } from "@stwd/plugin-trading";
 *   const app = createApp();
 *   await registerPlugin(app, tradingPlugin, buildPluginContext());
 *
 * the lean core (`createApp`) has NO dependency on the trading stack; trading is
 * opt-in via the plugin.
 *
 * NOTE: `composeApp` (compose.ts) is intentionally NOT re-exported here. it is
 * THIS repo's deploy-only composition root and statically imports
 * `@stwd/plugin-trading` (so the worker bundle includes it). re-exporting it from
 * the library entry would pull the trading plugin into the graph of every consumer
 * that imports `@stwd/api`, defeating the lean-core decoupling. a consumer that
 * wants trading composes it themselves with `registerPlugin(...)` as shown above.
 */

export { app, createApp, mountCoreIdempotencyAndRoutes, startTime } from "./app";
export {
  buildPluginContext,
  registerPlugin,
  type StewardApiPlugin,
  type StewardApp,
  type StewardAppContext,
} from "./plugin";

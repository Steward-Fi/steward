/**
 * _ctx.ts — test-only helper that builds the injected plugin context from the
 * real `@stwd/api` core singletons.
 *
 * the plugin's RUNTIME does not depend on `@stwd/api` (the core injects the
 * context at registration). the TESTS, however, exercise the moved routes
 * against the same real db/vault/policy singletons the core uses, so they import
 * `buildPluginContext()` from `@stwd/api` (a devDependency) to get a ctx wired to
 * those singletons — exactly what the core would inject at the composition root.
 * this keeps the test behavior identical to when these routes lived in @stwd/api.
 */

import { buildPluginContext } from "@stwd/api/plugin";
import type { StewardAppContext } from "../context";

export function testCtx(): StewardAppContext {
  // buildPluginContext() returns the structural shape the plugin expects; cast to
  // the plugin's own StewardAppContext (same shape, declared independently so the
  // plugin never imports the core at runtime).
  return buildPluginContext() as unknown as StewardAppContext;
}

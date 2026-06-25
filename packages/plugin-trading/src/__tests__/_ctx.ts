/**
 * _ctx.ts — test-only helper that builds the injected plugin context from the
 * real `@stwd/api` core singletons.
 *
 * the plugin's RUNTIME does not depend on `@stwd/api` (the core injects the
 * context at registration). the TESTS, however, exercise the moved routes
 * against the same real db/vault/policy singletons the core uses, so they import
 * `buildPluginContext()` from the core's source to get a ctx wired to those
 * singletons, exactly what the core would inject at the composition root. this
 * keeps the test behavior identical to when these routes lived in @stwd/api.
 *
 * NOTE: the import is a RELATIVE path into the core's source (not the `@stwd/api`
 * package specifier) ON PURPOSE. the core (`@stwd/api`) declares a runtime
 * dependency on this plugin (its deployable composes trading), so a package-level
 * `@stwd/api` devDependency here would form a workspace dependency CYCLE that the
 * monorepo task runner (turbo) rejects. importing the core's source directly keeps
 * this a test-only, build-graph-invisible edge: bun resolves the relative path at
 * test time, and the package graph stays acyclic (plugin has no dep back on the
 * core).
 */

import { buildPluginContext } from "../../../api/src/plugin";
import type { StewardAppContext } from "../context";

export function testCtx(): StewardAppContext {
  // buildPluginContext() returns the structural shape the plugin expects; cast to
  // the plugin's own StewardAppContext (same shape, declared independently so the
  // plugin never imports the core at runtime).
  return buildPluginContext() as unknown as StewardAppContext;
}

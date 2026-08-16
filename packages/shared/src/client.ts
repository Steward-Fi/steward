/**
 * client.ts: the browser/worker-safe entrypoint for `@stwd/shared`.
 *
 * WHY THIS EXISTS (issue #231)
 * ----------------------------
 * The top-level barrel (`index.ts`) re-exports server-only modules that import
 * `node:crypto` (`provider-execution-auth.ts`, `provider-action.ts`). Any web
 * bundle that imports the barrel, even for a pure helper like
 * `getNativeDecimals`, drags `node:crypto` into the Cloudflare Worker bundle,
 * which webpack/OpenNext cannot resolve, breaking `cf:build`.
 *
 * This entrypoint (`@stwd/shared/client`) exposes ONLY modules whose entire
 * transitive import graph is free of node builtins and free of server-only
 * crypto. Browser and Worker code MUST import from here, never from the
 * top-level barrel.
 *
 * RULES FOR ADDING EXPORTS
 * ------------------------
 *   1. Re-export a module here only if its transitive graph contains no
 *      `node:*` (or bare node builtin) imports and no server-only modules.
 *   2. NEVER re-export `provider-execution-auth.js` or `provider-action.js`
 *      from here; server crypto stays on the server entrypoint (`.`).
 *   3. The contract test `__tests__/client-entrypoint.test.ts` walks this
 *      module graph (source AND emitted dist) and fails the build if a node
 *      builtin or a server-only module leaks in. Keep it passing.
 */

// Chain provider registry: CAIP-2 metadata, explorer URLs, signing-curve
// support tables. Pure data + lookups, no node imports.
export * from "./chains/index.js";

// Non-throwing description of an arbitrary thrown value (fail-closed catches).
export { describeThrown, UNPRINTABLE_THROWN_VALUE } from "./safe-error.js";

// Token registry: native/known token decimals, symbols, metadata. Pure data.
export * from "./tokens.js";

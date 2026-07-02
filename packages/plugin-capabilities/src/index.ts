/**
 * @stwd/plugin-capabilities — the opt-in capability plugin for Steward.
 *
 * a CAPABILITY is a NAMED, narrowly-scoped use of a stored secret
 * (e.g. "github.pr.comment" -> secretId + host + path + method + header
 * injection). a GRANT says "agent X may use capability Y" (optionally until an
 * expiry). the plugin's job is to keep, per grant, exactly one legal narrow
 * secret_route — the row the already-defended proxy consumes to inject the
 * credential outbound. the plugin NEVER decrypts a secret and NEVER injects a
 * credential itself; it maintains the route rows the proxy matches.
 *
 * this package uses the shipped plugin SDK contribution points:
 *   - migrations (2c): plugin-owned, namespaced-journal `capabilities` +
 *     `capability_grants` tables (isolated from the core migration ledger).
 *   - routes (2a register): operator/tenant-auth capability + grant CRUD, plus
 *     the agent-scoped "what may this agent use" read.
 *   - webhookEvents (2a): the events THIS package emits at CRUD time.
 *
 * SCOPE (W-1a): schema + CRUD + grants + paired-route lifecycle ONLY. there is
 * NO policy evaluation and NO invoke/forward path here (those are W-1b / W-1c).
 * the package builds + tests STANDALONE and is NOT registered in the api
 * composition root yet (that wiring is W-1c's job).
 *
 * the core never imports this package, and this package never imports `@stwd/api`:
 * the shared service singletons + auth middleware the routes need are INJECTED via
 * the `StewardAppContext` the core hands `register(app, ctx)` (no dependency cycle).
 */

import { fileURLToPath } from "node:url";
import type { AppVariables, StewardPlugin } from "@stwd/shared";
import type { Hono } from "hono";
import type { StewardAppContext } from "./context";
import { createAgentCapabilityRoutes, createCapabilityRoutes } from "./routes";

export type { StewardAppContext } from "./context";
export type {
  Capability,
  CapabilityGrant,
  NewCapability,
  NewCapabilityGrant,
} from "./schema";
export { capabilities, capabilityGrants } from "./schema";
export { AgentNotFoundError, CapabilityStore, GrantExistsError, isExpired } from "./store";
export type { CapabilitySpec } from "./store";
export { createAgentCapabilityRoutes, createCapabilityRoutes } from "./routes";
export {
  createCapabilitySchema,
  createGrantSchema,
  updateCapabilitySchema,
  validateCapabilitySpec,
} from "./validate";

/** the steward app the plugin mounts onto: a hono app with the shared variables. */
export type StewardApp = Hono<{ Variables: AppVariables }>;

/** a steward plugin concretely bound to the hono app + the injected context. */
export type StewardApiPlugin = StewardPlugin<StewardApp, StewardAppContext>;

/**
 * the plugin's OWN drizzle migrations folder, resolved to an ABSOLUTE path at
 * runtime (a relative path would break depending on process cwd). the host
 * applies it AFTER the core migrator into a per-plugin namespaced bookkeeping
 * table (drizzle.__drizzle_migrations_plugin_capabilities), isolated from the
 * core journal.
 */
const MIGRATIONS_FOLDER = fileURLToPath(new URL("../drizzle", import.meta.url));

/**
 * Webhook event-type names this package emits (Phase 2a contribution). Only the
 * CRUD lifecycle events W-1a produces are declared here; the invoke-time events
 * (capability.invoked / .denied / .approval_queued) are declared by W-1c, the
 * package that emits them.
 */
export const CAPABILITY_WEBHOOK_EVENTS = ["capability.created", "capability.revoked"] as const;

/**
 * The capability plugin. `register(app, ctx)`:
 *   1. installs the tenant gate on /capabilities and /agents (operator-facing
 *      management surface; the routes additionally require recent tenant-admin
 *      MFA — the same bar the core /secrets + secret-route CRUD enforce, because
 *      capabilities drive live credential injection).
 *   2. mounts the capability + grant CRUD router at /capabilities and /v1/capabilities.
 *   3. mounts the agent-scoped "usable capabilities" read at /agents and /v1/agents.
 *
 * NOTE: this plugin is NOT registered in the api composition root during W-1a; it
 * is verified STANDALONE (its own tests register it onto a bare hono app with an
 * injected context). the composition-root registration (compose.ts) is W-1c.
 */
export const capabilitiesPlugin: StewardApiPlugin = {
  name: "capabilities",
  version: "0.1.0",
  webhookEvents: CAPABILITY_WEBHOOK_EVENTS,
  migrations: {
    id: "capabilities",
    migrationsFolder: MIGRATIONS_FOLDER,
  },
  register(app, ctx) {
    const { tenantAuth } = ctx;

    // ── tenant gate on the management + agent-scoped surfaces ─────────────────
    app.use("/capabilities", (c, next) => tenantAuth(c, next));
    app.use("/capabilities/*", (c, next) => tenantAuth(c, next));
    app.use("/v1/capabilities", (c, next) => tenantAuth(c, next));
    app.use("/v1/capabilities/*", (c, next) => tenantAuth(c, next));
    app.use("/agents/*", (c, next) => tenantAuth(c, next));
    app.use("/v1/agents/*", (c, next) => tenantAuth(c, next));

    // ── route mounts (unversioned + versioned) ────────────────────────────────
    const capabilityRoutes = createCapabilityRoutes(ctx);
    const agentRoutes = createAgentCapabilityRoutes(ctx);
    app.route("/capabilities", capabilityRoutes);
    app.route("/v1/capabilities", capabilityRoutes);
    app.route("/agents", agentRoutes);
    app.route("/v1/agents", agentRoutes);
  },
};

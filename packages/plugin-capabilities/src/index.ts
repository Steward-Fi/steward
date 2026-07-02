/**
 * @stwd/plugin-capabilities - the opt-in capability plugin for Steward.
 *
 * a CAPABILITY is a NAMED, narrowly-scoped use of a stored secret
 * (e.g. "github.pr.comment" -> secretId + host + path + method + header
 * injection). a GRANT says "agent X may use capability Y" (optionally until an
 * expiry). the plugin's job is to keep, per grant, exactly one legal narrow
 * secret_route - the row the already-defended proxy consumes to inject the
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
import { capabilityIntentContribution } from "@stwd/policy-engine";
import type { AppVariables, StewardPlugin } from "@stwd/shared";
import type { Context, Hono, Next } from "hono";
import type { StewardAppContext } from "./context";
import { createInvokeRoutes } from "./invoke";
import { createAgentCapabilityRoutes, createCapabilityRoutes } from "./routes";

export type { StewardAppContext } from "./context";
export { createInvokeRoutes } from "./invoke";
export { createAgentCapabilityRoutes, createCapabilityRoutes } from "./routes";
export type {
  Capability,
  CapabilityGrant,
  CapabilityInvocation,
  InvocationDecision,
  NewCapability,
  NewCapabilityGrant,
  NewCapabilityInvocation,
} from "./schema";
export { capabilities, capabilityGrants, capabilityInvocations } from "./schema";
export type { CapabilitySpec } from "./store";
export { AgentNotFoundError, CapabilityStore, GrantExistsError, isExpired } from "./store";
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
export const CAPABILITY_WEBHOOK_EVENTS = [
  "capability.created",
  "capability.revoked",
  // invoke-time events (W-1c). declared by THIS package because it emits them.
  "capability.invoked",
  "capability.denied",
  "capability.approval_queued",
] as const;

/**
 * The capability plugin. `register(app, ctx)`:
 *   1. installs the tenant gate on /capabilities and /agents (operator-facing
 *      management surface; the routes additionally require recent tenant-admin
 *      MFA - the same bar the core /secrets + secret-route CRUD enforce, because
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
  // the `capability-intent` policy rule (W-1b, shipped in @stwd/policy-engine as a
  // PolicyRuleContribution). the plugin host registers it into the policy-engine
  // evaluator registry BEFORE any route runs, so the engine can evaluate a
  // capability-intent rule (via the registry's default arm) instead of denying it
  // as an unknown type. the invoke path (invoke.ts) still owns the effective
  // default-deny; this contribution just makes the rule TYPE evaluable engine-wide.
  // registration fails closed on a type collision (a core rule type or another
  // plugin's) — see the plugin host.
  policyRules: [capabilityIntentContribution],
  migrations: {
    id: "capabilities",
    migrationsFolder: MIGRATIONS_FOLDER,
  },
  register(app, ctx) {
    const { tenantAuth, requireAgentJwt } = ctx;

    // ── auth gates ────────────────────────────────────────────────────────────
    // the agent-facing invoke path (`/capabilities/:name/invoke`) is agent-token-
    // authed, NOT tenant-gated. it carries its OWN agent-jwt middleware. every
    // OTHER `/capabilities/*` subpath is the operator CRUD/grant surface and stays
    // behind the tenant gate. because a single broad `/capabilities/*` tenant gate
    // would also match the invoke subpath (and reject an agent token), the tenant
    // gate is applied via a wrapper that SKIPS the invoke subpath — the invoke
    // route's own agent-jwt middleware is the only auth on that path. fail-closed:
    // anything that is not exactly the invoke subpath falls through to tenantAuth.
    app.use("/capabilities/:name/invoke", (c, next) => requireAgentJwt(c, next));
    app.use("/v1/capabilities/:name/invoke", (c, next) => requireAgentJwt(c, next));
    app.use("/capabilities", (c, next) => tenantAuth(c, next));
    app.use("/capabilities/*", (c, next) => tenantGateSkippingInvoke(c, next, tenantAuth));
    app.use("/v1/capabilities", (c, next) => tenantAuth(c, next));
    app.use("/v1/capabilities/*", (c, next) => tenantGateSkippingInvoke(c, next, tenantAuth));
    app.use("/agents/*", (c, next) => tenantAuth(c, next));
    app.use("/v1/agents/*", (c, next) => tenantAuth(c, next));

    // ── route mounts (unversioned + versioned) ────────────────────────────────
    // invoke routes mount FIRST so `/capabilities/:name/invoke` is registered
    // before the CRUD `/:id` matcher (hono resolves same-specificity routes in
    // registration order; the invoke handler ends the chain for that path).
    const invokeRoutes = createInvokeRoutes(ctx);
    const capabilityRoutes = createCapabilityRoutes(ctx);
    const agentRoutes = createAgentCapabilityRoutes(ctx);
    app.route("/capabilities", invokeRoutes);
    app.route("/v1/capabilities", invokeRoutes);
    app.route("/capabilities", capabilityRoutes);
    app.route("/v1/capabilities", capabilityRoutes);
    app.route("/agents", agentRoutes);
    app.route("/v1/agents", agentRoutes);
  },
};

/** the invoke subpath predicate: `/capabilities/<name>/invoke` (any single name segment). */
const INVOKE_SUBPATH = /\/(?:v1\/)?capabilities\/[^/]+\/invoke\/?$/;

/**
 * Apply the operator tenant gate to a `/capabilities/*` request UNLESS it is the
 * agent-facing invoke subpath (which is authed by its own agent-jwt middleware).
 * Skipping the invoke subpath here prevents the broad operator gate from
 * rejecting a valid agent token. Fail-closed: only the exact invoke subpath is
 * exempted; every other path is gated.
 */
async function tenantGateSkippingInvoke(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
  tenantAuth: StewardAppContext["tenantAuth"],
): Promise<void | Response> {
  if (INVOKE_SUBPATH.test(c.req.path)) return next();
  return tenantAuth(c, next);
}

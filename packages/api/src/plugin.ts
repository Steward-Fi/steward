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

import {
  type EvaluatorContext,
  type PolicyRuleRegistry,
  policyRuleRegistry,
  type RegisteredPolicyEvaluator,
} from "@stwd/policy-engine";
import type { StewardPlugin } from "@stwd/shared";
import { WebhookEventRegistry } from "@stwd/shared";
import type { Hono } from "hono";
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
import { CONFIGURED_WEBHOOK_EVENT_TYPES } from "./services/webhook-events";

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

/**
 * a steward plugin concretely bound to the hono app + the injected context. the
 * third type arg binds a contributed policy rule's evaluator context to the policy
 * engine's {@link EvaluatorContext}, so a plugin author's `policyRules[].evaluate`
 * receives the real engine context (request + spend counters + oracle + venue +
 * leverage + ...).
 */
export type StewardApiPlugin = StewardPlugin<StewardApp, StewardAppContext, EvaluatorContext>;

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
 * Error thrown when the plugin host cannot build a valid registration order:
 * a duplicate plugin name, a dependency on a plugin that was not provided, or a
 * dependency cycle. The host FAILS CLOSED on any of these — it never registers a
 * partial/ambiguous plugin set (mirrors the fail-closed-in-production philosophy
 * of the adapter registry).
 */
export class PluginHostError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PluginHostError";
  }
}

/** A loaded plugin's identity, surfaced by the host for diagnostics. */
export interface LoadedPluginInfo {
  name: string;
  version?: string;
}

/**
 * Diagnostics describing what a host run loaded + what plugins contributed.
 * Returned by {@link PluginHost.describe} for ops/health endpoints.
 */
export interface PluginHostDiagnostics {
  /** loaded plugins, in dependency (registration) order. */
  plugins: LoadedPluginInfo[];
  /** every valid webhook event name after merging plugin contributions. */
  webhookEvents: string[];
  /** which plugin contributed which webhook event names (core events excluded). */
  webhookEventContributions: Record<string, string[]>;
  /** which plugin contributed which policy rule types (Phase 2b). */
  policyRuleContributions: Record<string, string[]>;
}

/**
 * Topologically order plugins by their `dependsOn` graph so every plugin is
 * registered AFTER the plugins it depends on. FAILS CLOSED (throws
 * {@link PluginHostError}) on a duplicate name, an unknown dependency, or a
 * cycle — the host never registers a plugin against a half-built or missing
 * dependency.
 */
function orderByDependencies<Ctx>(
  plugins: ReadonlyArray<StewardPlugin<StewardApp, Ctx>>,
): Array<StewardPlugin<StewardApp, Ctx>> {
  const byName = new Map<string, StewardPlugin<StewardApp, Ctx>>();
  for (const plugin of plugins) {
    if (!plugin.name || typeof plugin.name !== "string") {
      throw new PluginHostError("plugin is missing a non-empty string `name`.");
    }
    if (byName.has(plugin.name)) {
      throw new PluginHostError(`duplicate plugin name: "${plugin.name}".`);
    }
    byName.set(plugin.name, plugin);
  }

  // Validate every declared dependency exists before ordering, so a missing dep
  // fails closed with a clear message rather than surfacing as a phantom cycle.
  for (const plugin of plugins) {
    for (const dep of plugin.dependsOn ?? []) {
      if (!byName.has(dep)) {
        throw new PluginHostError(
          `plugin "${plugin.name}" depends on "${dep}", which is not registered.`,
        );
      }
    }
  }

  // Depth-first topological sort with cycle detection. `visiting` marks nodes on
  // the current DFS stack; re-entering one is a cycle.
  const ordered: Array<StewardPlugin<StewardApp, Ctx>> = [];
  const visited = new Set<string>();
  const visiting = new Set<string>();

  const visit = (name: string, trail: string[]): void => {
    if (visited.has(name)) return;
    if (visiting.has(name)) {
      throw new PluginHostError(
        `plugin dependency cycle detected: ${[...trail, name].join(" -> ")}.`,
      );
    }
    visiting.add(name);
    const plugin = byName.get(name);
    // Non-null: every name came from byName, and deps were validated above.
    if (plugin) {
      for (const dep of plugin.dependsOn ?? []) {
        visit(dep, [...trail, name]);
      }
      ordered.push(plugin);
    }
    visiting.delete(name);
    visited.add(name);
  };

  // Visit in the caller's declared order so independent plugins keep a stable,
  // predictable registration order (only dependencies reorder them).
  for (const plugin of plugins) {
    visit(plugin.name, []);
  }

  return ordered;
}

/**
 * The plugin host: composes one or more plugins onto a steward app.
 *
 * RESPONSIBILITIES (Phase 2a + 2b)
 * --------------------------------
 *  1. validate unique plugin names + a valid (acyclic, fully-satisfied)
 *     `dependsOn` graph, FAILING CLOSED on any violation.
 *  2. order plugins so each registers AFTER its dependencies.
 *  3. collect each plugin's declared `webhookEvents` into a runtime-extensible
 *     {@link WebhookEventRegistry} (core events ∪ plugin-declared), so the
 *     webhook config/dispatch path accepts a plugin's event type. (Phase 2a)
 *  4. register each plugin's declared `policyRules` into the policy engine's
 *     runtime evaluator {@link PolicyRuleRegistry}, FAILING CLOSED on a rule
 *     `type` that collides with a core rule type or another plugin's, so the
 *     policy engine evaluates a contributed rule type via the plugin's
 *     evaluator (core rule evaluation is untouched). (Phase 2b)
 *  5. call each plugin's `register(app, ctx)` (if present) in dependency order.
 *  6. expose {@link describe} so ops can see what loaded + what was contributed.
 *
 * `migrations` / `adapters` contribution points are TYPED on the contract but
 * their wiring is DEFERRED to Phase 2c/2d; the host does not act on them yet.
 */
export class PluginHost<Ctx> {
  private readonly loaded: LoadedPluginInfo[] = [];
  private readonly eventRegistry: WebhookEventRegistry;
  private readonly policyRegistry: PolicyRuleRegistry;
  /** which plugin contributed which policy rule types (diagnostics). */
  private readonly policyContributions = new Map<string, string[]>();

  /**
   * @param eventRegistry the registry plugin-declared webhook events merge into.
   *   defaults to a fresh registry seeded with the core event types, so the host
   *   is usable standalone (tests); the composition root passes the SHARED
   *   registry the webhook config/dispatch path consults.
   * @param policyRegistry the policy-engine evaluator registry plugin-contributed
   *   policy rules register into. defaults to the process-wide
   *   {@link policyRuleRegistry} the engine's evaluatePolicy consults; tests pass
   *   an isolated registry for hermeticity.
   */
  constructor(eventRegistry?: WebhookEventRegistry, policyRegistry?: PolicyRuleRegistry) {
    this.eventRegistry = eventRegistry ?? new WebhookEventRegistry(CONFIGURED_WEBHOOK_EVENT_TYPES);
    this.policyRegistry = policyRegistry ?? policyRuleRegistry;
  }

  /** the webhook event registry this host merges plugin events into. */
  get webhookEventRegistry(): WebhookEventRegistry {
    return this.eventRegistry;
  }

  /** the policy-rule evaluator registry this host registers plugin rules into. */
  get policyRuleRegistry(): PolicyRuleRegistry {
    return this.policyRegistry;
  }

  /**
   * Register one or more plugins onto `app` with the injected `ctx`. Orders by
   * `dependsOn`, merges each plugin's declared webhook events into the registry,
   * then calls each plugin's `register` (if present) in dependency order. Throws
   * {@link PluginHostError} (fail closed) on a duplicate/missing/cyclic
   * dependency BEFORE registering anything.
   */
  async register(
    app: StewardApp,
    ctx: Ctx,
    ...plugins: Array<StewardPlugin<StewardApp, Ctx>>
  ): Promise<void> {
    const ordered = orderByDependencies(plugins);

    // Phase 1: merge declared webhook events FIRST, so a plugin's `register`
    // (and any concurrent dispatch) sees its own events as already valid.
    for (const plugin of ordered) {
      if (plugin.webhookEvents && plugin.webhookEvents.length > 0) {
        this.eventRegistry.registerPluginEvents(plugin.name, plugin.webhookEvents);
      }
    }

    // Phase 1b: register declared policy rules into the policy-engine evaluator
    // registry (Phase 2b). Done BEFORE any `register` hook runs, so a plugin's
    // rule type is evaluable as soon as it (or anything) calls into the engine.
    // FAILS CLOSED: a `type` colliding with a core rule type or another plugin's
    // throws PolicyRuleRegistryError from the registry — the host never composes
    // an ambiguous policy-evaluation surface (a plugin cannot shadow a money-rail
    // core decision, nor silently override another plugin's rule type).
    for (const plugin of ordered) {
      if (!plugin.policyRules || plugin.policyRules.length === 0) continue;
      for (const contribution of plugin.policyRules) {
        this.policyRegistry.register({
          type: contribution.type,
          pluginName: plugin.name,
          ...(contribution.description !== undefined
            ? { description: contribution.description }
            : {}),
          // the contribution's `evaluate` is declared against the plugin's bound
          // EvalCtx (the engine's EvaluatorContext at the api composition root);
          // the registry calls it with the concrete EvaluatorContext.
          evaluate: contribution.evaluate as RegisteredPolicyEvaluator["evaluate"],
        });
        const types = this.policyContributions.get(plugin.name) ?? [];
        types.push(contribution.type);
        this.policyContributions.set(plugin.name, types);
      }
    }

    // Phase 2: run each plugin's imperative register hook in dependency order.
    for (const plugin of ordered) {
      this.loaded.push({ name: plugin.name, version: plugin.version });
      if (plugin.register) {
        await plugin.register(app, ctx);
      }
    }
  }

  /** What this host loaded + what plugins contributed (for ops/health). */
  describe(): PluginHostDiagnostics {
    const policyRuleContributions: Record<string, string[]> = {};
    for (const [plugin, types] of this.policyContributions) {
      policyRuleContributions[plugin] = [...types].sort();
    }
    return {
      plugins: [...this.loaded],
      webhookEvents: this.eventRegistry.list(),
      webhookEventContributions: this.eventRegistry.describeContributions(),
      policyRuleContributions,
    };
  }
}

/**
 * Register a SINGLE plugin onto the steward app, injecting the core context.
 * Back-compat convenience that delegates to a {@link PluginHost} — the existing
 * `app.register(plugin)`-style call site keeps working unchanged. Use
 * {@link PluginHost} directly to compose multiple plugins with dependency
 * ordering + contribution diagnostics.
 *
 * @returns the host that registered the plugin, so a caller can inspect what was
 *   contributed via {@link PluginHost.describe}. (The return is additive; the
 *   prior `Promise<void>` callers ignore it.)
 */
export async function registerPlugin<Ctx>(
  app: StewardApp,
  plugin: StewardPlugin<StewardApp, Ctx>,
  ctx: Ctx,
  eventRegistry?: WebhookEventRegistry,
  policyRegistry?: PolicyRuleRegistry,
): Promise<PluginHost<Ctx>> {
  const host = new PluginHost<Ctx>(eventRegistry, policyRegistry);
  await host.register(app, ctx, plugin);
  return host;
}

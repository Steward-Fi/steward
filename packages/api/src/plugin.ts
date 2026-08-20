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
 *
 * PLUGIN TRUST MODEL (SEC-170)
 * ----------------------------
 * plugins run IN-PROCESS with FULL trust — there is no sandbox. the injected
 * ctx hands a plugin the live `vault` (it can sign arbitrary transactions for
 * any agent/tenant, bypassing the policy engine) and the raw drizzle `db`
 * handle (it can rewrite `agent_policies`, insert `secret_routes`, read
 * ciphertext). the host's fail-closed guarantees cover CONTRIBUTION COLLISIONS
 * (duplicate plugin names, missing deps, cycles, migration conflicts), NOT
 * privilege: a malicious or compromised plugin package is full RCE with
 * signing authority. therefore:
 *   - only register first-party plugins or third-party plugins you would
 *     trust with root on the host AND the master signing keys;
 *   - pin + audit plugin dependencies exactly as you would the core itself;
 *   - never register a plugin supplied at runtime by an untrusted party.
 * a policy-gated signing facade in place of the raw vault handle is a
 * considered future hardening, not currently implemented (SEC-170).
 */

import { type AdapterCategory, AdapterRegistry, adapterRegistry } from "@stwd/adapters";
import {
  getDb,
  hasTenantTransactionDatabase,
  pluginMigrationsTable,
  runPluginMigrations,
  withDatabaseDeadline,
  withTenantAuditedTransaction,
  withTenantAuditedTransactionOnDb,
  withTenantTransactionDatabaseDeadline,
} from "@stwd/db";
import {
  type EvaluatorContext,
  type PolicyRuleRegistry,
  policyRuleRegistry,
  type RegisteredPolicyEvaluator,
} from "@stwd/policy-engine";
import type { PluginMigrationSource, StewardPlugin } from "@stwd/shared";
import { WebhookEventRegistry } from "@stwd/shared";
import { KeyStore, SecretVault } from "@stwd/vault";
import type { Hono } from "hono";
import {
  requireAgentJwt,
  requireCapabilityAgentJwt,
  requireProviderAgentJwt,
} from "./middleware/agent-jwt";
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
  MASTER_PASSWORD,
  policyEngine,
  priceOracle,
  safeJsonParse,
  tenantAuth,
  vault,
} from "./services/context";
import { createEnvEvmSimulator, type EvmSimulator } from "./services/evm-simulator";
import { CONFIGURED_WEBHOOK_EVENT_TYPES } from "./services/webhook-events";

/** the steward app a plugin mounts onto: a hono app with the shared variables. */
export type StewardApp = Hono<{ Variables: AppVariables }>;

/**
 * The closed set of adapter categories the core registry knows, mirrored here so
 * the host can VALIDATE a plugin's structural `category: string` before casting
 * it to {@link AdapterCategory} and calling `register`. Kept in sync with
 * `@stwd/adapters`' `AdapterCategory` union (a compile-time exhaustiveness check
 * below fails the build if the union grows and this set doesn't).
 */
const KNOWN_ADAPTER_CATEGORIES = new Set<string>([
  "swap",
  "earn",
  "onramp",
  "offramp",
  "kyc",
  "tos",
  "custodial",
  "push",
  "bridge",
  "spark",
  "exchange",
]);

// Compile-time guard: every AdapterCategory must be present in the runtime set
// above. If the `@stwd/adapters` union grows a member not listed here, this
// assignment fails to type-check, forcing the set to be updated in lockstep.
const _ADAPTER_CATEGORY_EXHAUSTIVE: Record<AdapterCategory, true> = {
  swap: true,
  earn: true,
  onramp: true,
  offramp: true,
  kyc: true,
  tos: true,
  custodial: true,
  push: true,
  bridge: true,
  spark: true,
  exchange: true,
};
void _ADAPTER_CATEGORY_EXHAUSTIVE;

/** True if `c` is a known adapter category (narrows to {@link AdapterCategory}). */
function isAdapterCategory(c: string): c is AdapterCategory {
  return KNOWN_ADAPTER_CATEGORIES.has(c);
}

/**
 * Structural check that an injected context carries an adapter registry, so the
 * host can wire a plugin's `adapters` contributions WITHOUT the host's `Ctx`
 * type parameter having to be {@link StewardAppContext} (the host stays generic;
 * tests pass a minimal ctx + a fresh registry). A plugin that declares `adapters`
 * REQUIRES a registry in ctx; the host fails closed if one isn't present.
 */
function ctxAdapterRegistry(ctx: unknown): AdapterRegistry | undefined {
  if (ctx && typeof ctx === "object" && "adapterRegistry" in ctx) {
    const reg = (ctx as { adapterRegistry: unknown }).adapterRegistry;
    if (reg instanceof AdapterRegistry) return reg;
  }
  return undefined;
}

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
  withTenantAuditedTransaction: typeof withTenantAuditedTransaction;
  withCredentialLeaseDatabaseDeadline<T>(
    deadlineAt: number,
    use: (
      db: ReturnType<typeof getDb>,
      auditedTransaction: typeof withTenantAuditedTransaction,
    ) => Promise<T>,
  ): Promise<T>;
  getAgentTokenStatus: typeof getAgentTokenStatus;
  getRedisClient: typeof getRedisClient;
  exerciseCredentialSecret<T>(
    tenantId: string,
    secretId: string,
    use: (plaintext: string) => Promise<T>,
  ): Promise<T>;
  sealCredentialLeaseToken(
    tenantId: string,
    leaseId: string,
    token: string,
  ): Promise<{ ciphertext: string; iv: string; tag: string; salt: string }>;
  exerciseCredentialLeaseToken<T>(
    tenantId: string,
    leaseId: string,
    sealed: { ciphertext: string; iv: string; tag: string; salt: string },
    use: (token: string) => Promise<T>,
  ): Promise<T>;
  requireAgentJwt: typeof requireAgentJwt;
  /**
   * Capability-surface authenticator: verifies the agent JWT and installs the
   * context WITHOUT the legacy `trade:order` scope gate. Capability invoke /
   * manifest / issuance routes use this — their authorization is the
   * capability grant + capability-intent policy (default-deny), not the
   * trading scope. It is a NEW field and does NOT replace `requireAgentJwt`.
   */
  requireCapabilityAgentJwt: typeof requireCapabilityAgentJwt;
  /**
   * Provider-action authenticator: verifies the agent JWT and installs the
   * runtime-neutral principal WITHOUT a trading/proxy scope check. Provider-action
   * routes use this; it is a NEW field and does NOT replace `requireAgentJwt`.
   */
  requireProviderAgentJwt: typeof requireProviderAgentJwt;
  operatorAuth: typeof operatorAuth;
  tenantAuth: typeof tenantAuth;
  /**
   * the core's adapter registry — the seam a plugin's `adapters` contributions
   * register a real provider integration into. Defaults to the
   * process-wide {@link adapterRegistry} routes consult; tests inject a fresh
   * {@link AdapterRegistry} (with a controlled env) so adapter resolution is
   * hermetic. the host only CALLS `register(category, provider, adapter)` on it;
   * the registry's fail-closed-in-production resolution is untouched.
   */
  adapterRegistry: AdapterRegistry;
  evmSimulator: EvmSimulator | null;
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
  const credentialVault = new SecretVault(MASTER_PASSWORD);
  const leaseKeyStore = new KeyStore(MASTER_PASSWORD, undefined, "credential-lease");
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
    withTenantAuditedTransaction,
    withCredentialLeaseDatabaseDeadline: (deadlineAt, use) => {
      if (hasTenantTransactionDatabase()) {
        return withTenantTransactionDatabaseDeadline(deadlineAt, (tenantDb) =>
          use(tenantDb, withTenantAuditedTransaction),
        );
      }
      return withDatabaseDeadline(deadlineAt, (deadlineDb) =>
        use(deadlineDb, (tenantId, fn) =>
          withTenantAuditedTransactionOnDb(deadlineDb, tenantId, fn, deadlineAt),
        ),
      );
    },
    getAgentTokenStatus,
    getRedisClient,
    exerciseCredentialSecret: (tenantId, secretId, use) =>
      credentialVault.exerciseSecret(tenantId, secretId, use),
    sealCredentialLeaseToken: async (tenantId, leaseId, token) =>
      leaseKeyStore.encrypt(token, { tenantId, name: `upstream-lease:${leaseId}`, version: 1 }),
    exerciseCredentialLeaseToken: async (tenantId, leaseId, sealed, use) => {
      const token = leaseKeyStore.decrypt(sealed, {
        tenantId,
        name: `upstream-lease:${leaseId}`,
        version: 1,
      });
      return use(token);
    },
    requireAgentJwt,
    requireCapabilityAgentJwt,
    requireProviderAgentJwt,
    operatorAuth,
    tenantAuth,
    adapterRegistry,
    evmSimulator: createEnvEvmSimulator(),
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
  /** which plugin contributed which policy rule types. */
  policyRuleContributions: Record<string, string[]>;
  /**
   * which plugin contributed which adapters, as `"<category>::<provider>"` keys
   * Reflects what the host registered into the adapter registry.
   */
  adapterContributions: Record<string, string[]>;
  /**
   * which plugin declared a migration source, and the namespaced bookkeeping
   * table its ledger is (or will be) recorded in —
   * `drizzle.__drizzle_migrations_plugin_<id>`, isolated from the core journal
   * Present whether or not {@link PluginHost.runMigrations} has run
   * yet (it reflects the declared sources, not applied state).
   */
  migrationSources: Record<string, { id: string; migrationsTable: string }>;
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
 * Responsibilities
 * ----------------
 *  1. validate unique plugin names + a valid (acyclic, fully-satisfied)
 *     `dependsOn` graph, FAILING CLOSED on any violation.
 *  2. order plugins so each registers AFTER its dependencies.
 *  3. collect each plugin's declared `webhookEvents` into a runtime-extensible
 *     {@link WebhookEventRegistry} (core events ∪ plugin-declared), so the
 *     webhook config/dispatch path accepts a plugin's event type.
 *  4. register each plugin's declared `policyRules` into the policy engine's
 *     runtime evaluator {@link PolicyRuleRegistry}, FAILING CLOSED on a rule
 *     `type` that collides with a core rule type or another plugin's, so the
 *     policy engine evaluates a contributed rule type via the plugin's
 *     evaluator (core rule evaluation is untouched).
 *  5. call each plugin's `register(app, ctx)` (if present) in dependency order.
 *  6. collect each plugin's declared `migrations` source (in dependency order)
 *     and apply them — via {@link runMigrations}, called by the boot/migrate path
 *     AFTER the core migrator — into a per-plugin NAMESPACED bookkeeping table,
 *     totally isolated from the core's `drizzle.__drizzle_migrations` journal
 *     Migrations are NOT run during `register` (route registration
 *     must not block on a schema migration) and NEVER per request.
 *  7. register each plugin's declared `adapters` into the core adapter registry
 *     (from `ctx.adapterRegistry`) via its existing `register(category, provider,
 *     adapter)` seam, in dependency order, FAILING CLOSED on a `(category,
 *     provider)` collision with another plugin's contribution (the host never
 *     silently overwrites a real money-route adapter) or an invalid contribution
 *     (unknown category, empty provider, missing adapter). The registry's
 *     fail-closed-in-production RESOLUTION is untouched — the host only CALLS
 *     register().
 *  8. expose {@link describe} so ops can see what loaded + what was contributed.
 */
export class PluginHost<Ctx> {
  private readonly loaded: LoadedPluginInfo[] = [];
  private readonly eventRegistry: WebhookEventRegistry;
  private readonly policyRegistry: PolicyRuleRegistry;
  /** which plugin contributed which policy rule types (diagnostics). */
  private readonly policyContributions = new Map<string, string[]>();
  /**
   * which plugin contributed which adapters, as `"<category>::<provider>"` keys
   * (diagnostics).
   */
  private readonly adapterContributions = new Map<string, string[]>();
  /**
   * EVERY `(category, provider)` pair this host has registered, durable across
   * `register()` calls. The collision guard must outlive a single host pass:
   * the registry's own `register` silently `Map.set`-overwrites, so a plugin
   * registered in a LATER pass (or core code registering directly) would
   * otherwise clobber a live money-route adapter without an error.
   */
  private readonly registeredAdapterKeys = new Set<string>();
  /**
   * declared plugin migration sources, in dependency (registration) order. The
   * host does NOT run these during `register` (route registration must not block
   * on a schema migration); instead {@link runMigrations} applies them, called by
   * the boot/migrate path AFTER the core migrator has run. Stored in dependency
   * order so a plugin's migrations apply after the plugins it depends on.
   */
  private readonly migrationSources: Array<{ pluginName: string; source: PluginMigrationSource }> =
    [];

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

  private prepareMigrationSources(
    plugins: ReadonlyArray<StewardPlugin<StewardApp, Ctx>>,
  ): Array<{ pluginName: string; source: PluginMigrationSource }> {
    const owners = new Map(
      this.migrationSources.map(({ pluginName, source }) => [
        pluginMigrationsTable(source.id),
        pluginName,
      ]),
    );
    const additions: Array<{ pluginName: string; source: PluginMigrationSource }> = [];
    for (const plugin of plugins) {
      if (!plugin.migrations) continue;
      let table: string;
      try {
        table = pluginMigrationsTable(plugin.migrations.id);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new PluginHostError(`plugin "${plugin.name}" migration id is invalid: ${message}`);
      }
      const owner = owners.get(table);
      if (owner) {
        throw new PluginHostError(
          `plugin "${plugin.name}" migration id aliases the journal already owned by ` +
            `plugin "${owner}" (${table}); refusing cross-plugin migration state.`,
        );
      }
      owners.set(table, plugin.name);
      additions.push({ pluginName: plugin.name, source: plugin.migrations });
    }
    return additions;
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
    const migrationSources = this.prepareMigrationSources(ordered);

    // Merge declared webhook events first so a plugin's `register`
    // (and any concurrent dispatch) sees its own events as already valid.
    for (const plugin of ordered) {
      if (plugin.webhookEvents && plugin.webhookEvents.length > 0) {
        this.eventRegistry.registerPluginEvents(plugin.name, plugin.webhookEvents);
      }
    }

    // Register declared policy rules into the policy-engine evaluator registry
    // before any `register` hook runs, so a plugin's
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

    // Register declared adapter contributions into the core's adapter registry
    // before any `register` hook runs (so a plugin route
    // that resolves an adapter during its own registration sees the contributed
    // provider). The registry is taken from `ctx.adapterRegistry`; a plugin that
    // declares `adapters` REQUIRES it. The registry's own fail-closed-in-prod
    // RESOLUTION is untouched — the host only CALLS register(category, provider,
    // adapter).
    //
    // FAIL-CLOSED on a `(category, provider)` collision: the registry's own
    // `register` would silently OVERWRITE by (category, provider); to prevent a
    // plugin (or two plugins) from silently clobbering a real money-route
    // adapter, the host tracks every (category, provider) it has registered
    // DURABLY (across `register()` passes, not just within one) AND consults the
    // registry itself, so a pair already registered outside this host (core
    // code, or a previous host sharing the registry) also fails closed. Each
    // contribution is also validated fail-closed: a known category, a non-empty
    // provider, and a present adapter.
    {
      const hostRegistry = ctxAdapterRegistry(ctx);
      for (const plugin of ordered) {
        if (!plugin.adapters || plugin.adapters.length === 0) continue;
        if (!hostRegistry) {
          throw new PluginHostError(
            `plugin "${plugin.name}" contributes adapters but the injected context ` +
              "carries no `adapterRegistry`.",
          );
        }
        for (const contribution of plugin.adapters) {
          const category = contribution.category;
          const provider = contribution.provider;
          if (typeof category !== "string" || !isAdapterCategory(category)) {
            throw new PluginHostError(
              `plugin "${plugin.name}" contributes an adapter for unknown category ` +
                `"${String(category)}".`,
            );
          }
          if (typeof provider !== "string" || provider.trim() === "") {
            throw new PluginHostError(
              `plugin "${plugin.name}" contributes a "${category}" adapter with an ` +
                "empty provider name.",
            );
          }
          if (contribution.adapter === undefined || contribution.adapter === null) {
            throw new PluginHostError(
              `plugin "${plugin.name}" contributes a "${category}" adapter under ` +
                `provider "${provider}" with no adapter instance.`,
            );
          }
          const key = `${category}::${provider}`;
          if (this.registeredAdapterKeys.has(key)) {
            throw new PluginHostError(
              `duplicate adapter contribution for (category="${category}", ` +
                `provider="${provider}") — plugin "${plugin.name}" collides with an ` +
                "already-registered contribution; refusing to overwrite a registered " +
                "adapter.",
            );
          }
          if (hostRegistry.has(category, provider)) {
            throw new PluginHostError(
              `adapter contribution for (category="${category}", ` +
                `provider="${provider}") from plugin "${plugin.name}" collides with ` +
                "an adapter already registered outside the plugin host; refusing " +
                "to overwrite a live adapter.",
            );
          }
          this.registeredAdapterKeys.add(key);
          // category is narrowed to AdapterCategory; adapter is `unknown` at the
          // shared boundary — cast to the registry's per-category type here, at
          // the api boundary where @stwd/adapters is a legitimate dependency. The
          // cast is unavoidable (see AdapterContribution's cycle note); the
          // contribution author owns the adapter conforming to its category.
          hostRegistry.register(
            category,
            provider,
            contribution.adapter as Parameters<AdapterRegistry["register"]>[2],
          );
          const list = this.adapterContributions.get(plugin.name) ?? [];
          list.push(key);
          this.adapterContributions.set(plugin.name, list);
        }
      }
    }

    // Collect declared migration sources in dependency order. They are not
    // applied here because route registration must not block on a schema
    // migration, and migrations must run AFTER the CORE migrator. They are
    // applied by runMigrations(), called from the boot/migrate path after core
    // migrations. Stored in dependency order so a dependent plugin's migrations
    // apply after the plugins it depends on (it may FK their tables).
    this.migrationSources.push(...migrationSources);

    // Run each plugin's imperative register hook in dependency order.
    for (const plugin of ordered) {
      this.loaded.push({ name: plugin.name, version: plugin.version });
      if (plugin.register) {
        await plugin.register(app, ctx);
      }
    }
  }

  /**
   * Collect the declared migration sources of `plugins` (in `dependsOn` order)
   * WITHOUT mounting routes/middleware or touching the webhook/policy registries.
   * For a migrate-only boot/CI step that wants to apply plugin migrations without
   * building the full app. Validates the dependency graph fail-closed (same
   * {@link PluginHostError} cases as {@link register}).
   *
   * After this, call {@link runMigrations} to apply them. Idempotent w.r.t. the
   * host's stored sources only insofar as it APPENDS; call once per host.
   */
  collectMigrations(...plugins: Array<StewardPlugin<StewardApp, Ctx>>): this {
    const ordered = orderByDependencies(plugins);
    this.migrationSources.push(...this.prepareMigrationSources(ordered));
    return this;
  }

  /**
   * Apply every registered plugin's declared migrations into its OWN namespaced
   * bookkeeping table (`drizzle.__drizzle_migrations_plugin_<id>`), totally
   * isolated from the core's `drizzle.__drizzle_migrations` journal (see
   * `@stwd/db`'s `runPluginMigrations`). Runs in dependency (registration) order
   * so a dependent plugin's migrations apply after the plugins it depends on.
   *
   * ORDERING (load-bearing): the caller MUST invoke this AFTER the core migrator
   * (`runMigrations()` from `@stwd/db`) has completed at boot/migrate time, so a
   * plugin migration may reference core tables via FK. It is NOT run implicitly on
   * every request — only at the explicit boot/migrate step, mirroring the core.
   *
   * FAIL-CLOSED: a plugin migration failure rejects with the plugin name in the
   * message; the boot path surfaces it and refuses to half-boot. Plugins after a
   * failing one are NOT applied (the run stops at the first failure).
   *
   * @returns per-plugin results: the id + the namespaced table its ledger was
   *   written to (for diagnostics / isolation assertions). Empty if no plugin
   *   declared a migration source.
   */
  async runMigrations(): Promise<
    Array<{ pluginName: string; id: string; migrationsTable: string }>
  > {
    const results: Array<{ pluginName: string; id: string; migrationsTable: string }> = [];
    for (const { pluginName, source } of this.migrationSources) {
      try {
        const { id, migrationsTable } = await runPluginMigrations(source);
        results.push({ pluginName, id, migrationsTable });
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new PluginHostError(`plugin "${pluginName}" migration failed: ${message}`);
      }
    }
    return results;
  }

  /** the declared plugin migration sources, in dependency order (diagnostics). */
  get pluginMigrationSources(): ReadonlyArray<{
    pluginName: string;
    source: PluginMigrationSource;
  }> {
    return this.migrationSources;
  }

  /** What this host loaded + what plugins contributed (for ops/health). */
  describe(): PluginHostDiagnostics {
    const policyRuleContributions: Record<string, string[]> = {};
    for (const [plugin, types] of this.policyContributions) {
      policyRuleContributions[plugin] = [...types].sort();
    }
    const adapterContributions: Record<string, string[]> = {};
    for (const [plugin, keys] of this.adapterContributions) {
      adapterContributions[plugin] = [...keys].sort();
    }
    const migrationSources: Record<string, { id: string; migrationsTable: string }> = {};
    for (const { pluginName, source } of this.migrationSources) {
      migrationSources[pluginName] = {
        id: source.id,
        migrationsTable: pluginMigrationsTable(source.id),
      };
    }
    return {
      plugins: [...this.loaded],
      webhookEvents: this.eventRegistry.list(),
      webhookEventContributions: this.eventRegistry.describeContributions(),
      policyRuleContributions,
      adapterContributions,
      migrationSources,
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

/**
 * plugin.ts — the lean-core + opt-in-plugin contract.
 *
 * steward is a lean open core (auth, wallet/vault, policy, proxy, webhooks) plus
 * opt-in plugins that a host registers onto the app at the composition root. the
 * core never imports a plugin; a plugin contributes routes/middleware through the
 * register seam, so the majority of installs that only want the core never pull a
 * plugin's transitive dependencies (smaller install, smaller supply-chain and
 * audit surface). trading is the first such plugin.
 *
 * `StewardPlugin` is intentionally generic and framework-agnostic here: it carries
 * no hono (or any http-framework) types so `@stwd/shared` keeps zero runtime deps.
 * the concrete app + context types are supplied by `@stwd/api` (see its
 * `StewardApiPlugin` / `StewardAppContext`), which is where the hono `app` and the
 * injected service context are bound. a third-party plugin author depends only on
 * `@stwd/api`'s exported plugin types, not on `@stwd/shared`'s generic shape, but
 * the generic lives here so the contract is owned by the core's type vocabulary.
 *
 * App  = the host application a plugin mounts onto (a hono app in @stwd/api).
 * Ctx  = the injected context the core hands the plugin: the shared service
 *        singletons (db, vault, policy engine, audit writer, ...) and the auth
 *        middleware a plugin needs to gate its own routes. injecting these is what
 *        lets a plugin live in its own package WITHOUT importing the core (no
 *        circular dependency: core does not import plugin, plugin does not import
 *        core).
 */
/**
 * The shape of a single policy rule as seen by a contributed evaluator. A plugin
 * owns a rule `type` that the core's closed {@link PolicyType} union does NOT
 * enumerate, so the contribution sees the rule structurally: a string `type`
 * (the plugin's discriminator), an `enabled` flag, and an opaque `config` bag the
 * evaluator interprets. This mirrors the core {@link PolicyRule} fields WITHOUT
 * narrowing `type` to the core union, so a plugin rule type is representable.
 */
export interface ContributedPolicyRule {
  readonly id: string;
  /** the plugin's rule-type discriminator (NOT a member of the core union). */
  readonly type: string;
  readonly enabled: boolean;
  readonly config: Record<string, unknown>;
}

/**
 * The verdict a contributed evaluator returns. Structurally identical to the
 * core `PolicyResult` (policyId/type/passed/reason). Defined here — rather than
 * importing the core `PolicyResult` — so this contract stays self-contained in
 * `@stwd/shared`'s type vocabulary; the policy engine treats a returned value as
 * a `PolicyResult` (the shapes are assignable).
 */
export interface ContributedPolicyResult {
  readonly policyId: string;
  readonly type: string;
  readonly passed: boolean;
  readonly reason?: string;
}

/**
 * A policy-rule contribution a plugin declares so the core's policy engine can
 * evaluate a rule type the plugin owns (e.g. a venue-specific gate) WITHOUT the
 * core importing the plugin.
 *
 * WIRED in Phase 2b. The plugin host registers each contribution into the policy
 * engine's runtime evaluator registry (fail-closed on a `type` that collides with
 * a core rule type or another plugin's). When `evaluatePolicy` meets a rule whose
 * `type` is not one of the core cases, it consults the registry; the contributed
 * `evaluate` runs and its result is used. Core rule evaluation is untouched.
 *
 * GENERIC over the evaluator context `Ctx`: `@stwd/shared` must not import
 * `@stwd/policy-engine` (that would be a dependency cycle — policy-engine imports
 * shared), so the concrete evaluator context type lives in policy-engine and is
 * bound there. A plugin author binds `Ctx` to the policy engine's exported
 * `EvaluatorContext`. Left unbound, `Ctx` defaults to `unknown` so the contract
 * is usable without the policy engine present.
 */
export interface PolicyRuleContribution<Ctx = unknown> {
  /** the policy `type` discriminator this rule contributes (must be unique). */
  readonly type: string;
  /**
   * evaluate a rule of this contributed `type` against the injected context.
   * MUST be pure with respect to money state (it reads the context the engine
   * supplies and returns a verdict; it reserves/commits nothing). may be async.
   * a thrown error is treated by the engine as a fail-closed deny.
   */
  evaluate(
    rule: ContributedPolicyRule,
    ctx: Ctx,
  ): ContributedPolicyResult | Promise<ContributedPolicyResult>;
  /** optional human-readable description, surfaced in diagnostics. */
  readonly description?: string;
}

/**
 * A database-migration source a plugin contributes so its tables/columns are
 * created when the plugin is enabled, WITHOUT the core owning the plugin's
 * schema.
 *
 * PLACEHOLDER (Phase 2c): minimal shape so the contract is real; the host does
 * not yet RUN these (migration ordering, idempotency, and the drizzle journal
 * integration are Phase 2c). Accepted + reported, not executed.
 */
export interface PluginMigrationSource {
  /** a stable id for the plugin's migration namespace. */
  readonly id: string;
}

/**
 * An adapter contribution a plugin registers into the core's adapter registry
 * (mirrors `packages/adapters` categories) so a plugin can supply a real
 * provider integration.
 *
 * PLACEHOLDER (Phase 2d): minimal shape so the contract is real; the host does
 * not yet REGISTER these into the adapter registry (category typing + the
 * fail-closed-in-production resolution are Phase 2d). Accepted + reported, not
 * registered.
 */
export interface AdapterContribution {
  /** the adapter category this contribution targets, e.g. "swap". */
  readonly category: string;
  /** the provider name this contribution registers under. */
  readonly provider: string;
}

export interface StewardPlugin<App = unknown, Ctx = unknown, EvalCtx = unknown> {
  /** stable identifier for the plugin, e.g. "trading". used in logs/diagnostics. */
  readonly name: string;
  /**
   * optional semantic version of the plugin. surfaced in the host's diagnostics
   * so an operator can see which plugin versions a deploy composed.
   */
  readonly version?: string;
  /**
   * names of other plugins that must be registered BEFORE this one. the host
   * topologically orders plugins by this graph and FAILS CLOSED (throws) on a
   * missing or cyclic dependency — a plugin never silently registers against a
   * half-built dependency.
   */
  readonly dependsOn?: readonly string[];
  /**
   * mount the plugin's routes + middleware onto `app`, using the injected `ctx`
   * for shared services and auth gates. may be async (e.g. to lazily resolve a
   * provider). called once, at the composition root, after the core is built.
   *
   * OPTIONAL as of Phase 2: a plugin may contribute ONLY declaratively (via the
   * contribution points below) without mounting any route/middleware. the
   * trading plugin still uses `register` for back-compat.
   */
  register?(app: App, ctx: Ctx): void | Promise<void>;

  // ── declarative contribution points (all optional) ──────────────────────────

  /**
   * webhook event-type names this plugin emits. the host merges these into the
   * runtime registry of valid event types (core union ∪ plugin-declared) so the
   * webhook dispatcher/config validation accepts a plugin's event without the
   * core's closed union having to know about it ahead of time.
   *
   * WIRED in Phase 2a — this is the keystone contribution point proven
   * end-to-end by the trading plugin.
   */
  readonly webhookEvents?: readonly string[];

  /**
   * policy rules this plugin contributes. WIRED in Phase 2b: the host registers
   * each into the policy engine's runtime evaluator registry (fail-closed on a
   * `type` collision with a core rule type or another plugin's). The policy
   * engine then evaluates a rule of a contributed `type` via the contribution's
   * `evaluate`. `EvalCtx` is bound by the concrete app plugin type (in
   * `@stwd/api`) to the policy engine's `EvaluatorContext`.
   */
  readonly policyRules?: readonly PolicyRuleContribution<EvalCtx>[];

  /**
   * database migrations this plugin contributes. TYPED here
   * (`PluginMigrationSource`); execution is DEFERRED to Phase 2c.
   */
  readonly migrations?: PluginMigrationSource;

  /**
   * adapter integrations this plugin contributes. TYPED here
   * (`AdapterContribution`); registration into the adapter registry is DEFERRED
   * to Phase 2d.
   */
  readonly adapters?: readonly AdapterContribution[];
}

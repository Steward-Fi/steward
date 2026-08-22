/**
 * AdapterRegistry — keeps durable stateless providers/factories while resolving
 * selection policy from the current request's immutable runtime environment.
 *
 * Resolution order per category (e.g. "swap"):
 *   1. The env var STEWARD_<CATEGORY>_ADAPTER selects a durable provider
 *      registered via {@link AdapterRegistry.register}, or the built-in mock.
 *   2. Fallback:
 *        - DEV / test (NODE_ENV !== "production"): the built-in MOCK.
 *        - PRODUCTION (NODE_ENV === "production"): a DISABLED adapter whose
 *          operations throw {@link AdapterNotConfiguredError}. This guarantees a
 *          production deploy never silently uses mocks for real money.
 *
 * The only way to use mocks in production is to select `mock` for the current
 * category AND opt in via STEWARD_ALLOW_MOCK_ADAPTERS=true (intended for
 * staging/load tests only).
 */

import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { type BridgeAdapter, MockBridgeAdapter } from "./adapters/bridge.js";
import { type CustodialWalletAdapter, MockCustodialWalletAdapter } from "./adapters/custodial.js";
import { type EarnAdapter, MockEarnAdapter } from "./adapters/earn.js";
import { type ExchangeEmbedAdapter, MockExchangeEmbedAdapter } from "./adapters/exchange.js";
import { type KycAdapter, MockKycAdapter } from "./adapters/kyc.js";
import { MockOfframpAdapter, type OfframpAdapter } from "./adapters/offramp.js";
import { MockOnrampAdapter, type OnrampAdapter } from "./adapters/onramp.js";
import { MockPushAdapter, type PushAdapter } from "./adapters/push.js";
import { MockSparkAdapter, type SparkAdapter } from "./adapters/spark.js";
import { MockSwapAdapter, type SwapAdapter } from "./adapters/swap.js";
import { MockTosAdapter, type TosAdapter } from "./adapters/tos.js";
import { type AdapterCategory, AdapterNotConfiguredError, type BaseAdapter } from "./types.js";

export interface AdapterRegistryOptions {
  /**
   * Fixed environment for isolated registries. The shared singleton resolves
   * from @stwd/shared's request snapshot and falls back to process.env on Bun.
   */
  env?: Record<string, string | undefined>;
}

type CategoryToAdapter = {
  swap: SwapAdapter;
  earn: EarnAdapter;
  onramp: OnrampAdapter;
  offramp: OfframpAdapter;
  kyc: KycAdapter;
  tos: TosAdapter;
  custodial: CustodialWalletAdapter;
  push: PushAdapter;
  bridge: BridgeAdapter;
  spark: SparkAdapter;
  exchange: ExchangeEmbedAdapter;
};

type RegisteredProvider<C extends AdapterCategory = AdapterCategory> =
  | { readonly kind: "instance"; readonly adapter: CategoryToAdapter[C] }
  | { readonly kind: "factory"; readonly createAdapter: () => CategoryToAdapter[C] };

const ALL_CATEGORIES: readonly AdapterCategory[] = [
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
];

function envKey(category: AdapterCategory): string {
  return `STEWARD_${category.toUpperCase()}_ADAPTER`;
}

/**
 * A disabled adapter returned in production when nothing real is configured.
 * Every property access that isn't an introspection field throws. This is the
 * fail-closed sentinel.
 */
function makeDisabledAdapter<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
  const base: BaseAdapter = { category, provider: "disabled", enabled: false };
  return new Proxy(base, {
    get(target, prop, receiver) {
      if (prop === "category" || prop === "provider" || prop === "enabled") {
        return Reflect.get(target, prop, receiver);
      }
      if (prop === "then") return undefined; // not a thenable
      if (typeof prop === "string") {
        // Any operation refuses, fail-closed.
        return () => {
          throw new AdapterNotConfiguredError(category);
        };
      }
      return Reflect.get(target, prop, receiver);
    },
  }) as unknown as CategoryToAdapter[C];
}

const MOCK_FACTORIES: { [C in AdapterCategory]: () => CategoryToAdapter[C] } = {
  swap: () => new MockSwapAdapter(),
  earn: () => new MockEarnAdapter(),
  onramp: () => new MockOnrampAdapter(),
  offramp: () => new MockOfframpAdapter(),
  kyc: () => new MockKycAdapter(),
  tos: () => new MockTosAdapter(),
  custodial: () => new MockCustodialWalletAdapter(),
  push: () => new MockPushAdapter(),
  bridge: () => new MockBridgeAdapter(),
  spark: () => new MockSparkAdapter(),
  exchange: () => new MockExchangeEmbedAdapter(),
};

function makeMockAdapter<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
  return MOCK_FACTORIES[category]();
}

export class AdapterRegistry {
  private readonly env: Readonly<Record<string, string | undefined>> | null;
  // category -> (providerName -> stateless instance or request-authority factory)
  private readonly registered = new Map<AdapterCategory, Map<string, RegisteredProvider>>();
  // Configuration-free implementations may be durable; binding-dependent ones
  // are factories. Stable mock instances preserve their in-memory development
  // behavior without caching the authority decision that made one reachable.
  private readonly mockAdapters = new Map<AdapterCategory, BaseAdapter>();
  private readonly disabledAdapters = new Map<AdapterCategory, BaseAdapter>();

  constructor(options?: AdapterRegistryOptions) {
    this.env = options?.env ? Object.freeze({ ...options.env }) : null;
  }

  private environmentValue(name: string): string | undefined {
    return this.env ? this.env[name] : runtimeEnvironmentValue(name);
  }

  private isProduction(): boolean {
    const nodeEnvironment = this.environmentValue("NODE_ENV")?.trim();
    if (nodeEnvironment === "production") return true;
    // Workers are internet-facing by default. An omitted NODE_ENV binding must
    // never activate Bun's development mocks; only explicit dev/test modes do.
    return (
      this.environmentValue("STEWARD_RUNTIME") === "workers" &&
      nodeEnvironment !== "development" &&
      nodeEnvironment !== "test"
    );
  }

  private allowMocksInProd(): boolean {
    return this.environmentValue("STEWARD_ALLOW_MOCK_ADAPTERS") === "true";
  }

  private mock<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
    const existing = this.mockAdapters.get(category);
    if (existing) return existing as CategoryToAdapter[C];
    const created = makeMockAdapter(category);
    this.mockAdapters.set(category, created);
    return created;
  }

  private disabled<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
    const existing = this.disabledAdapters.get(category);
    if (existing) return existing as CategoryToAdapter[C];
    const created = makeDisabledAdapter(category);
    this.disabledAdapters.set(category, created);
    return created;
  }

  /**
   * Register a concrete (typically real-provider) adapter under a provider name.
   * This is the plug-in point for real integrations.
   */
  register<C extends AdapterCategory>(
    category: C,
    providerName: string,
    adapter: CategoryToAdapter[C],
  ): void {
    let byName = this.registered.get(category);
    if (!byName) {
      byName = new Map();
      this.registered.set(category, byName);
    }
    byName.set(providerName, { kind: "instance", adapter } as RegisteredProvider);
  }

  /**
   * Register a stateless provider factory. The registry invokes it only after
   * the current request selects this provider and never retains the returned
   * adapter. Binding-dependent integrations MUST use this seam so a reused
   * Worker isolate cannot carry an endpoint or credential into another binding
   * generation.
   */
  registerFactory<C extends AdapterCategory>(
    category: C,
    providerName: string,
    createAdapter: () => CategoryToAdapter[C],
  ): void {
    let byName = this.registered.get(category);
    if (!byName) {
      byName = new Map();
      this.registered.set(category, byName);
    }
    byName.set(providerName, { kind: "factory", createAdapter } as RegisteredProvider);
  }

  /**
   * True when an adapter is already registered under `(category, providerName)`.
   * Read-only introspection for callers (e.g. the plugin host) that must refuse
   * to SILENTLY overwrite a live adapter: `register` itself is a plain
   * `Map.set`, so the collision check has to happen before calling it.
   */
  has(category: AdapterCategory, providerName: string): boolean {
    return this.registered.get(category)?.has(providerName) ?? false;
  }

  private instantiate<C extends AdapterCategory>(
    provider: RegisteredProvider<C>,
  ): CategoryToAdapter[C] {
    return provider.kind === "factory" ? provider.createAdapter() : provider.adapter;
  }

  private resolve<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
    // Never cache this authority decision: the same Worker isolate can serve a
    // rotated binding set, and overlapping requests retain distinct ALS-backed
    // snapshots. Provider implementations themselves remain durable above.
    const configured = this.environmentValue(envKey(category))?.trim();
    const byName = this.registered.get(category);

    // 1. Explicit env selection of a registered provider.
    if (configured && configured !== "mock" && byName?.has(configured)) {
      return this.instantiate(byName.get(configured) as RegisteredProvider<C>);
    }

    // 2. Env explicitly asks for "mock".
    if (configured === "mock") {
      if (this.isProduction() && !this.allowMocksInProd()) {
        return this.disabled(category);
      }
      return this.mock(category);
    }

    // 3. Bun development convenience: a sole registered provider needs no env
    // disambiguation. Production requires a current, explicit binding.
    if (!configured && !this.isProduction() && byName && byName.size === 1) {
      const [provider] = byName.values();
      return this.instantiate(provider as RegisteredProvider<C>);
    }

    // 4. Env names an unknown provider -> fail closed everywhere (never silently
    //    fall back to a mock when an operator asked for a specific provider).
    if (configured && configured !== "mock") {
      return this.disabled(category);
    }

    // 5. Nothing configured. DEV -> mock; PROD -> disabled (fail closed). The
    // production mock acknowledgement above is valid only with an exact current
    // `mock` selection; the allow flag alone cannot authorize every category.
    if (this.isProduction()) return this.disabled(category);
    return this.mock(category);
  }

  swap(): SwapAdapter {
    return this.resolve("swap");
  }
  earn(): EarnAdapter {
    return this.resolve("earn");
  }
  onramp(): OnrampAdapter {
    return this.resolve("onramp");
  }
  offramp(): OfframpAdapter {
    return this.resolve("offramp");
  }
  kyc(): KycAdapter {
    return this.resolve("kyc");
  }
  tos(): TosAdapter {
    return this.resolve("tos");
  }
  custodial(): CustodialWalletAdapter {
    return this.resolve("custodial");
  }
  push(): PushAdapter {
    return this.resolve("push");
  }
  bridge(): BridgeAdapter {
    return this.resolve("bridge");
  }
  spark(): SparkAdapter {
    return this.resolve("spark");
  }
  exchange(): ExchangeEmbedAdapter {
    return this.resolve("exchange");
  }

  /** Introspect which provider is resolved per category (for ops/health). */
  describe(): Record<AdapterCategory, { provider: string; enabled: boolean }> {
    const out = {} as Record<AdapterCategory, { provider: string; enabled: boolean }>;
    for (const category of ALL_CATEGORIES) {
      const adapter = this.resolve(category);
      out[category] = { provider: adapter.provider, enabled: adapter.enabled };
    }
    return out;
  }
}

/**
 * Process-wide implementation registry. Selection is request-local under
 * Workers and falls back to process.env under Bun. Tests can still construct an
 * isolated registry with a fixed injected environment.
 */
export const adapterRegistry = new AdapterRegistry();

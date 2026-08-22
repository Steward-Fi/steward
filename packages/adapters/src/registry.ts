/**
 * AdapterRegistry — resolves the configured adapter per category, with a
 * fail-closed default in production.
 *
 * Resolution order per category (e.g. "swap"):
 *   1. A real adapter explicitly registered via {@link AdapterRegistry.register}
 *      (this is where a real provider integration plugs in later).
 *   2. The env var STEWARD_<CATEGORY>_ADAPTER selects a registered named provider.
 *   3. Fallback:
 *        - DEV / test (NODE_ENV !== "production"): the built-in MOCK.
 *        - PRODUCTION (NODE_ENV === "production"): a DISABLED adapter whose
 *          operations throw {@link AdapterNotConfiguredError}. This guarantees a
 *          production deploy never silently uses mocks for real money.
 *
 * The only way to use mocks in production is to opt in explicitly via
 * STEWARD_ALLOW_MOCK_ADAPTERS=true (intended for staging/load tests only).
 */

import { runtimeEnvironmentSnapshot } from "@stwd/shared/runtime-env";
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
  /** Explicit immutable authority. Defaults to the current request snapshot. */
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
  private readonly explicitEnv?: Record<string, string | undefined>;
  // category -> (providerName -> adapter) for explicitly registered real adapters
  private readonly registered = new Map<AdapterCategory, Map<string, BaseAdapter>>();
  private readonly resolved = new Map<string, BaseAdapter>();

  constructor(options?: AdapterRegistryOptions) {
    this.explicitEnv = options?.env ? Object.freeze({ ...options.env }) : undefined;
  }

  private environment(): Readonly<Record<string, string | undefined>> {
    return this.explicitEnv ?? runtimeEnvironmentSnapshot();
  }

  private authorityKey(env: Readonly<Record<string, string | undefined>>): string {
    return JSON.stringify([
      env.NODE_ENV ?? "",
      env.STEWARD_RUNTIME ?? "",
      env.STEWARD_ALLOW_MOCK_ADAPTERS ?? "",
      ...ALL_CATEGORIES.map((category) => env[envKey(category)] ?? ""),
    ]);
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
    byName.set(providerName, adapter);
    // Invalidate any previously-resolved instance for this category.
    this.resolved.clear();
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

  private resolve<C extends AdapterCategory>(category: C): CategoryToAdapter[C] {
    const env = this.environment();
    const cacheKey = `${this.authorityKey(env)}:${category}`;
    const cached = this.resolved.get(cacheKey);
    if (cached) return cached as CategoryToAdapter[C];

    const configured = env[envKey(category)]?.trim();
    const isProduction = env.NODE_ENV === "production" || env.STEWARD_RUNTIME === "workers";
    const allowMocksInProd = env.STEWARD_ALLOW_MOCK_ADAPTERS === "true";
    const byName = this.registered.get(category);

    // 1. Explicit env selection of a registered provider.
    if (configured && configured !== "mock" && byName?.has(configured)) {
      const adapter = byName.get(configured) as CategoryToAdapter[C];
      this.resolved.set(cacheKey, adapter);
      return adapter;
    }

    // 2. Env explicitly asks for "mock".
    if (configured === "mock") {
      if (isProduction && !allowMocksInProd) {
        const disabled = makeDisabledAdapter(category);
        this.resolved.set(cacheKey, disabled);
        return disabled;
      }
      const mock = makeMockAdapter(category);
      this.resolved.set(cacheKey, mock);
      return mock;
    }

    // 3. A single real adapter registered without env disambiguation: use it.
    if (!configured && byName && byName.size === 1) {
      const [adapter] = byName.values();
      this.resolved.set(cacheKey, adapter as CategoryToAdapter[C]);
      return adapter as CategoryToAdapter[C];
    }

    // 4. Env names an unknown provider -> fail closed everywhere (never silently
    //    fall back to a mock when an operator asked for a specific provider).
    if (configured && configured !== "mock") {
      const disabled = makeDisabledAdapter(category);
      this.resolved.set(cacheKey, disabled);
      return disabled;
    }

    // 5. Nothing configured. DEV -> mock; PROD -> disabled (fail closed).
    if (isProduction && !allowMocksInProd) {
      const disabled = makeDisabledAdapter(category);
      this.resolved.set(cacheKey, disabled);
      return disabled;
    }
    const mock = makeMockAdapter(category);
    this.resolved.set(cacheKey, mock);
    return mock;
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
 * Default process-wide registry, resolved from process.env. Routes import this.
 * Tests construct their own {@link AdapterRegistry} with an injected env.
 */
export const adapterRegistry = new AdapterRegistry();

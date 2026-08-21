import { AsyncLocalStorage } from "node:async_hooks";

export type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

const runtimeEnvironmentStorage = new AsyncLocalStorage<RuntimeEnvironment>();

function snapshotRuntimeEnvironment(environment: Record<string, unknown>): RuntimeEnvironment {
  const snapshot: Record<string, string | undefined> = {};
  for (const [name, value] of Object.entries(environment)) {
    if (typeof value === "string") snapshot[name] = value;
  }
  return Object.freeze(snapshot);
}

/** Bind an immutable environment snapshot to one asynchronous request. */
export function withRuntimeEnvironment<T>(
  environment: Record<string, unknown>,
  callback: () => T,
): T {
  return runtimeEnvironmentStorage.run(snapshotRuntimeEnvironment(environment), callback);
}

/** Resolve one setting from the current request snapshot or Bun process. */
export function runtimeEnvironmentValue(name: string): string | undefined {
  const requestEnvironment = runtimeEnvironmentStorage.getStore();
  return requestEnvironment ? requestEnvironment[name] : process.env[name];
}

/** True when runtime-local safety fallbacks must be treated as production posture. */
export function isProductionRuntimeEnvironment(): boolean {
  if (
    runtimeEnvironmentValue("STEWARD_RUNTIME") === "workers" ||
    runtimeEnvironmentValue("CF_PAGES") === "1"
  ) {
    return true;
  }
  const nodeEnvironment = runtimeEnvironmentValue("NODE_ENV");
  return nodeEnvironment !== "development" && nodeEnvironment !== "test";
}

/** Whether trading rate limits may use the bounded, single-process fallback. */
export function allowsMemoryTradingRateLimits(): boolean {
  return (
    !isProductionRuntimeEnvironment() ||
    runtimeEnvironmentValue("STEWARD_ALLOW_MEMORY_TRADING_RATE_LIMITS") === "true"
  );
}

/** Whether readiness must require Redis for the enabled trading plugin. */
export function tradingRateLimitRedisRequired(tradingEnabled: boolean): boolean {
  return tradingEnabled && isProductionRuntimeEnvironment() && !allowsMemoryTradingRateLimits();
}

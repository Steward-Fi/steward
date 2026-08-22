import { AsyncLocalStorage } from "node:async_hooks";

export type RuntimeEnvironment = Readonly<Record<string, string | undefined>>;

interface RuntimeEnvironmentContext {
  readonly environment: RuntimeEnvironment;
  readonly identity: object;
}

const runtimeEnvironmentStorage = new AsyncLocalStorage<RuntimeEnvironmentContext>();

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
  return runtimeEnvironmentStorage.run(
    {
      environment: snapshotRuntimeEnvironment(environment),
      identity: Object.freeze({}),
    },
    callback,
  );
}

/** Resolve one setting from the current request snapshot or Bun process. */
export function runtimeEnvironmentValue(name: string): string | undefined {
  const context = runtimeEnvironmentStorage.getStore();
  return context ? context.environment[name] : process.env[name];
}

/**
 * Return an opaque identity for the active request environment.
 *
 * Callers may use this object as a WeakMap key for request-local memoization.
 * The environment values themselves deliberately remain hidden behind the
 * `object` return type: cache identity must never be derived from, serialize,
 * or expose secret binding values. Outside an explicitly bound request there
 * is no safe generation identity, so callers must not reuse authority-bearing
 * instances across calls.
 */
export function runtimeEnvironmentIdentity(): object | undefined {
  return runtimeEnvironmentStorage.getStore()?.identity;
}

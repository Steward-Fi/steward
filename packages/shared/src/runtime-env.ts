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

/**
 * Resolve the complete immutable environment authority for the current unit of
 * work. Bun callers receive a frozen snapshot of process.env; Worker callers
 * receive the snapshot bound by withRuntimeEnvironment. Consumers that need to
 * enumerate prefixed settings must use this instead of Object.keys(process.env)
 * so an overlapping Worker request cannot replace their authority mid-read.
 */
export function runtimeEnvironmentSnapshot(): RuntimeEnvironment {
  const requestEnvironment = runtimeEnvironmentStorage.getStore();
  return requestEnvironment ?? snapshotRuntimeEnvironment(process.env);
}

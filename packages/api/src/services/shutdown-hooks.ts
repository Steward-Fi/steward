type ShutdownHook = () => void | Promise<void>;
const hooks: ShutdownHook[] = [];

/** Register durability work that must finish before the API closes its database. */
export function registerShutdownHook(hook: ShutdownHook): void {
  hooks.push(hook);
}

export async function runShutdownHooks(): Promise<void> {
  const pending = hooks.splice(0);
  for (const hook of pending) await hook();
}

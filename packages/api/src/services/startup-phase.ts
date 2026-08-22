import { redactedThrownDiagnostics } from "@stwd/shared";

function positiveMilliseconds(name: string, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

export function startupPhaseTimeoutMs(): number {
  return positiveMilliseconds("STEWARD_STARTUP_PHASE_TIMEOUT_MS", 60_000);
}

export function bootTimeoutMs(): number {
  return positiveMilliseconds("STEWARD_BOOT_TIMEOUT_MS", 240_000);
}

export function migrationPhaseTimeoutMs(): number {
  return positiveMilliseconds("STEWARD_MIGRATION_OVERALL_TIMEOUT_MS", 180_000) + 5_000;
}

export async function runStartupPhase<T>(
  name: string,
  task: () => T | Promise<T>,
  timeoutMs = startupPhaseTimeoutMs(),
): Promise<T> {
  const startedAt = Date.now();
  console.log(`[steward:start] phase=${name} state=begin`);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`startup phase ${name} exceeded ${timeoutMs}ms`)),
        timeoutMs,
      );
    });
    const result = await Promise.race([Promise.resolve().then(task), timeout]);
    console.log(
      `[steward:start] phase=${name} state=complete durationMs=${Date.now() - startedAt}`,
    );
    return result;
  } catch (error) {
    console.error(
      `[steward:start] phase=${name} state=failed durationMs=${Date.now() - startedAt}`,
      redactedThrownDiagnostics(error),
    );
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export function installBootDeadline(onTimeout: () => void): () => void {
  const timeoutMs = bootTimeoutMs();
  const timer = setTimeout(() => {
    console.error(`[steward:start] phase=boot state=failed durationMs=${timeoutMs}`);
    onTimeout();
  }, timeoutMs);
  return () => clearTimeout(timer);
}

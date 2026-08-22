import { redactedThrownDiagnostics } from "@stwd/shared";

export const STARTUP_PHASES = [
  "compose",
  "rls",
  "redis",
  "auth-stores",
  "schedulers",
  "custody",
] as const;

export type StartupPhase = (typeof STARTUP_PHASES)[number];

const DEFAULT_STARTUP_PHASE_TIMEOUT_MS = 30_000;

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`[steward:start] ${name} must be a positive integer`);
  }
  return parsed;
}

export function resolveStartupPhaseTimeoutMs(
  phase: StartupPhase,
  env: Record<string, string | undefined> = process.env,
): number {
  const phaseKey = `STEWARD_STARTUP_${phase.replaceAll("-", "_").toUpperCase()}_TIMEOUT_MS`;
  const defaultMs = positiveInteger(
    env.STEWARD_STARTUP_PHASE_TIMEOUT_MS,
    DEFAULT_STARTUP_PHASE_TIMEOUT_MS,
    "STEWARD_STARTUP_PHASE_TIMEOUT_MS",
  );
  return positiveInteger(env[phaseKey], defaultMs, phaseKey);
}

export interface StartupPhaseEvent {
  phase: StartupPhase;
  state: "started" | "completed" | "failed";
  timeoutMs: number;
  elapsedMs?: number;
  diagnostic?: ReturnType<typeof redactedThrownDiagnostics>;
}

/**
 * Bound one pre-listen startup phase. A timeout is terminal: index.ts does not
 * catch it, so Bun exits instead of leaving a live-but-unlistening container.
 */
export async function runStartupPhase<T>(
  phase: StartupPhase,
  operation: () => T | Promise<T>,
  options: {
    env?: Record<string, string | undefined>;
    emit?: (event: StartupPhaseEvent) => void;
  } = {},
): Promise<T> {
  const timeoutMs = resolveStartupPhaseTimeoutMs(phase, options.env);
  const startedAt = Date.now();
  const emit =
    options.emit ??
    ((event: StartupPhaseEvent) => {
      const detail = event.state === "failed" ? ` ${JSON.stringify(event.diagnostic)}` : "";
      const elapsed = event.elapsedMs === undefined ? "" : ` elapsedMs=${event.elapsedMs}`;
      const message =
        `[steward:start] phase=${event.phase} state=${event.state} timeoutMs=${event.timeoutMs}` +
        elapsed +
        detail;
      if (event.state === "failed") console.error(message);
      else console.log(message);
    });
  emit({ phase, state: "started", timeoutMs });

  let timer: ReturnType<typeof setTimeout> | undefined;
  let timedOut = false;
  try {
    const result = await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          timedOut = true;
          reject(new Error(`startup phase "${phase}" exceeded ${timeoutMs}ms`));
        }, timeoutMs);
      }),
    ]);
    emit({ phase, state: "completed", timeoutMs, elapsedMs: Date.now() - startedAt });
    return result;
  } catch (error) {
    emit({
      phase,
      state: "failed",
      timeoutMs,
      elapsedMs: Date.now() - startedAt,
      diagnostic: redactedThrownDiagnostics(error),
    });
    // Bun prints uncaught top-level-await errors. Never rethrow a provider or
    // driver-controlled message after recording its redacted classification.
    if (timedOut) throw error;
    throw new Error(`startup phase "${phase}" failed`);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

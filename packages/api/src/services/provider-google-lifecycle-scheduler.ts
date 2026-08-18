import { SecretVault } from "@stwd/vault";
import {
  resolveGoogleConnectConfig,
  runGoogleCredentialLifecycleSweep,
} from "./provider-google-connect";

const DEFAULT_INTERVAL_MS = 15_000;
const MAX_INTERVAL_MS = 60_000;

export interface GoogleCredentialLifecycleSchedulerHealth {
  enabled: boolean;
  inFlight: boolean;
  lastStartedAt: number | null;
  lastSucceededAt: number | null;
  lastFailedAt: number | null;
  lastError: string | null;
}

const health: GoogleCredentialLifecycleSchedulerHealth = {
  enabled: false,
  inFlight: false,
  lastStartedAt: null,
  lastSucceededAt: null,
  lastFailedAt: null,
  lastError: null,
};

export function getGoogleCredentialLifecycleSchedulerHealth(): GoogleCredentialLifecycleSchedulerHealth {
  return { ...health };
}

function intervalMs(): number {
  const raw = process.env.STEWARD_GOOGLE_LIFECYCLE_SWEEP_INTERVAL_MS;
  if (raw === undefined) return DEFAULT_INTERVAL_MS;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1_000 || parsed > MAX_INTERVAL_MS) {
    throw new Error(
      `STEWARD_GOOGLE_LIFECYCLE_SWEEP_INTERVAL_MS must be between 1000 and ${MAX_INTERVAL_MS}`,
    );
  }
  return parsed;
}

async function defaultSweep() {
  const { MASTER_PASSWORD } = await import("./context");
  return runGoogleCredentialLifecycleSweep({
    vault: new SecretVault(MASTER_PASSWORD),
    config: resolveGoogleConnectConfig(),
  });
}

/** Start the immediate and periodic bounded Google OAuth lifecycle recovery. */
export function startGoogleCredentialLifecycleScheduler(options?: {
  intervalMs?: number;
  sweep?: typeof defaultSweep;
}): () => void {
  if (process.env.STEWARD_GOOGLE_LIFECYCLE_SWEEPER === "false") {
    Object.assign(health, { enabled: false, lastError: "scheduler disabled" });
    return () => {};
  }
  const sweep = options?.sweep ?? defaultSweep;
  const every = options?.intervalMs ?? intervalMs();
  if (!Number.isSafeInteger(every) || every < 1_000 || every > MAX_INTERVAL_MS) {
    throw new Error(
      `Google lifecycle scheduler interval must be between 1000 and ${MAX_INTERVAL_MS}`,
    );
  }
  Object.assign(health, {
    enabled: true,
    inFlight: false,
    lastStartedAt: null,
    lastSucceededAt: null,
    lastFailedAt: null,
    lastError: null,
  });
  let stopped = false;
  let active: Promise<void> | undefined;
  const tick = () => {
    if (stopped || active) return;
    health.inFlight = true;
    health.lastStartedAt = Date.now();
    active = sweep()
      .then((result) => {
        health.lastSucceededAt = Date.now();
        health.lastError =
          result.needsAttention > 0 || result.failed > 0
            ? `recovery left ${result.needsAttention + result.failed} lifecycle(s) unresolved`
            : null;
      })
      .catch((error) => {
        health.lastFailedAt = Date.now();
        health.lastError = error instanceof Error ? error.message : "unknown sweep failure";
        console.error("[google-lifecycle] sweep failed:", error);
      })
      .finally(() => {
        health.inFlight = false;
        active = undefined;
      });
  };
  const timer = setInterval(tick, every);
  timer.unref?.();
  tick();
  return () => {
    stopped = true;
    clearInterval(timer);
    health.enabled = false;
  };
}

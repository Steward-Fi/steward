import { redactedThrownDiagnostics } from "@stwd/shared";

const DEFAULT_INTERVAL_MS = 15_000;
const MAX_INTERVAL_MS = 15_000;
const HEALTH_STALE_AFTER_MS = MAX_INTERVAL_MS * 3;

export interface UpstreamCredentialLeaseSchedulerHealth {
  ok: boolean;
  enabled: boolean;
  inFlight: boolean;
  lastStartedAt: number | null;
  lastSucceededAt: number | null;
  lastFailedAt: number | null;
  lastError: string | null;
}

const schedulerHealth: Omit<UpstreamCredentialLeaseSchedulerHealth, "ok"> = {
  enabled: false,
  inFlight: false,
  lastStartedAt: null,
  lastSucceededAt: null,
  lastFailedAt: null,
  lastError: null,
};
let unresolvedRecoveryLatched = false;

export function getUpstreamCredentialLeaseSchedulerHealth(
  now = Date.now(),
): UpstreamCredentialLeaseSchedulerHealth {
  const lastSuccess = schedulerHealth.lastSucceededAt;
  const latestAttemptSucceeded =
    lastSuccess !== null &&
    (schedulerHealth.lastFailedAt === null || lastSuccess >= schedulerHealth.lastFailedAt);
  return {
    ...schedulerHealth,
    ok:
      schedulerHealth.enabled &&
      latestAttemptSucceeded &&
      lastSuccess !== null &&
      now - lastSuccess <= HEALTH_STALE_AFTER_MS,
  };
}

export async function runUpstreamCredentialLeaseSweep() {
  const { GitHubAppInstallationTokenIssuer, recoverAllInterruptedUpstreamCredentialLeases } =
    await import("@stwd/plugin-capabilities");
  const { buildPluginContext } = await import("../plugin");
  const ctx = buildPluginContext();
  if (!ctx.exerciseCredentialLeaseToken) {
    throw new Error("credential lease recovery is not configured");
  }
  return recoverAllInterruptedUpstreamCredentialLeases({
    db: ctx.db,
    issuer: new GitHubAppInstallationTokenIssuer(),
    exerciseToken: ctx.exerciseCredentialLeaseToken,
    auditedTransaction: ctx.withTenantAuditedTransaction,
    withDatabaseDeadline: ctx.withCredentialLeaseDatabaseDeadline,
  });
}

function configuredInterval(): number {
  if (process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS === undefined) {
    return DEFAULT_INTERVAL_MS;
  }
  const parsed = Number(process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS);
  if (!Number.isSafeInteger(parsed) || parsed < 1_000 || parsed > MAX_INTERVAL_MS) {
    throw new Error(
      `STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS must be between 1000 and ${MAX_INTERVAL_MS}`,
    );
  }
  return parsed;
}

/**
 * Starts an immediate and periodic all-tenant lease lifecycle sweep. The
 * dynamic, literal import keeps the lean/library graph free of the optional
 * plugin while still making the long-lived server autonomous. The returned
 * disposer stops future ticks and is wired into graceful shutdown by index.ts.
 */
export async function startUpstreamCredentialLeaseScheduler(options?: {
  intervalMs?: number;
  sweep?: () => Promise<{
    unknown: number;
    revoked: number;
    attention: number;
    expired: number;
    remaining?: boolean;
  }>;
}): Promise<() => Promise<void>> {
  if (process.env.STEWARD_UPSTREAM_LEASE_SWEEPER === "false") {
    Object.assign(schedulerHealth, {
      enabled: false,
      inFlight: false,
      lastError: "credential lease sweeper is disabled",
    });
    return async () => {};
  }
  const sweep = options?.sweep ?? runUpstreamCredentialLeaseSweep;
  Object.assign(schedulerHealth, {
    enabled: true,
    inFlight: false,
    lastStartedAt: null,
    lastSucceededAt: null,
    lastFailedAt: null,
    lastError: null,
  });
  unresolvedRecoveryLatched = false;
  let active: Promise<void> | undefined;
  let stopped = false;
  let rerunRequested = false;
  const tick = () => {
    if (stopped) return;
    if (active) {
      rerunRequested = true;
      return;
    }
    schedulerHealth.inFlight = true;
    schedulerHealth.lastStartedAt = Date.now();
    active = sweep()
      .then((result) => {
        const unresolved = result.unknown + result.attention;
        if (unresolved > 0) {
          unresolvedRecoveryLatched = true;
          schedulerHealth.lastFailedAt = Date.now();
          schedulerHealth.lastError =
            `credential lease recovery left ${unresolved} lease(s) unresolved; ` +
            "operator verification and process restart are required";
        } else if (!unresolvedRecoveryLatched) {
          // An unresolved result is deliberately latched until restart. A later
          // empty page cannot prove that the original lease was repaired.
          schedulerHealth.lastSucceededAt = Date.now();
          schedulerHealth.lastError = null;
        }
        rerunRequested ||= result.remaining === true;
        const changed = result.unknown + result.revoked + result.attention + result.expired;
        if (changed > 0) console.log(`[upstream-leases] reconciled ${changed} lease(s)`);
      })
      .catch((error) => {
        schedulerHealth.lastFailedAt = Date.now();
        schedulerHealth.lastError = "credential lease recovery failed";
        console.error("[upstream-leases] sweep failed", redactedThrownDiagnostics(error));
      })
      .finally(() => {
        schedulerHealth.inFlight = false;
        active = undefined;
        if (rerunRequested && !stopped) {
          rerunRequested = false;
          queueMicrotask(tick);
        }
      });
  };
  const timer = setInterval(tick, options?.intervalMs ?? configuredInterval());
  timer.unref?.();
  tick();
  return async () => {
    stopped = true;
    clearInterval(timer);
    await active;
    schedulerHealth.enabled = false;
    schedulerHealth.inFlight = false;
  };
}

import { buildPluginContext } from "../plugin";

const DEFAULT_INTERVAL_MS = 15_000;
const MAX_INTERVAL_MS = 15_000;

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
  if (process.env.STEWARD_UPSTREAM_LEASE_SWEEPER === "false") return async () => {};
  let sweep = options?.sweep;
  if (!sweep) {
    const { GitHubAppInstallationTokenIssuer, recoverAllInterruptedUpstreamCredentialLeases } =
      await import("@stwd/plugin-capabilities");
    const ctx = buildPluginContext();
    if (!ctx.exerciseCredentialLeaseToken) {
      throw new Error("credential lease recovery is not configured");
    }
    const issuer = new GitHubAppInstallationTokenIssuer();
    sweep = () =>
      recoverAllInterruptedUpstreamCredentialLeases({
        db: ctx.db,
        issuer,
        exerciseToken: ctx.exerciseCredentialLeaseToken,
        auditedTransaction: ctx.withTenantAuditedTransaction,
      });
  }
  let active: Promise<void> | undefined;
  let stopped = false;
  let rerunRequested = false;
  const tick = () => {
    if (stopped) return;
    if (active) {
      rerunRequested = true;
      return;
    }
    active = sweep()
      .then((result) => {
        rerunRequested ||= result.remaining === true;
        const changed = result.unknown + result.revoked + result.attention + result.expired;
        if (changed > 0) console.log(`[upstream-leases] reconciled ${changed} lease(s)`);
      })
      .catch((error) => console.error("[upstream-leases] sweep failed:", error))
      .finally(() => {
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
  };
}

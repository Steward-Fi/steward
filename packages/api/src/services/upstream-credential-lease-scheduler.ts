import { buildPluginContext } from "../plugin";

const DEFAULT_INTERVAL_MS = 15_000;

function configuredInterval(): number {
  const parsed = Number(process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS);
  return Number.isSafeInteger(parsed) && parsed >= 1_000 ? parsed : DEFAULT_INTERVAL_MS;
}

/**
 * Starts an immediate and periodic all-tenant lease lifecycle sweep. The
 * dynamic, literal import keeps the lean/library graph free of the optional
 * plugin while still making the long-lived server autonomous. The returned
 * disposer stops future ticks and is wired into graceful shutdown by index.ts.
 */
export async function startUpstreamCredentialLeaseScheduler(options?: {
  intervalMs?: number;
  sweep?: (afterTenantId?: string) => Promise<{
    unknown: number;
    revoked: number;
    attention: number;
    expired: number;
    nextTenantId?: string | null;
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
    sweep = (afterTenantId) =>
      recoverAllInterruptedUpstreamCredentialLeases({
        db: ctx.db,
        issuer,
        exerciseToken: ctx.exerciseCredentialLeaseToken,
        auditedTransaction: ctx.withTenantAuditedTransaction,
        afterTenantId,
      });
  }
  let active: Promise<void> | undefined;
  let stopped = false;
  let afterTenantId: string | undefined;
  const tick = () => {
    if (active || stopped) return;
    active = sweep(afterTenantId)
      .then((result) => {
        afterTenantId = result.nextTenantId ?? undefined;
        const changed = result.unknown + result.revoked + result.attention + result.expired;
        if (changed > 0) console.log(`[upstream-leases] reconciled ${changed} lease(s)`);
      })
      .catch((error) => console.error("[upstream-leases] sweep failed:", error))
      .finally(() => {
        active = undefined;
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

import { redactedThrownDiagnostics } from "@stwd/shared";
import { providerActionService } from "./provider-action-service";
import { internalJobTenantIds, runInternalJobForTenant } from "./tenant-job";

const DEFAULT_INTERVAL_MS = 15_000;

export interface ProviderActionRecoverySweepResult {
  auditsDelivered: number;
  reservationsReconciled: number;
  failures: Array<{
    tenantId: string;
    domain: "required-audit" | "reservation";
    error: unknown;
  }>;
}

export interface ProviderActionRecoveryService {
  recoverRequiredAuditOutbox(tenantId: string): Promise<number>;
  reconcilePolicyReservations(tenantId: string): Promise<number>;
}

/** Run both independent recovery domains once for one tenant. */
export async function recoverProviderActionTenant(
  tenantId: string,
  service: ProviderActionRecoveryService = providerActionService,
): Promise<ProviderActionRecoverySweepResult> {
  let auditsDelivered = 0;
  let reservationsReconciled = 0;
  const failures: ProviderActionRecoverySweepResult["failures"] = [];
  try {
    auditsDelivered = await service.recoverRequiredAuditOutbox(tenantId);
  } catch (error) {
    failures.push({ tenantId, domain: "required-audit", error });
  }
  try {
    reservationsReconciled = await service.reconcilePolicyReservations(tenantId);
  } catch (error) {
    failures.push({ tenantId, domain: "reservation", error });
  }
  return { auditsDelivered, reservationsReconciled, failures };
}

function configuredInterval(): number {
  const parsed = Number(process.env.STEWARD_PROVIDER_RESERVATION_SWEEP_INTERVAL_MS);
  return Number.isSafeInteger(parsed) && parsed >= 1_000 ? parsed : DEFAULT_INTERVAL_MS;
}

/** Drain both C2 recovery domains once for every tenant. */
export async function runProviderActionRecoverySweep(): Promise<ProviderActionRecoverySweepResult> {
  const total: ProviderActionRecoverySweepResult = {
    auditsDelivered: 0,
    reservationsReconciled: 0,
    failures: [],
  };
  for (const tenantId of await internalJobTenantIds()) {
    // Keep the domains in distinct tenant transactions. A signer rollback must
    // not poison reservation recovery, and Redis latency must not extend the
    // required-audit claim/append transaction or its row locks.
    const value = await recoverProviderActionTenant(tenantId, {
      recoverRequiredAuditOutbox: () =>
        runInternalJobForTenant(tenantId, "provider-required-audit-recovery", () =>
          providerActionService.recoverRequiredAuditOutbox(tenantId),
        ),
      reconcilePolicyReservations: () =>
        runInternalJobForTenant(tenantId, "provider-reservation-reconciliation", () =>
          providerActionService.reconcilePolicyReservations(tenantId),
        ),
    });
    total.auditsDelivered += value.auditsDelivered;
    total.reservationsReconciled += value.reservationsReconciled;
    total.failures.push(...value.failures);
  }
  return total;
}

/**
 * Starts the autonomous C2 audit-outbox and reservation reconciler. The
 * immediate startup pass closes both crash-before-drain gaps; later passes
 * retry transient signer, Redis and DB failures independently.
 */
export function startProviderReservationReconciliationScheduler(options?: {
  intervalMs?: number;
  sweep?: () => Promise<ProviderActionRecoverySweepResult>;
}): () => void {
  if (process.env.STEWARD_PROVIDER_RESERVATION_SWEEPER === "false") return () => {};
  const sweep = options?.sweep ?? runProviderActionRecoverySweep;
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void sweep()
      .then((result) => {
        if (result.auditsDelivered > 0) {
          console.log(`[provider-actions] delivered ${result.auditsDelivered} required audit(s)`);
        }
        if (result.reservationsReconciled > 0) {
          console.log(
            `[provider-reservations] reconciled ${result.reservationsReconciled} reservation(s)`,
          );
        }
        for (const failure of result.failures) {
          console.error(
            `[provider-actions] ${failure.domain} recovery failed tenant=${failure.tenantId}`,
            redactedThrownDiagnostics(failure.error),
          );
        }
      })
      .catch((error) =>
        console.error("[provider-actions] recovery sweep failed", redactedThrownDiagnostics(error)),
      )
      .finally(() => {
        running = false;
      });
  };
  const timer = setInterval(tick, options?.intervalMs ?? configuredInterval());
  timer.unref?.();
  tick();
  return () => clearInterval(timer);
}

import { providerActionService } from "./provider-action-service";

const DEFAULT_INTERVAL_MS = 15_000;

function configuredInterval(): number {
  const parsed = Number(process.env.STEWARD_PROVIDER_RESERVATION_SWEEP_INTERVAL_MS);
  return Number.isSafeInteger(parsed) && parsed >= 1_000 ? parsed : DEFAULT_INTERVAL_MS;
}

/**
 * Starts the autonomous C2 reservation reconciler. The immediate startup pass
 * closes the crash-before-drain gap; later passes retry transient Redis/DB
 * failures. The service records attempts, backoff, the last error and a
 * needs_attention state after sustained failure, so recovery never disappears
 * into an unobservable catch.
 */
export function startProviderReservationReconciliationScheduler(): () => void {
  if (process.env.STEWARD_PROVIDER_RESERVATION_SWEEPER === "false") return () => {};
  let running = false;
  const tick = () => {
    if (running) return;
    running = true;
    void providerActionService
      .reconcilePolicyReservations()
      .then((count) => {
        if (count > 0) console.log(`[provider-reservations] reconciled ${count} reservation(s)`);
      })
      .catch((error) => console.error("[provider-reservations] sweep failed:", error))
      .finally(() => {
        running = false;
      });
  };
  const timer = setInterval(tick, configuredInterval());
  timer.unref?.();
  tick();
  return () => clearInterval(timer);
}

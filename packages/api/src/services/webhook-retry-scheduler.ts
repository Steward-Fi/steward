import { redactedThrownDiagnostics } from "@stwd/shared";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
import { PersistentQueue } from "@stwd/webhooks";
import { runInternalJobForEachTenant } from "./tenant-job";

const DEFAULT_WEBHOOK_RETRY_INTERVAL_MS = 30_000;
const DEFAULT_WEBHOOK_RETRY_BATCH_SIZE = 50;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function startWebhookRetryScheduler(): () => void {
  if (runtimeEnvironmentValue("STEWARD_WEBHOOK_RETRY_WORKER") === "false") {
    console.log("[webhooks] Retry scheduler disabled by STEWARD_WEBHOOK_RETRY_WORKER=false");
    return () => {};
  }

  const intervalMs = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_WEBHOOK_RETRY_INTERVAL_MS"),
    DEFAULT_WEBHOOK_RETRY_INTERVAL_MS,
  );
  const batchSize = parsePositiveInt(
    runtimeEnvironmentValue("STEWARD_WEBHOOK_RETRY_BATCH_SIZE"),
    DEFAULT_WEBHOOK_RETRY_BATCH_SIZE,
  );
  const queue = new PersistentQueue(undefined, { batchSize });
  let running = false;

  const tick = () => {
    if (running) return;
    running = true;
    void runInternalJobForEachTenant("webhook-delivery-retry", () => queue.processQueue())
      .then((tenantResults) => {
        const results = tenantResults.flatMap(({ value }) => value);
        const failures = results.filter((result) => !result.success).length;
        if (results.length > 0) {
          console.log(
            `[webhooks] Processed ${results.length} queued delivery retry(s), ${failures} failed`,
          );
        }
      })
      .catch((error) => {
        console.error("[webhooks] Retry scheduler tick failed", redactedThrownDiagnostics(error));
      })
      .finally(() => {
        running = false;
      });
  };

  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  tick();

  return () => {
    clearInterval(timer);
  };
}

import { redactedThrownDiagnostics } from "@stwd/shared";
import { SecretVault } from "@stwd/vault";
import {
  resolveXConnectConfig,
  runXCredentialLifecycleSweep,
  type XCredentialLifecycleSweepResult,
} from "./provider-x-connect";
import { runInternalJobForEachTenant } from "./tenant-job";

const DEFAULT_INTERVAL_MS = 60_000;
const MIN_INTERVAL_MS = 5_000;
const MAX_INTERVAL_MS = 5 * 60_000;

function configuredInterval(): number {
  const raw = process.env.STEWARD_X_LIFECYCLE_SWEEP_INTERVAL_MS;
  if (raw === undefined) return DEFAULT_INTERVAL_MS;
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < MIN_INTERVAL_MS || parsed > MAX_INTERVAL_MS) {
    throw new Error(
      `STEWARD_X_LIFECYCLE_SWEEP_INTERVAL_MS must be between ${MIN_INTERVAL_MS} and ${MAX_INTERVAL_MS}`,
    );
  }
  return parsed;
}

export async function runXCredentialLifecycleRecoverySweep(): Promise<XCredentialLifecycleSweepResult> {
  const password = process.env.STEWARD_MASTER_PASSWORD?.trim();
  if (!password) throw new Error("STEWARD_MASTER_PASSWORD is required for X OAuth recovery");
  const results = await runInternalJobForEachTenant("x-credential-lifecycle-sweep", () =>
    runXCredentialLifecycleSweep({
      vault: new SecretVault(password),
      config: resolveXConnectConfig(),
    }),
  );
  return results.reduce<XCredentialLifecycleSweepResult>(
    (total, { value }) => ({
      processed: total.processed + value.processed,
      adopted: total.adopted + value.adopted,
      revoked: total.revoked + value.revoked,
      attention: total.attention + value.attention,
      remaining: total.remaining || value.remaining,
    }),
    { processed: 0, adopted: 0, revoked: 0, attention: 0, remaining: false },
  );
}

export function startXCredentialLifecycleScheduler(options?: {
  intervalMs?: number;
  sweep?: () => Promise<XCredentialLifecycleSweepResult>;
}): () => Promise<void> {
  const sweep = options?.sweep ?? runXCredentialLifecycleRecoverySweep;
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
        rerunRequested ||= result.remaining;
        if (result.processed > 0) {
          console.log(
            `[provider-x] reconciled ${result.processed} lifecycle(s): ` +
              `${result.adopted} adopted, ${result.revoked} revoked, ${result.attention} attention`,
          );
        }
      })
      .catch((error) => {
        const classified = redactedThrownDiagnostics(error);
        console.error("[provider-x] lifecycle sweep failed", {
          errorClass: classified.errorClass,
          errorCode: classified.errorCode,
        });
      })
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

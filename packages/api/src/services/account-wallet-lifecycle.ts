import {
  agents,
  digitalAssetAccountWalletLifecycles,
  digitalAssetAccountWallets,
  getDb,
} from "@stwd/db";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { and, asc, eq, inArray, lte, sql } from "drizzle-orm";
import { withTenantAuditedTransaction } from "./audit";
import { runInternalJobForEachTenant } from "./tenant-job";

const DEFAULT_SWEEP_INTERVAL_MS = 15_000;
const DEFAULT_SWEEP_BATCH_SIZE = 25;
const RECOVERY_LEASE_MS = 2 * 60_000;
const ATTENTION_RETRY_MS = 15 * 60_000;

type Db = ReturnType<typeof getDb>;

export type StagedAccountWallet = {
  lifecycleId: string;
  tenantId: string;
  accountId: string;
  walletAgentId: string;
  ownerToken: string;
};

export type AccountWalletLifecycleRecoveryResult = {
  processed: number;
  adopted: number;
  retired: number;
  attention: number;
  remaining: boolean;
};

/** Canonical runtime predicate used anywhere this lifecycle would issue PG-only SQL. */
export function accountWalletLifecycleUsesPglite(): boolean {
  return process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true";
}

export async function lockAccountMutation(tx: Db, tenantId: string, accountId: string) {
  if (accountWalletLifecycleUsesPglite()) return;
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended(${`steward_account_${tenantId}_${accountId}`}, 0))`,
  );
}

function lifecycleAudit(input: {
  tenantId: string;
  action: string;
  walletAgentId: string;
  lifecycleId: string;
  outcome?: string;
}) {
  return {
    tenantId: input.tenantId,
    actorType: "system" as const,
    actorId: "account-wallet-lifecycle-recovery",
    action: input.action,
    resourceType: "wallet",
    resourceId: input.walletAgentId,
    metadata: { lifecycleId: input.lifecycleId, outcome: input.outcome },
  };
}

async function reconcileLifecycle(input: {
  tenantId: string;
  lifecycleId: string;
  expectedOwnerToken?: string;
  allowFreshLease?: boolean;
  now: Date;
}): Promise<"adopted" | "retired" | "attention" | "skipped"> {
  return withTenantAuditedTransaction(input.tenantId, async (txRaw, appendRequiredAudit) => {
    const tx = txRaw as Db;
    const [current] = await tx
      .select()
      .from(digitalAssetAccountWalletLifecycles)
      .where(
        and(
          eq(digitalAssetAccountWalletLifecycles.tenantId, input.tenantId),
          eq(digitalAssetAccountWalletLifecycles.id, input.lifecycleId),
        ),
      )
      .limit(1)
      .for("update");
    if (!current || current.state === "adopted" || current.state === "retired") return "skipped";
    if (input.expectedOwnerToken && current.ownerToken !== input.expectedOwnerToken)
      return "skipped";
    if (!input.allowFreshLease && current.leaseExpiresAt.getTime() > input.now.getTime()) {
      return "skipped";
    }

    await lockAccountMutation(tx, input.tenantId, current.walletAgentId);
    const [membership] = await tx
      .select({ id: digitalAssetAccountWallets.id })
      .from(digitalAssetAccountWallets)
      .where(
        and(
          eq(digitalAssetAccountWallets.tenantId, input.tenantId),
          eq(digitalAssetAccountWallets.walletAgentId, current.walletAgentId),
        ),
      )
      .limit(1);
    if (membership) {
      await tx
        .update(digitalAssetAccountWalletLifecycles)
        .set({ state: "adopted", adoptedAt: input.now, updatedAt: input.now, lastError: null })
        .where(eq(digitalAssetAccountWalletLifecycles.id, current.id));
      await appendRequiredAudit(
        lifecycleAudit({
          tenantId: input.tenantId,
          action: "account.wallet_provision.recover",
          walletAgentId: current.walletAgentId,
          lifecycleId: current.id,
          outcome: "adopted",
        }),
      );
      return "adopted";
    }

    const recoveryToken = crypto.randomUUID();
    const [claimed] = await tx
      .update(digitalAssetAccountWalletLifecycles)
      .set({
        state: "retiring",
        ownerToken: recoveryToken,
        leaseExpiresAt: new Date(input.now.getTime() + RECOVERY_LEASE_MS),
        updatedAt: input.now,
      })
      .where(
        and(
          eq(digitalAssetAccountWalletLifecycles.id, current.id),
          eq(digitalAssetAccountWalletLifecycles.ownerToken, current.ownerToken),
          inArray(digitalAssetAccountWalletLifecycles.state, [
            "staging",
            "provisioned",
            "recoverable",
            "retiring",
          ]),
        ),
      )
      .returning({ id: digitalAssetAccountWalletLifecycles.id });
    if (!claimed) return "skipped";

    const [authority] = await tx
      .select({ platformId: agents.platformId })
      .from(agents)
      .where(and(eq(agents.tenantId, input.tenantId), eq(agents.id, current.walletAgentId)))
      .limit(1);
    if (authority && authority.platformId !== `account-provision:${current.id}`) {
      await tx
        .update(digitalAssetAccountWalletLifecycles)
        .set({
          state: "recoverable",
          leaseExpiresAt: new Date(input.now.getTime() + ATTENTION_RETRY_MS),
          lastError: "Configured wallet authority no longer matches lifecycle",
          updatedAt: input.now,
        })
        .where(
          and(
            eq(digitalAssetAccountWalletLifecycles.id, current.id),
            eq(digitalAssetAccountWalletLifecycles.ownerToken, recoveryToken),
          ),
        );
      await appendRequiredAudit(
        lifecycleAudit({
          tenantId: input.tenantId,
          action: "account.wallet_provision.recovery_attention",
          walletAgentId: current.walletAgentId,
          lifecycleId: current.id,
          outcome: "authority_mismatch",
        }),
      );
      return "attention";
    }

    if (authority) {
      const deleted = await tx
        .delete(agents)
        .where(
          and(
            eq(agents.tenantId, input.tenantId),
            eq(agents.id, current.walletAgentId),
            eq(agents.platformId, `account-provision:${current.id}`),
          ),
        )
        .returning({ id: agents.id });
      if (deleted.length !== 1)
        throw new Error("Configured wallet retirement lost its authority fence");
    }
    const retired = await tx
      .update(digitalAssetAccountWalletLifecycles)
      .set({ state: "retired", retiredAt: input.now, updatedAt: input.now, lastError: null })
      .where(
        and(
          eq(digitalAssetAccountWalletLifecycles.id, current.id),
          eq(digitalAssetAccountWalletLifecycles.ownerToken, recoveryToken),
          eq(digitalAssetAccountWalletLifecycles.state, "retiring"),
        ),
      )
      .returning({ id: digitalAssetAccountWalletLifecycles.id });
    if (retired.length !== 1)
      throw new Error("Configured wallet retirement lost its lifecycle fence");
    await appendRequiredAudit(
      lifecycleAudit({
        tenantId: input.tenantId,
        action: "account.wallet_provision.retire",
        walletAgentId: current.walletAgentId,
        lifecycleId: current.id,
        outcome: "retired",
      }),
    );
    return "retired";
  });
}

/**
 * Synchronously retire authorities from a failed request. Failures are persisted
 * as immediately claimable recovery work; callers never lose the durable row.
 */
export async function retireStagedAccountWallets(stagedWallets: StagedAccountWallet[]) {
  for (const staged of stagedWallets) {
    try {
      await reconcileLifecycle({
        tenantId: staged.tenantId,
        lifecycleId: staged.lifecycleId,
        expectedOwnerToken: staged.ownerToken,
        allowFreshLease: true,
        now: new Date(),
      });
    } catch (error) {
      const classified = redactedThrownDiagnostics(error);
      try {
        await getDb()
          .update(digitalAssetAccountWalletLifecycles)
          .set({
            state: "recoverable",
            leaseExpiresAt: new Date(),
            lastError: classified.errorCode ?? classified.errorClass,
            updatedAt: new Date(),
          })
          .where(
            and(
              eq(digitalAssetAccountWalletLifecycles.id, staged.lifecycleId),
              eq(digitalAssetAccountWalletLifecycles.ownerToken, staged.ownerToken),
              inArray(digitalAssetAccountWalletLifecycles.state, [
                "staging",
                "provisioned",
                "retiring",
                "recoverable",
              ]),
            ),
          );
      } catch (markError) {
        console.error(
          "[account-wallet-lifecycle] failed to persist recovery classification",
          redactedThrownDiagnostics(markError),
        );
      }
      console.error(
        "[account-wallet-lifecycle] inline retirement deferred to durable recovery",
        classified,
      );
    }
  }
}

export async function recoverStaleAccountWalletLifecyclesForTenant(
  tenantId: string,
  options?: { limit?: number; now?: Date },
): Promise<AccountWalletLifecycleRecoveryResult> {
  const limit = Math.max(1, Math.min(options?.limit ?? DEFAULT_SWEEP_BATCH_SIZE, 100));
  const now = options?.now ?? new Date();
  const candidates = await getDb()
    .select({ id: digitalAssetAccountWalletLifecycles.id })
    .from(digitalAssetAccountWalletLifecycles)
    .where(
      and(
        eq(digitalAssetAccountWalletLifecycles.tenantId, tenantId),
        inArray(digitalAssetAccountWalletLifecycles.state, [
          "staging",
          "provisioned",
          "recoverable",
          "retiring",
        ]),
        lte(digitalAssetAccountWalletLifecycles.leaseExpiresAt, now),
      ),
    )
    .orderBy(asc(digitalAssetAccountWalletLifecycles.leaseExpiresAt))
    .limit(limit + 1);
  const result: AccountWalletLifecycleRecoveryResult = {
    processed: 0,
    adopted: 0,
    retired: 0,
    attention: 0,
    remaining: candidates.length > limit,
  };
  for (const candidate of candidates.slice(0, limit)) {
    const outcome = await reconcileLifecycle({ tenantId, lifecycleId: candidate.id, now });
    if (outcome === "skipped") continue;
    result.processed += 1;
    result[outcome] += 1;
  }
  return result;
}

export async function runAccountWalletLifecycleRecoverySweep() {
  const results = await runInternalJobForEachTenant(
    "account-wallet-lifecycle-recovery",
    (tenantId) => recoverStaleAccountWalletLifecyclesForTenant(tenantId),
  );
  return results.map(({ value }) => value);
}

export function startAccountWalletLifecycleRecoveryScheduler(options?: {
  intervalMs?: number;
  sweep?: () => Promise<AccountWalletLifecycleRecoveryResult[]>;
}): () => Promise<void> {
  if (process.env.STEWARD_ACCOUNT_WALLET_LIFECYCLE_SWEEPER === "false") return async () => {};
  const sweep = options?.sweep ?? runAccountWalletLifecycleRecoverySweep;
  let active: Promise<void> | undefined;
  let stopped = false;
  const tick = () => {
    if (stopped || active) return;
    active = sweep()
      .then((results) => {
        const processed = results.reduce((total, result) => total + result.processed, 0);
        if (processed > 0) {
          console.log(`[account-wallet-lifecycle] reconciled ${processed} lifecycle(s)`);
        }
      })
      .catch((error) =>
        console.error(
          "[account-wallet-lifecycle] recovery sweep failed",
          redactedThrownDiagnostics(error),
        ),
      )
      .finally(() => {
        active = undefined;
      });
  };
  const parsedInterval = Number(process.env.STEWARD_ACCOUNT_WALLET_SWEEP_INTERVAL_MS);
  const intervalMs =
    options?.intervalMs ??
    (Number.isSafeInteger(parsedInterval) && parsedInterval >= 1_000
      ? parsedInterval
      : DEFAULT_SWEEP_INTERVAL_MS);
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  tick();
  return async () => {
    stopped = true;
    clearInterval(timer);
    await active;
  };
}

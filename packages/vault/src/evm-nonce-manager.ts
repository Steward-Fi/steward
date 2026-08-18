import { and, asc, eq, evmWalletNonceInflight, evmWalletNonces, getDb, sql } from "@stwd/db";
import type { Address } from "viem";

type PendingNonceReader = (address: Address) => Promise<number>;

const locks = new Map<string, Promise<void>>();

function usesAdvisoryLock(): boolean {
  return process.env.STEWARD_DB_MODE !== "pglite" && process.env.STEWARD_PGLITE_MEMORY !== "true";
}

async function withNonceLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const previous = locks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const current = new Promise<void>((resolve) => {
    release = resolve;
  });
  const chained = previous.then(
    () => current,
    () => current,
  );
  locks.set(key, chained);
  await previous;
  try {
    return await fn();
  } finally {
    release();
    if (locks.get(key) === chained) locks.delete(key);
  }
}

export async function allocateEvmNonce(input: {
  walletAddress: Address;
  chainId: number;
  getPendingNonce: PendingNonceReader;
}): Promise<number> {
  const walletAddress = input.walletAddress.toLowerCase() as Address;
  const lockKey = `${input.chainId}:${walletAddress}`;

  return withNonceLock(lockKey, async () => {
    const pendingNonce = await input.getPendingNonce(walletAddress);
    if (!Number.isSafeInteger(pendingNonce) || pendingNonce < 0) {
      throw new Error("RPC returned an invalid pending nonce");
    }

    return getDb().transaction(async (tx) => {
      if (usesAdvisoryLock()) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`evm-nonce:${lockKey}`}))`);
      }

      // A transport failure after submission cannot prove whether the network
      // accepted the transaction. Never reuse such a nonce while it is still at
      // or ahead of the chain's pending nonce. Once the pending nonce advances
      // past it, the chain itself proves the slot was consumed and the fence can
      // be removed safely.
      await tx
        .delete(evmWalletNonceInflight)
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            sql`${evmWalletNonceInflight.state} in ('broadcasting', 'unknown')`,
            sql`${evmWalletNonceInflight.nonce} < ${pendingNonce}`,
          ),
        );
      const [uncertain] = await tx
        .select({ nonce: evmWalletNonceInflight.nonce })
        .from(evmWalletNonceInflight)
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            sql`${evmWalletNonceInflight.state} in ('broadcasting', 'unknown')`,
            sql`${evmWalletNonceInflight.nonce} >= ${pendingNonce}`,
          ),
        )
        .orderBy(asc(evmWalletNonceInflight.nonce))
        .limit(1);
      if (uncertain) {
        throw new Error(
          `Nonce ${uncertain.nonce} has an unresolved broadcast outcome; reconcile it before submitting another transaction`,
        );
      }

      // Gap recovery: reclaim the lowest previously-dropped nonce that is still
      // at or ahead of the chain's pending nonce. Dropped nonces below the
      // pending nonce are already consumed/replaced on-chain and must not be
      // reused, so they are skipped (the row is harmless and ignored).
      const [reclaimable] = await tx
        .select({ nonce: evmWalletNonceInflight.nonce })
        .from(evmWalletNonceInflight)
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            eq(evmWalletNonceInflight.state, "dropped"),
            sql`${evmWalletNonceInflight.nonce} >= ${pendingNonce}`,
          ),
        )
        .orderBy(asc(evmWalletNonceInflight.nonce))
        .limit(1);

      if (reclaimable) {
        await tx
          .update(evmWalletNonceInflight)
          .set({ state: "allocated", updatedAt: new Date() })
          .where(
            and(
              eq(evmWalletNonceInflight.walletAddress, walletAddress),
              eq(evmWalletNonceInflight.chainId, input.chainId),
              eq(evmWalletNonceInflight.nonce, reclaimable.nonce),
            ),
          );
        return reclaimable.nonce;
      }

      const [row] = await tx
        .select({ nextNonce: evmWalletNonces.nextNonce })
        .from(evmWalletNonces)
        .where(
          and(
            eq(evmWalletNonces.walletAddress, walletAddress),
            eq(evmWalletNonces.chainId, input.chainId),
          ),
        )
        .limit(1);

      const nonce = Math.max(row?.nextNonce ?? pendingNonce, pendingNonce);
      await tx
        .insert(evmWalletNonces)
        .values({
          walletAddress,
          chainId: input.chainId,
          nextNonce: nonce + 1,
          updatedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: [evmWalletNonces.walletAddress, evmWalletNonces.chainId],
          set: { nextNonce: nonce + 1, updatedAt: new Date() },
        });

      await tx
        .insert(evmWalletNonceInflight)
        .values({
          walletAddress,
          chainId: input.chainId,
          nonce,
          state: "allocated",
          updatedAt: new Date(),
        })
        .onConflictDoUpdate({
          target: [
            evmWalletNonceInflight.walletAddress,
            evmWalletNonceInflight.chainId,
            evmWalletNonceInflight.nonce,
          ],
          set: { state: "allocated", updatedAt: new Date() },
        });

      return nonce;
    });
  });
}

async function setEvmNonceState(input: {
  walletAddress: Address;
  chainId: number;
  nonce: number;
  state: "broadcasting" | "unknown";
}): Promise<void> {
  const walletAddress = input.walletAddress.toLowerCase() as Address;
  const lockKey = `${input.chainId}:${walletAddress}`;

  await withNonceLock(lockKey, async () => {
    const updated = await getDb().transaction(async (tx) => {
      if (usesAdvisoryLock()) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`evm-nonce:${lockKey}`}))`);
      }
      return tx
        .update(evmWalletNonceInflight)
        .set({ state: input.state, updatedAt: new Date() })
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            eq(evmWalletNonceInflight.nonce, input.nonce),
          ),
        )
        .returning({ nonce: evmWalletNonceInflight.nonce });
    });
    if (updated.length !== 1) throw new Error("Allocated EVM nonce is missing");
  });
}

/** Fence an allocated nonce immediately before the irreversible RPC call. */
export async function markEvmNonceBroadcasting(input: {
  walletAddress: Address;
  chainId: number;
  nonce: number;
}): Promise<void> {
  await setEvmNonceState({ ...input, state: "broadcasting" });
}

/** Preserve a nonce whose broadcast result is ambiguous until chain reconciliation. */
export async function markEvmNonceSubmissionUnknown(input: {
  walletAddress: Address;
  chainId: number;
  nonce: number;
}): Promise<void> {
  await setEvmNonceState({ ...input, state: "unknown" });
}

/**
 * Mark an allocated-but-failed nonce as reclaimable so the next allocation for
 * the same (wallet, chain) reuses it instead of leaving a permanent hole that
 * wedges the wallet behind a stuck nonce. Best-effort: a failure here must not
 * break the caller's error handling.
 */
export async function markEvmNonceDropped(input: {
  walletAddress: Address;
  chainId: number;
  nonce: number;
}): Promise<void> {
  const walletAddress = input.walletAddress.toLowerCase() as Address;
  const lockKey = `${input.chainId}:${walletAddress}`;

  await withNonceLock(lockKey, async () => {
    await getDb().transaction(async (tx) => {
      if (usesAdvisoryLock()) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`evm-nonce:${lockKey}`}))`);
      }
      await tx
        .update(evmWalletNonceInflight)
        .set({ state: "dropped", updatedAt: new Date() })
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            eq(evmWalletNonceInflight.nonce, input.nonce),
          ),
        );
    });
  });
}

/**
 * Clear an in-flight nonce once its transaction is confirmed/broadcast
 * successfully. Best-effort: a failure here must not break a successful send.
 */
export async function confirmEvmNonce(input: {
  walletAddress: Address;
  chainId: number;
  nonce: number;
}): Promise<void> {
  const walletAddress = input.walletAddress.toLowerCase() as Address;
  const lockKey = `${input.chainId}:${walletAddress}`;

  await withNonceLock(lockKey, async () => {
    await getDb().transaction(async (tx) => {
      if (usesAdvisoryLock()) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`evm-nonce:${lockKey}`}))`);
      }
      await tx
        .delete(evmWalletNonceInflight)
        .where(
          and(
            eq(evmWalletNonceInflight.walletAddress, walletAddress),
            eq(evmWalletNonceInflight.chainId, input.chainId),
            eq(evmWalletNonceInflight.nonce, input.nonce),
          ),
        );
    });
  });
}

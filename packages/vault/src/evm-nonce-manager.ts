import { and, eq, evmWalletNonces, getDb, sql } from "@stwd/db";
import type { Address } from "viem";

type PendingNonceReader = (address: Address) => Promise<number>;

const locks = new Map<string, Promise<void>>();

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
      if (
        process.env.STEWARD_DB_MODE !== "pglite" &&
        process.env.STEWARD_PGLITE_MEMORY !== "true"
      ) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${`evm-nonce:${lockKey}`}))`);
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

      return nonce;
    });
  });
}

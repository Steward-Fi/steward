import type { TxRecord, TxStatus } from "@stwd/sdk";
import { useCallback, useEffect, useState } from "react";
import { useStewardContext } from "../provider.js";
import type { SpendStats } from "../types.js";
import { formatWei } from "../utils/format.js";

type SpendRange = "24h" | "7d" | "30d" | "all";

/** Statuses that represent value actually committed on-chain. */
const SPEND_STATUSES: readonly TxStatus[] = ["signed", "broadcast", "confirmed"];

const RANGE_MS: Record<Exclude<SpendRange, "all">, number> = {
  "24h": 24 * 60 * 60 * 1000,
  "7d": 7 * 24 * 60 * 60 * 1000,
  "30d": 30 * 24 * 60 * 60 * 1000,
};

function txValue(tx: TxRecord): bigint {
  try {
    return BigInt(tx.request?.value || "0");
  } catch {
    return 0n;
  }
}

function txDate(tx: TxRecord): Date {
  return tx.createdAt instanceof Date ? tx.createdAt : new Date(tx.createdAt);
}

/**
 * Aggregate history records into SpendStats: only value-committing statuses
 * count, and only transactions inside the range window. Exported for unit
 * tests; not part of the package API.
 */
export function computeSpendStats(
  range: SpendRange,
  txs: TxRecord[],
  now = Date.now(),
): SpendStats {
  const since = range === "all" ? null : now - RANGE_MS[range];
  const relevant = txs.filter(
    (tx) => SPEND_STATUSES.includes(tx.status) && (since === null || txDate(tx).getTime() >= since),
  );

  let total = 0n;
  let largest: TxRecord | null = null;
  const daily = new Map<string, { spent: bigint; txCount: number }>();
  const destinations = new Map<string, { totalSent: bigint; txCount: number }>();

  for (const tx of relevant) {
    const value = txValue(tx);
    total += value;

    const day = txDate(tx).toISOString().slice(0, 10);
    const dayBucket = daily.get(day) ?? { spent: 0n, txCount: 0 };
    dayBucket.spent += value;
    dayBucket.txCount += 1;
    daily.set(day, dayBucket);

    const to = tx.request?.to;
    if (to) {
      const dest = destinations.get(to) ?? { totalSent: 0n, txCount: 0 };
      dest.totalSent += value;
      dest.txCount += 1;
      destinations.set(to, dest);
    }

    if (value > 0n && (!largest || value > txValue(largest))) largest = tx;
  }

  const txCount = relevant.length;
  const avg = txCount > 0 ? total / BigInt(txCount) : 0n;

  return {
    range,
    totalSpent: total.toString(),
    totalSpentFormatted: formatWei(total.toString()),
    txCount,
    avgTxValue: avg.toString(),
    avgTxValueFormatted: formatWei(avg.toString()),
    largestTx: largest
      ? {
          value: txValue(largest).toString(),
          txHash: largest.txHash ?? "",
          timestamp: txDate(largest).toISOString(),
        }
      : { value: "0", txHash: "", timestamp: "" },
    daily: [...daily.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([date, d]) => ({
        date,
        spent: d.spent.toString(),
        spentFormatted: formatWei(d.spent.toString()),
        txCount: d.txCount,
      })),
    topDestinations: [...destinations.entries()]
      .sort(([, a], [, b]) => (a.totalSent > b.totalSent ? -1 : a.totalSent < b.totalSent ? 1 : 0))
      .slice(0, 5)
      .map(([address, d]) => ({
        address,
        totalSent: d.totalSent.toString(),
        txCount: d.txCount,
      })),
    // Budget limits live in policy config, not in history — left undefined.
  };
}

/**
 * Spend analytics for a given time range.
 *
 * There is no spend-stats endpoint; stats are derived from the credentialed
 * transaction history via StewardClient, so credentials always attach
 * (SEC-195).
 */
export function useSpend(range: SpendRange = "7d") {
  const { client, agentId, pollInterval } = useStewardContext();
  const [stats, setStats] = useState<SpendStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const records = await client.getTransactionHistory(agentId);
      setStats(computeSpendStats(range, records));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [client, agentId, range]);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, pollInterval);
    return () => clearInterval(interval);
  }, [fetchStats, pollInterval]);

  return {
    stats,
    isLoading,
    error,
    refetch: fetchStats,
  };
}

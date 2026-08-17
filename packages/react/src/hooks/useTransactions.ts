import type { TxRecord, TxStatus } from "@stwd/sdk";
import { useCallback, useEffect, useState } from "react";
import { useStewardContext } from "../provider.js";

interface UseTransactionsOpts {
  pageSize?: number;
  status?: TxStatus[];
  chainId?: number;
}

/**
 * Client-side status/chain filtering for history records. Exported for unit
 * tests; not part of the package API.
 */
export function filterTransactions(
  records: TxRecord[],
  opts: { status?: TxStatus[]; chainId?: number },
): TxRecord[] {
  return records.filter(
    (tx) =>
      (!opts.status?.length || opts.status.includes(tx.status)) &&
      (!opts.chainId || tx.request?.chainId === opts.chainId),
  );
}

/**
 * Paginated transaction history.
 * There is no paginated list endpoint; the hook fetches the credentialed
 * history through StewardClient and filters/paginates client-side. Raw
 * fetch is never used, so credentials always attach (SEC-195).
 */
export function useTransactions(opts: UseTransactionsOpts = {}) {
  const { client, agentId, pollInterval } = useStewardContext();
  const { pageSize = 20, status, chainId } = opts;

  const [allTransactions, setAllTransactions] = useState<TxRecord[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [page, setPage] = useState(1);

  const fetchTransactions = useCallback(async () => {
    try {
      const records = await client.getTransactionHistory(agentId);
      setAllTransactions(filterTransactions(records, { status, chainId }));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [client, agentId, status, chainId]);

  useEffect(() => {
    fetchTransactions();
    const interval = setInterval(fetchTransactions, pollInterval);
    return () => clearInterval(interval);
  }, [fetchTransactions, pollInterval]);

  // Client-side pagination
  const totalPages = Math.max(1, Math.ceil(allTransactions.length / pageSize));
  const paginatedTx = allTransactions.slice((page - 1) * pageSize, page * pageSize);

  return {
    transactions: paginatedTx,
    isLoading,
    error,
    page,
    totalPages,
    nextPage: () => setPage((p) => Math.min(p + 1, totalPages)),
    prevPage: () => setPage((p) => Math.max(p - 1, 1)),
    setPage,
    refetch: fetchTransactions,
  };
}

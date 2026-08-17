import type { ApprovalQueueEntry as SdkApprovalQueueEntry } from "@stwd/sdk";
import { useCallback, useEffect, useState } from "react";
import { useStewardContext } from "../provider.js";
import type { ApprovalQueueEntry } from "../types.js";

/**
 * Map the SDK tenant-level approval entry onto the dashboard shape. The
 * tenant approvals API does not expose per-entry policy results, so that
 * list stays empty. Exported for unit tests; not part of the package API.
 */
export function toQueueEntry(entry: SdkApprovalQueueEntry): ApprovalQueueEntry {
  const requestedAt =
    entry.requestedAt instanceof Date ? entry.requestedAt : new Date(entry.requestedAt);
  const resolvedAt =
    entry.resolvedAt === undefined
      ? undefined
      : entry.resolvedAt instanceof Date
        ? entry.resolvedAt
        : new Date(entry.resolvedAt);
  return {
    id: entry.id,
    agentId: entry.agentId,
    txId: entry.txId,
    status: entry.status,
    to: entry.toAddress ?? "",
    value: entry.value ?? "0",
    chainId: entry.chainId ?? 0,
    policyResults: [],
    createdAt: Number.isNaN(requestedAt.getTime()) ? "" : requestedAt.toISOString(),
    resolvedAt:
      resolvedAt && !Number.isNaN(resolvedAt.getTime()) ? resolvedAt.toISOString() : undefined,
    resolvedBy: entry.resolvedBy,
  };
}

/**
 * Approval queue with approve/reject actions.
 *
 * All calls route through the credentialed StewardClient (tenant-scoped
 * `/approvals` endpoints) — never raw fetch — so approvals cannot become
 * unauthenticated mutations behind an ambient-auth deployment (SEC-195).
 */
export function useApprovals(refreshInterval?: number) {
  const { client, agentId, pollInterval } = useStewardContext();
  const interval = refreshInterval || pollInterval;

  const [pending, setPending] = useState<ApprovalQueueEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isResolving, setIsResolving] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchApprovals = useCallback(async () => {
    try {
      // Tenant-scoped list; narrow to this provider's agent client-side.
      const entries = await client.listApprovals({ status: "pending" });
      setPending(entries.filter((e) => e.agentId === agentId).map(toQueueEntry));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setIsLoading(false);
    }
  }, [client, agentId]);

  useEffect(() => {
    fetchApprovals();
    const timer = setInterval(fetchApprovals, interval);
    return () => clearInterval(timer);
  }, [fetchApprovals, interval]);

  const approve = useCallback(
    async (txId: string) => {
      setIsResolving(true);
      try {
        await client.approveTransaction(txId);
        setPending((prev) => prev.filter((a) => a.txId !== txId));
      } finally {
        setIsResolving(false);
      }
    },
    [client],
  );

  const reject = useCallback(
    async (txId: string, reason?: string) => {
      setIsResolving(true);
      try {
        await client.denyTransaction(txId, reason ?? "");
        setPending((prev) => prev.filter((a) => a.txId !== txId));
      } finally {
        setIsResolving(false);
      }
    },
    [client],
  );

  return {
    pending,
    isLoading,
    error,
    approve,
    reject,
    isResolving,
    refetch: fetchApprovals,
  };
}

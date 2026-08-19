"use client";

import { type ApprovalQueueEntry, StewardClient } from "@stwd/sdk";
import { AnimatePresence, motion } from "framer-motion";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/components/auth-provider";
import { ChainBadge } from "@/components/chain-badge";
import { STEWARD_API_URL } from "@/lib/steward-api-url";
import { formatDate, formatNativeAmount, shortenAddress } from "@/lib/utils";

type PendingItem = ApprovalQueueEntry;

interface ApprovalLoad {
  promise: Promise<PendingItem[]>;
  value?: PendingItem[];
}

// StewardProvider owns the session object above WalletProviderTree, whose
// client-only provider activation can remount dashboard children once. Keep
// one weakly-held load per session/tenant so that remount cannot duplicate the
// request. A tenant rotation creates a new session object, and explicit retry
// replaces the cached attempt.
const approvalLoads = new WeakMap<object, Map<string, ApprovalLoad>>();

function loadApprovalsForSession(
  session: object,
  tenantId: string,
  client: StewardClient,
  force: boolean,
): Promise<PendingItem[]> {
  let tenantLoads = approvalLoads.get(session);
  if (!tenantLoads) {
    tenantLoads = new Map();
    approvalLoads.set(session, tenantLoads);
  }
  const existing = tenantLoads.get(tenantId);
  if (existing && !force) return existing.promise;

  const load: ApprovalLoad = {
    promise: client.listApprovals({ limit: 200 }).then((items) => {
      load.value = items;
      return items;
    }),
  };
  tenantLoads.set(tenantId, load);
  return load.promise;
}

function removeCachedApproval(session: object, tenantId: string, txId: string): void {
  const load = approvalLoads.get(session)?.get(tenantId);
  if (!load?.value) return;
  load.value = load.value.filter((item) => item.txId !== txId);
  load.promise = Promise.resolve(load.value);
}

interface Toast {
  id: string;
  message: string;
  kind: "success" | "error";
}

export default function ApprovalsPage() {
  const auth = useAuth();
  const activeTenantId = auth.tenant?.tenantId ?? null;
  const authReady =
    auth.isAuthenticated &&
    !auth.isLoading &&
    activeTenantId !== null &&
    auth.sessionTenantId === activeTenantId &&
    auth.accessToken !== null &&
    auth.sessionIdentity !== null;
  const client = useMemo(
    () =>
      authReady
        ? new StewardClient({ baseUrl: STEWARD_API_URL, bearerToken: auth.accessToken! })
        : null,
    [auth.accessToken, authReady],
  );
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [loadedTenantId, setLoadedTenantId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const requestGeneration = useRef(0);
  const requestedTenant = useRef<string | null>(null);

  function addToast(message: string, kind: Toast["kind"]) {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, { id, message, kind }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }

  const loadPending = useCallback(
    async (force = false) => {
      const generation = ++requestGeneration.current;
      const tenantId = activeTenantId;
      setPending([]);
      setLoadedTenantId(null);
      setActionLoading(null);
      if (!authReady) {
        setLoading(true);
        setError(null);
        return;
      }
      try {
        setLoading(true);
        setError(null);
        // Request the max page size so the dashboard shows all pending items in a single load.
        const items = await loadApprovalsForSession(
          auth.sessionIdentity!,
          tenantId!,
          client!,
          force,
        );
        if (requestGeneration.current !== generation) return;
        setPending(items);
        setLoadedTenantId(tenantId);
      } catch (e: unknown) {
        if (requestGeneration.current !== generation) return;
        setError(e instanceof Error ? e.message : "Failed to load approvals");
        setLoadedTenantId(tenantId);
      } finally {
        if (requestGeneration.current === generation) setLoading(false);
      }
    },
    [activeTenantId, auth.sessionIdentity, authReady, client],
  );

  useEffect(() => {
    if (!authReady) {
      requestGeneration.current += 1;
      requestedTenant.current = null;
      setPending([]);
      setLoadedTenantId(null);
      setActionLoading(null);
      setError(null);
      setLoading(true);
      return;
    }
    if (requestedTenant.current === activeTenantId) return;
    requestedTenant.current = activeTenantId;
    void loadPending();
  }, [activeTenantId, authReady, loadPending]);

  async function handleAction(txId: string, action: "approve" | "reject") {
    const generation = requestGeneration.current;
    const tenantId = activeTenantId;
    const key = `${txId}-${action}`;
    setActionLoading(key);
    try {
      if (action === "approve") {
        await client!.approveTransaction(txId, { comment: "Approved from dashboard" });
      } else {
        await client!.denyTransaction(txId, "Rejected from dashboard");
      }
      if (requestGeneration.current !== generation || activeTenantId !== tenantId) return;
      removeCachedApproval(auth.sessionIdentity!, tenantId!, txId);
      setPending((prev) => prev.filter((item) => item.txId !== txId));
      addToast(
        action === "approve"
          ? "Transaction approved and queued for signing"
          : "Transaction rejected",
        "success",
      );
    } catch (e: unknown) {
      if (requestGeneration.current !== generation || activeTenantId !== tenantId) return;
      addToast(e instanceof Error ? e.message : `Failed to ${action}`, "error");
    } finally {
      if (requestGeneration.current === generation && activeTenantId === tenantId) {
        setActionLoading(null);
      }
    }
  }

  const tenantIsCurrent = loadedTenantId === activeTenantId;
  const visiblePending = tenantIsCurrent ? pending : [];
  const visibleError = tenantIsCurrent ? error : null;

  if (loading || !tenantIsCurrent) {
    return (
      <div className="space-y-8">
        <div className="h-8 w-48 bg-bg-surface animate-pulse" />
        <div className="space-y-px bg-border">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-bg h-32 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-8"
    >
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Approval Queue</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Transactions exceeding policy thresholds
          </p>
        </div>
        {visiblePending.length > 0 && (
          <span className="text-xs text-amber-400 font-medium tabular-nums">
            {visiblePending.length} pending
          </span>
        )}
      </div>

      <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-2 pointer-events-none">
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: 16, scale: 0.96 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 8, scale: 0.96 }}
              transition={{ duration: 0.22, ease: [0.25, 1, 0.5, 1] }}
              className={`px-4 py-3 text-sm font-medium border pointer-events-auto ${
                toast.kind === "success"
                  ? "bg-bg-elevated border-emerald-400/30 text-emerald-400"
                  : "bg-bg-elevated border-red-400/30 text-red-400"
              }`}
            >
              {toast.message}
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {visibleError && !loading && (
        <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
          <p className="text-text-secondary text-sm mb-1">Failed to load approvals</p>
          <p className="text-text-tertiary text-xs mb-4 font-mono">{visibleError}</p>
          <button
            onClick={() => void loadPending(true)}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {visiblePending.length === 0 && !visibleError ? (
        <div className="py-20 text-center border border-border-subtle">
          <p className="font-display text-lg font-600 text-text-secondary">Queue is clear</p>
          <p className="text-sm text-text-tertiary mt-2 max-w-sm mx-auto">
            All transactions are either auto-approved or have been reviewed. Transactions that
            exceed policy thresholds will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <AnimatePresence initial={false}>
            {visiblePending.map((item, i) => (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: 24, height: 0, marginBottom: 0 }}
                transition={{
                  delay: i * 0.06,
                  duration: 0.3,
                  ease: [0.25, 1, 0.5, 1],
                }}
                className="border border-border p-6 bg-bg-elevated hover:bg-bg-surface transition-colors overflow-hidden"
              >
                <div className="flex items-start justify-between gap-6">
                  <div className="min-w-0 space-y-3">
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="text-xs px-2 py-0.5 bg-amber-400/10 text-amber-400 font-medium">
                        Pending
                      </span>
                      <ChainBadge chainId={item.chainId || 8453} />
                      <span className="text-xs text-text-tertiary">
                        {formatDate(item.requestedAt)}
                      </span>
                    </div>

                    <div className="text-sm flex items-center gap-2 flex-wrap">
                      <Link
                        href={`/dashboard/agents/${item.agentId}`}
                        className="text-text hover:text-accent transition-colors font-display font-600"
                      >
                        {item.agentName || item.agentId}
                      </Link>
                      <span className="text-text-tertiary">&rarr;</span>
                      <span className="font-mono text-xs text-text-tertiary">
                        {shortenAddress(item.toAddress || "0x0", 8)}
                      </span>
                    </div>

                    <div className="flex items-center gap-5 text-xs text-text-tertiary">
                      <span>
                        Value:{" "}
                        <span className="text-text-secondary tabular-nums">
                          {formatNativeAmount(item.value || "0", item.chainId || 8453)}
                        </span>
                      </span>
                    </div>
                  </div>

                  <div className="flex gap-2 flex-shrink-0">
                    <button
                      onClick={() => handleAction(item.txId, "approve")}
                      disabled={actionLoading !== null}
                      className="px-4 py-2 text-xs font-medium bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {actionLoading === `${item.txId}-approve` ? "..." : "Approve"}
                    </button>
                    <button
                      onClick={() => handleAction(item.txId, "reject")}
                      disabled={actionLoading !== null}
                      className="px-4 py-2 text-xs font-medium bg-red-400/10 text-red-400 hover:bg-red-400/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {actionLoading === `${item.txId}-reject` ? "..." : "Reject"}
                    </button>
                  </div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </motion.div>
  );
}

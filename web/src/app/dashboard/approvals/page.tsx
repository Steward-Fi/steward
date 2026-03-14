"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { motion, AnimatePresence } from "framer-motion";
import { steward, API_URL } from "@/lib/api";
import { useAuth } from "@/components/auth-provider";
import { shortenAddress, formatDate, formatWei } from "@/lib/utils";
import { getChainSymbol } from "@/lib/chains";
import { ChainBadge } from "@/components/chain-badge";
import type { AgentIdentity } from "@/lib/steward-client";

interface PendingItem {
  queueId: string;
  status: string;
  requestedAt: string;
  transaction: {
    id: string;
    request?: { to: string; value: string; data?: string; chainId: number };
    toAddress?: string;
    value?: string;
    chainId?: number;
    policyResults?: { type: string; passed: boolean; reason?: string }[];
  };
  agentId: string;
  agentName: string;
}

interface Toast {
  id: string;
  message: string;
  kind: "success" | "error";
}

export default function ApprovalsPage() {
  const { tenant } = useAuth();
  const TENANT_ID = tenant?.tenantId || "";
  const API_KEY = tenant?.apiKey || "";
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toasts, setToasts] = useState<Toast[]>([]);

  useEffect(() => {
    loadPending();
  }, []);

  function addToast(message: string, kind: Toast["kind"]) {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, { id, message, kind }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3000);
  }

  async function loadPending() {
    try {
      setLoading(true);
      setError(null);
      const agents: AgentIdentity[] = await steward.listAgents();
      const allPending: PendingItem[] = [];

      for (const agent of agents) {
        try {
          const res = await fetch(`${API_URL}/vault/${agent.id}/pending`, {
            headers: {
              "X-Steward-Tenant": TENANT_ID,
              "X-Steward-Key": API_KEY,
            },
          });
          const data = await res.json();
          if (data.ok && data.data) {
            allPending.push(
              ...data.data.map((item: PendingItem) => ({
                ...item,
                agentId: agent.id,
                agentName: agent.name,
              }))
            );
          }
        } catch {
          /* skip agent */
        }
      }

      allPending.sort(
        (a, b) =>
          new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime()
      );
      setPending(allPending);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load approvals");
    } finally {
      setLoading(false);
    }
  }

  async function handleAction(
    agentId: string,
    txId: string,
    action: "approve" | "reject"
  ) {
    const key = `${txId}-${action}`;
    setActionLoading(key);
    try {
      const res = await fetch(
        `${API_URL}/vault/${agentId}/${action}/${txId}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Tenant": TENANT_ID,
            "X-Steward-Key": API_KEY,
          },
        }
      );
      const data = await res.json();
      if (data.ok) {
        // Optimistically remove from list
        setPending((prev) =>
          prev.filter((item) => item.transaction?.id !== txId)
        );
        addToast(
          action === "approve"
            ? "Transaction approved and queued for signing"
            : "Transaction rejected",
          "success"
        );
      } else {
        addToast(data.error || `Failed to ${action}`, "error");
      }
    } catch (e: unknown) {
      addToast(
        e instanceof Error ? e.message : `Failed to ${action}`,
        "error"
      );
    } finally {
      setActionLoading(null);
    }
  }

  if (loading) {
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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">
            Approval Queue
          </h1>
          <p className="text-sm text-text-tertiary mt-1">
            Transactions exceeding policy thresholds
          </p>
        </div>
        {pending.length > 0 && (
          <span className="text-xs text-amber-400 font-medium tabular-nums">
            {pending.length} pending
          </span>
        )}
      </div>

      {/* Toast notifications */}
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

      {/* Error state */}
      {error && !loading && (
        <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
          <p className="text-text-secondary text-sm mb-1">Failed to load approvals</p>
          <p className="text-text-tertiary text-xs mb-4 font-mono">{error}</p>
          <button
            onClick={loadPending}
            className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {pending.length === 0 && !error ? (
        <div className="py-20 text-center border border-border-subtle">
          <p className="font-display text-lg font-600 text-text-secondary">
            Queue is clear
          </p>
          <p className="text-sm text-text-tertiary mt-2 max-w-sm mx-auto">
            All transactions are either auto-approved or have been reviewed.
            Transactions that exceed policy thresholds will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          <AnimatePresence initial={false}>
            {pending.map((item, i) => (
              <motion.div
                key={item.queueId || item.transaction?.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, x: 24, height: 0, marginBottom: 0 }}
                transition={{ delay: i * 0.06, duration: 0.3, ease: [0.25, 1, 0.5, 1] }}
                className="border border-border p-6 bg-bg-elevated hover:bg-bg-surface transition-colors overflow-hidden"
              >
                <div className="flex items-start justify-between gap-6">
                  <div className="min-w-0 space-y-3">
                    {/* Agent & time */}
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="text-xs px-2 py-0.5 bg-amber-400/10 text-amber-400 font-medium">
                        Pending
                      </span>
                      <ChainBadge chainId={item.transaction?.request?.chainId || item.transaction?.chainId || 8453} />
                      <span className="text-xs text-text-tertiary">
                        {formatDate(item.requestedAt)}
                      </span>
                    </div>

                    {/* From -> To */}
                    <div className="text-sm flex items-center gap-2 flex-wrap">
                      <Link
                        href={`/dashboard/agents/${item.agentId}`}
                        className="text-text hover:text-accent transition-colors font-display font-600"
                      >
                        {item.agentName}
                      </Link>
                      <span className="text-text-tertiary">&rarr;</span>
                      <span className="font-mono text-xs text-text-tertiary">
                        {shortenAddress(
                          item.transaction?.request?.to ||
                            item.transaction?.toAddress ||
                            "0x0",
                          8
                        )}
                      </span>
                    </div>

                    {/* Details */}
                    <div className="flex items-center gap-5 text-xs text-text-tertiary">
                      <span>
                        Value:{" "}
                        <span className="text-text-secondary tabular-nums">
                          {formatWei(
                            item.transaction?.request?.value ||
                              item.transaction?.value ||
                              "0",
                            getChainSymbol(item.transaction?.request?.chainId || item.transaction?.chainId || 8453)
                          )}
                        </span>
                      </span>
                      {item.transaction?.request?.data && (
                        <span>Has calldata</span>
                      )}
                    </div>

                    {/* Policy results */}
                    {item.transaction?.policyResults &&
                      item.transaction.policyResults.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-1">
                          {item.transaction.policyResults.map((result, ri) => (
                            <span
                              key={ri}
                              className={`text-xs px-2 py-0.5 ${
                                result.passed
                                  ? "bg-emerald-400/10 text-emerald-400"
                                  : "bg-red-400/10 text-red-400"
                              }`}
                            >
                              {result.type}:{" "}
                              {result.passed
                                ? "pass"
                                : result.reason || "fail"}
                            </span>
                          ))}
                        </div>
                      )}
                  </div>

                  {/* Actions */}
                  <div className="flex gap-2 flex-shrink-0">
                    <button
                      onClick={() =>
                        handleAction(
                          item.agentId,
                          item.transaction?.id,
                          "approve"
                        )
                      }
                      disabled={actionLoading !== null}
                      className="px-4 py-2 text-xs font-medium bg-emerald-400/10 text-emerald-400 hover:bg-emerald-400/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {actionLoading === `${item.transaction?.id}-approve`
                        ? "..."
                        : "Approve"}
                    </button>
                    <button
                      onClick={() =>
                        handleAction(
                          item.agentId,
                          item.transaction?.id,
                          "reject"
                        )
                      }
                      disabled={actionLoading !== null}
                      className="px-4 py-2 text-xs font-medium bg-red-400/10 text-red-400 hover:bg-red-400/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {actionLoading === `${item.transaction?.id}-reject`
                        ? "..."
                        : "Reject"}
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

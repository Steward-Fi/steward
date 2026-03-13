"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { steward } from "@/lib/api";
import { shortenAddress, formatDate, formatWei, statusColor } from "@/lib/utils";
import { EmptyState } from "@/components/empty-state";

interface PendingItem {
  queueId: string;
  status: string;
  requestedAt: string;
  transaction: any;
  agentId: string;
  agentName: string;
}

export default function ApprovalsPage() {
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  useEffect(() => {
    loadPending();
  }, []);

  async function loadPending() {
    try {
      setLoading(true);
      const agents = await steward.listAgents();
      const allPending: PendingItem[] = [];

      for (const agent of agents) {
        try {
          const res = await fetch(
            `${process.env.NEXT_PUBLIC_STEWARD_API_URL || "http://localhost:3200"}/vault/${agent.id}/pending`,
            {
              headers: {
                "X-Steward-Tenant": process.env.NEXT_PUBLIC_STEWARD_TENANT_ID || "default",
                "X-Steward-Key": process.env.NEXT_PUBLIC_STEWARD_API_KEY || "",
              },
            }
          );
          const data = await res.json();
          if (data.ok && data.data) {
            allPending.push(
              ...data.data.map((item: any) => ({
                ...item,
                agentId: agent.id,
                agentName: agent.name,
              }))
            );
          }
        } catch {}
      }

      allPending.sort(
        (a, b) => new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime()
      );
      setPending(allPending);
    } catch (e) {
      console.error("Failed to load pending:", e);
    } finally {
      setLoading(false);
    }
  }

  async function handleAction(agentId: string, txId: string, action: "approve" | "reject") {
    const key = `${txId}-${action}`;
    setActionLoading(key);
    try {
      const endpoint = action === "approve" ? "approve" : "reject";
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_STEWARD_API_URL || "http://localhost:3200"}/vault/${agentId}/${endpoint}/${txId}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Steward-Tenant": process.env.NEXT_PUBLIC_STEWARD_TENANT_ID || "default",
            "X-Steward-Key": process.env.NEXT_PUBLIC_STEWARD_API_KEY || "",
          },
        }
      );
      const data = await res.json();
      if (data.ok) {
        await loadPending();
      } else {
        alert(data.error || `Failed to ${action}`);
      }
    } catch (e: any) {
      alert(e.message || `Failed to ${action}`);
    } finally {
      setActionLoading(null);
    }
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 w-48 bg-zinc-800 rounded" />
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => <div key={i} className="card p-5 h-24" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Approval Queue</h1>
        <p className="text-sm text-zinc-500 mt-1">
          Transactions that exceeded policy thresholds and need manual review
        </p>
      </div>

      {pending.length === 0 ? (
        <EmptyState
          icon="◉"
          title="No pending approvals"
          description="All transactions are either auto-approved or have been reviewed."
        />
      ) : (
        <div className="space-y-3">
          {pending.map((item) => (
            <div key={item.queueId} className="card p-5">
              <div className="flex items-start justify-between">
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="badge badge-warning">Pending Approval</span>
                    <span className="text-xs text-zinc-500">{formatDate(item.requestedAt)}</span>
                  </div>

                  <div className="text-sm">
                    <Link href={`/agents/${item.agentId}`} className="text-zinc-300 hover:text-white font-medium">
                      {item.agentName}
                    </Link>
                    <span className="text-zinc-600 mx-2">→</span>
                    <span className="font-mono text-xs text-zinc-400">
                      {shortenAddress(item.transaction?.request?.to || item.transaction?.toAddress || "0x0", 8)}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs text-zinc-500">
                    <span>
                      Value: <span className="text-zinc-300 tabular-nums">{formatWei(item.transaction?.request?.value || item.transaction?.value || "0")}</span>
                    </span>
                    <span>
                      Chain: <span className="text-zinc-300">{item.transaction?.request?.chainId || item.transaction?.chainId || 8453}</span>
                    </span>
                    {item.transaction?.request?.data && (
                      <span>Has calldata</span>
                    )}
                  </div>

                  {/* Policy results */}
                  {item.transaction?.policyResults && (
                    <div className="flex flex-wrap gap-1 mt-1">
                      {item.transaction.policyResults.map((result: any, i: number) => (
                        <span
                          key={i}
                          className={`text-xs px-2 py-0.5 rounded ${
                            result.passed ? "bg-green-500/10 text-green-400" : "bg-red-500/10 text-red-400"
                          }`}
                        >
                          {result.type}: {result.passed ? "✓" : result.reason || "✗"}
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex gap-2 ml-4">
                  <button
                    onClick={() => handleAction(item.agentId, item.transaction?.id, "approve")}
                    disabled={actionLoading !== null}
                    className="btn btn-primary text-xs"
                  >
                    {actionLoading === `${item.transaction?.id}-approve` ? "..." : "Approve"}
                  </button>
                  <button
                    onClick={() => handleAction(item.agentId, item.transaction?.id, "reject")}
                    disabled={actionLoading !== null}
                    className="btn btn-danger text-xs"
                  >
                    {actionLoading === `${item.transaction?.id}-reject` ? "..." : "Reject"}
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

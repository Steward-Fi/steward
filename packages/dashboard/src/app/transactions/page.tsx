"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { steward } from "@/lib/api";
import { shortenAddress, formatDate, formatWei, statusColor } from "@/lib/utils";
import { EmptyState } from "@/components/empty-state";

export default function TransactionsPage() {
  const [transactions, setTransactions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<string>("all");

  useEffect(() => {
    loadTransactions();
  }, []);

  async function loadTransactions() {
    try {
      setLoading(true);
      const agents = await steward.listAgents();
      const allTx: any[] = [];

      for (const agent of agents) {
        try {
          const history = await steward.getHistory(agent.id);
          allTx.push(
            ...history.map((tx: any) => ({
              ...tx,
              agentId: agent.id,
              agentName: agent.name,
            }))
          );
        } catch {}
      }

      allTx.sort(
        (a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime()
      );
      setTransactions(allTx);
    } catch (e) {
      console.error("Failed to load transactions:", e);
    } finally {
      setLoading(false);
    }
  }

  const filtered = filter === "all"
    ? transactions
    : transactions.filter((tx) => tx.status === filter);

  const statusCounts = transactions.reduce(
    (acc: Record<string, number>, tx) => {
      acc[tx.status] = (acc[tx.status] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 w-48 bg-zinc-800 rounded" />
        <div className="card h-96" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Transactions</h1>
        <p className="text-sm text-zinc-500 mt-1">All transactions across agents</p>
      </div>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap">
        {["all", "signed", "confirmed", "pending", "rejected", "failed"].map((status) => (
          <button
            key={status}
            onClick={() => setFilter(status)}
            className={`text-xs px-3 py-1.5 rounded-lg transition-colors ${
              filter === status
                ? "bg-white/10 text-white"
                : "text-zinc-500 hover:text-zinc-300 hover:bg-white/5"
            }`}
          >
            {status === "all" ? "All" : status.charAt(0).toUpperCase() + status.slice(1)}
            {status !== "all" && statusCounts[status] ? ` (${statusCounts[status]})` : ""}
            {status === "all" ? ` (${transactions.length})` : ""}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon="◎"
          title={filter === "all" ? "No transactions yet" : `No ${filter} transactions`}
          description={
            filter === "all"
              ? "Transactions will appear here when agents start signing."
              : "Try a different filter."
          }
        />
      ) : (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#262626] text-zinc-500 text-xs uppercase tracking-wider">
                <th className="text-left p-3 pl-4">Agent</th>
                <th className="text-left p-3">To</th>
                <th className="text-left p-3">Value</th>
                <th className="text-left p-3">Status</th>
                <th className="text-left p-3">TX Hash</th>
                <th className="text-left p-3 pr-4">Time</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((tx: any, i: number) => (
                <tr
                  key={tx.id || i}
                  className="border-b border-[#262626] last:border-0 hover:bg-white/[0.02]"
                >
                  <td className="p-3 pl-4">
                    <Link
                      href={`/agents/${tx.agentId}`}
                      className="text-zinc-300 hover:text-white"
                    >
                      {tx.agentName || shortenAddress(tx.agentId)}
                    </Link>
                  </td>
                  <td className="p-3 font-mono text-xs text-zinc-400">
                    {shortenAddress(tx.request?.to || tx.toAddress || "0x0", 6)}
                  </td>
                  <td className="p-3 tabular-nums">
                    {formatWei(tx.request?.value || tx.value || "0")}
                  </td>
                  <td className="p-3">
                    <span className={`badge ${statusColor(tx.status)}`}>{tx.status}</span>
                  </td>
                  <td className="p-3 font-mono text-xs text-zinc-500">
                    {tx.txHash ? (
                      <a
                        href={`https://basescan.org/tx/${tx.txHash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-zinc-300"
                      >
                        {shortenAddress(tx.txHash, 6)}
                      </a>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="p-3 pr-4 text-zinc-500 text-xs">
                    {tx.createdAt ? formatDate(tx.createdAt) : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

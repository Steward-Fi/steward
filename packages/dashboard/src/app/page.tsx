"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { steward } from "@/lib/api";
import { StatCard } from "@/components/stat-card";
import { shortenAddress, formatDate, statusColor, formatWei } from "@/lib/utils";

interface DashboardData {
  agents: any[];
  recentTx: any[];
  pendingCount: number;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      setLoading(true);
      const agentsList = await steward.listAgents();

      // Gather recent transactions + pending counts from all agents
      let allTx: any[] = [];
      let pendingCount = 0;

      for (const agent of agentsList.slice(0, 20)) {
        try {
          const history = await steward.getHistory(agent.id);
          allTx.push(...history.map((tx: any) => ({ ...tx, agentId: agent.id, agentName: agent.name })));
        } catch {}
      }

      allTx.sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
      pendingCount = allTx.filter((tx) => tx.status === "pending").length;

      setData({
        agents: agentsList,
        recentTx: allTx.slice(0, 10),
        pendingCount,
      });
    } catch (e: any) {
      setError(e.message || "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 w-48 bg-zinc-800 rounded" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="card p-5 h-24" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card p-8 text-center">
        <div className="text-red-400 mb-2">Connection Error</div>
        <div className="text-sm text-zinc-500 mb-4">{error}</div>
        <button onClick={loadDashboard} className="btn btn-primary">Retry</button>
      </div>
    );
  }

  const { agents, recentTx, pendingCount } = data!;

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-zinc-500 mt-1">Agent wallet infrastructure overview</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Agents" value={agents.length} />
        <StatCard
          label="Pending Approvals"
          value={pendingCount}
          trend={pendingCount > 0 ? "up" : "neutral"}
          subtext={pendingCount > 0 ? "Needs attention" : "All clear"}
        />
        <StatCard label="Transactions (24h)" value={recentTx.length} />
        <StatCard label="Status" value="Active" subtext="API connected" trend="up" />
      </div>

      {/* Pending Approvals Banner */}
      {pendingCount > 0 && (
        <Link href="/approvals" className="card p-4 flex items-center justify-between hover:border-yellow-500/30 transition-colors">
          <div className="flex items-center gap-3">
            <div className="w-2 h-2 rounded-full bg-yellow-400 animate-pulse" />
            <span className="text-sm font-medium">{pendingCount} transaction{pendingCount !== 1 ? "s" : ""} awaiting approval</span>
          </div>
          <span className="text-xs text-zinc-500">View all →</span>
        </Link>
      )}

      {/* Recent Transactions */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-medium">Recent Transactions</h2>
          <Link href="/transactions" className="text-xs text-zinc-500 hover:text-zinc-300">
            View all →
          </Link>
        </div>

        {recentTx.length === 0 ? (
          <div className="card p-8 text-center text-zinc-500 text-sm">
            No transactions yet. Create an agent to get started.
          </div>
        ) : (
          <div className="card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#262626] text-zinc-500 text-xs uppercase tracking-wider">
                  <th className="text-left p-3 pl-4">Agent</th>
                  <th className="text-left p-3">To</th>
                  <th className="text-left p-3">Value</th>
                  <th className="text-left p-3">Status</th>
                  <th className="text-left p-3 pr-4">Time</th>
                </tr>
              </thead>
              <tbody>
                {recentTx.map((tx: any, i: number) => (
                  <tr key={tx.id || i} className="border-b border-[#262626] last:border-0 hover:bg-white/[0.02]">
                    <td className="p-3 pl-4">
                      <Link href={`/agents/${tx.agentId}`} className="text-zinc-300 hover:text-white">
                        {tx.agentName || shortenAddress(tx.agentId)}
                      </Link>
                    </td>
                    <td className="p-3 font-mono text-xs text-zinc-400">
                      {shortenAddress(tx.request?.to || tx.toAddress || "0x0")}
                    </td>
                    <td className="p-3 tabular-nums">
                      {formatWei(tx.request?.value || tx.value || "0")}
                    </td>
                    <td className="p-3">
                      <span className={`badge ${statusColor(tx.status)}`}>{tx.status}</span>
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

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Link href="/agents" className="card p-5 hover:border-zinc-600 transition-colors group">
          <div className="text-sm font-medium group-hover:text-white transition-colors">Manage Agents</div>
          <div className="text-xs text-zinc-500 mt-1">Create wallets, configure policies, view activity</div>
        </Link>
        <Link href="/approvals" className="card p-5 hover:border-zinc-600 transition-colors group">
          <div className="text-sm font-medium group-hover:text-white transition-colors">Approval Queue</div>
          <div className="text-xs text-zinc-500 mt-1">Review and approve pending transactions</div>
        </Link>
      </div>
    </div>
  );
}

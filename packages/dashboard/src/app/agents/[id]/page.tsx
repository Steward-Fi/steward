"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { steward } from "@/lib/api";
import { shortenAddress, formatDate, formatWei, statusColor, policyTypeLabel } from "@/lib/utils";
import { StatCard } from "@/components/stat-card";
import { EmptyState } from "@/components/empty-state";

export default function AgentDetailPage() {
  const params = useParams();
  const agentId = params.id as string;

  const [agent, setAgent] = useState<any>(null);
  const [policies, setPolicies] = useState<any[]>([]);
  const [transactions, setTransactions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"transactions" | "policies">("transactions");

  useEffect(() => {
    loadAgent();
  }, [agentId]);

  async function loadAgent() {
    try {
      setLoading(true);
      const [agentData, policyData, txData] = await Promise.all([
        steward.getAgent(agentId),
        steward.getPolicies(agentId),
        steward.getHistory(agentId),
      ]);
      setAgent(agentData);
      setPolicies(policyData);
      setTransactions(txData);
    } catch (e: any) {
      console.error("Failed to load agent:", e);
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="animate-pulse space-y-6">
        <div className="h-8 w-64 bg-zinc-800 rounded" />
        <div className="grid grid-cols-3 gap-4">
          {[...Array(3)].map((_, i) => <div key={i} className="card p-5 h-24" />)}
        </div>
      </div>
    );
  }

  if (!agent) {
    return (
      <EmptyState
        icon="◈"
        title="Agent not found"
        description={`No agent found with ID "${agentId}"`}
        action={<Link href="/agents" className="btn btn-primary">Back to Agents</Link>}
      />
    );
  }

  const pendingTx = transactions.filter((tx) => tx.status === "pending");
  const totalVolume = transactions.reduce((sum: bigint, tx: any) => {
    try { return sum + BigInt(tx.request?.value || tx.value || "0"); }
    catch { return sum; }
  }, 0n);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link href="/agents" className="text-zinc-500 hover:text-zinc-300 text-sm">← Agents</Link>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{agent.name}</h1>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-xs text-zinc-500">{agent.id}</span>
            <span className="text-xs text-zinc-600">·</span>
            <span className="font-mono text-xs text-zinc-400">{agent.walletAddress}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <a
            href={`https://basescan.org/address/${agent.walletAddress}`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn btn-ghost text-xs"
          >
            View on BaseScan ↗
          </a>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard label="Transactions" value={transactions.length} />
        <StatCard
          label="Pending Approvals"
          value={pendingTx.length}
          trend={pendingTx.length > 0 ? "up" : "neutral"}
          subtext={pendingTx.length > 0 ? "Action required" : "Clear"}
        />
        <StatCard label="Total Volume" value={formatWei(totalVolume.toString())} />
      </div>

      {/* Tabs */}
      <div className="border-b border-[#262626] flex gap-1">
        {(["transactions", "policies"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 text-sm border-b-2 transition-colors ${
              activeTab === tab
                ? "border-green-500 text-white"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            }`}
          >
            {tab === "transactions" ? `Transactions (${transactions.length})` : `Policies (${policies.length})`}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "transactions" && (
        <div>
          {transactions.length === 0 ? (
            <div className="card p-8 text-center text-zinc-500 text-sm">
              No transactions yet for this agent.
            </div>
          ) : (
            <div className="card overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#262626] text-zinc-500 text-xs uppercase tracking-wider">
                    <th className="text-left p-3 pl-4">To</th>
                    <th className="text-left p-3">Value</th>
                    <th className="text-left p-3">Status</th>
                    <th className="text-left p-3">TX Hash</th>
                    <th className="text-left p-3 pr-4">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {transactions.map((tx: any, i: number) => (
                    <tr key={tx.id || i} className="border-b border-[#262626] last:border-0 hover:bg-white/[0.02]">
                      <td className="p-3 pl-4 font-mono text-xs text-zinc-400">
                        {shortenAddress(tx.request?.to || tx.toAddress || "0x0")}
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
      )}

      {activeTab === "policies" && (
        <div className="space-y-3">
          {policies.length === 0 ? (
            <div className="card p-8 text-center text-zinc-500 text-sm">
              No policies configured. This agent has no spending restrictions.
            </div>
          ) : (
            policies.map((policy: any, i: number) => (
              <div key={policy.id || i} className="card p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${policy.enabled ? "bg-green-400" : "bg-zinc-600"}`} />
                    <div>
                      <div className="text-sm font-medium">{policyTypeLabel(policy.type)}</div>
                      <div className="text-xs text-zinc-500 mt-0.5">
                        {formatPolicyConfig(policy.type, policy.config)}
                      </div>
                    </div>
                  </div>
                  <span className={`badge ${policy.enabled ? "badge-success" : "badge-neutral"}`}>
                    {policy.enabled ? "Active" : "Disabled"}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
}

function formatPolicyConfig(type: string, config: Record<string, any>): string {
  switch (type) {
    case "spending-limit":
      return `Max ${formatWei(config.maxPerTx || "0")}/tx · ${formatWei(config.maxPerDay || "0")}/day`;
    case "approved-addresses":
      return `${config.addresses?.length || 0} addresses (${config.mode || "whitelist"})`;
    case "auto-approve-threshold":
      return `Auto-approve below ${formatWei(config.threshold || "0")}`;
    case "time-window":
      return `${config.allowedHours?.length || 0} time windows · ${config.allowedDays?.length || 7} days`;
    case "rate-limit":
      return `${config.maxTxPerHour || 0}/hour · ${config.maxTxPerDay || 0}/day`;
    default:
      return JSON.stringify(config);
  }
}

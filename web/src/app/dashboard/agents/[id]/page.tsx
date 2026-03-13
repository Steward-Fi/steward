"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import { steward } from "@/lib/api";
import {
  shortenAddress,
  formatDate,
  formatWei,
  policyTypeLabel,
} from "@/lib/utils";
import { StatusBadge } from "@/components/status-badge";
import { CopyButton } from "@/components/copy-button";
import type {
  AgentIdentity,
  PolicyRule,
  TxRecord,
} from "@/lib/steward-client";

export default function AgentDetailPage() {
  const params = useParams();
  const agentId = params.id as string;

  const [agent, setAgent] = useState<AgentIdentity | null>(null);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [transactions, setTransactions] = useState<TxRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<"transactions" | "policies">(
    "transactions"
  );

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
    } catch {
      /* failed */
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="h-8 w-64 bg-bg-surface animate-pulse" />
        <div className="grid grid-cols-3 gap-px bg-border">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-bg p-8 h-28 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="py-20 text-center">
        <p className="font-display text-lg font-600 text-text-secondary">
          Agent not found
        </p>
        <p className="text-sm text-text-tertiary mt-2">
          No agent with ID &ldquo;{agentId}&rdquo;
        </p>
        <Link
          href="/dashboard/agents"
          className="inline-block mt-6 text-xs px-4 py-2 bg-accent text-bg hover:bg-accent-hover transition-colors"
        >
          Back to Agents
        </Link>
      </div>
    );
  }

  const totalVolume = transactions.reduce((sum: bigint, tx) => {
    try {
      return sum + BigInt(tx.request?.value || tx.value || "0");
    } catch {
      return sum;
    }
  }, 0n);

  const pendingCount = transactions.filter(
    (tx) => tx.status === "pending"
  ).length;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-10"
    >
      {/* Header */}
      <div>
        <Link
          href="/dashboard/agents"
          className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
        >
          Agents /
        </Link>

        <div className="flex items-start justify-between mt-3">
          <div>
            <h1 className="font-display text-2xl font-700 tracking-tight">
              {agent.name}
            </h1>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-xs text-text-tertiary">{agent.id}</span>
              <span className="text-border">|</span>
              <div className="flex items-center gap-1">
                <span className="font-mono text-xs text-text-secondary">
                  {agent.walletAddress}
                </span>
                <CopyButton text={agent.walletAddress} />
              </div>
            </div>
          </div>
          <a
            href={`https://basescan.org/address/${agent.walletAddress}`}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-text-tertiary hover:text-text-secondary transition-colors px-3 py-1.5 border border-border hover:border-border"
          >
            BaseScan
          </a>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-border">
        {[
          { label: "Transactions", value: transactions.length },
          {
            label: "Pending",
            value: pendingCount,
            accent: pendingCount > 0,
          },
          {
            label: "Volume",
            value: `${formatWei(totalVolume.toString())} ETH`,
          },
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06, duration: 0.3 }}
            className="bg-bg p-6"
          >
            <div className="text-xs text-text-tertiary tracking-wider uppercase">
              {stat.label}
            </div>
            <div
              className={`font-display text-2xl font-700 mt-2 tabular-nums ${
                stat.accent ? "text-amber-400" : ""
              }`}
            >
              {stat.value}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border-subtle">
        {(["transactions", "policies"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`relative px-4 py-2.5 text-sm transition-colors ${
              activeTab === tab
                ? "text-text"
                : "text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {tab === "transactions"
              ? `Transactions (${transactions.length})`
              : `Policies (${policies.length})`}
            {activeTab === tab && (
              <motion.div
                layoutId="agent-tab-indicator"
                className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent"
                transition={{ type: "tween", duration: 0.2, ease: [0.25, 1, 0.5, 1] }}
              />
            )}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "transactions" && (
        <div>
          {transactions.length === 0 ? (
            <div className="py-16 text-center border border-border-subtle">
              <p className="text-text-tertiary text-sm">
                No transactions for this agent yet.
              </p>
            </div>
          ) : (
            <div className="border-t border-border-subtle">
              {transactions.map((tx, i) => (
                <motion.div
                  key={tx.id || i}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03, duration: 0.3 }}
                  className="flex items-center justify-between py-3.5 border-b border-border-subtle hover:bg-bg-elevated/30 transition-colors px-2 -mx-2"
                >
                  <div className="flex items-center gap-4 min-w-0">
                    <StatusBadge status={tx.status} />
                    <span className="font-mono text-xs text-text-tertiary">
                      {shortenAddress(
                        tx.request?.to || tx.toAddress || "0x0",
                        6
                      )}
                    </span>
                  </div>
                  <div className="flex items-center gap-6 flex-shrink-0">
                    <span className="text-sm tabular-nums text-text-secondary">
                      {formatWei(tx.request?.value || tx.value || "0")} ETH
                    </span>
                    {tx.txHash && (
                      <a
                        href={`https://basescan.org/tx/${tx.txHash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-text-tertiary hover:text-text-secondary transition-colors"
                      >
                        {shortenAddress(tx.txHash, 6)}
                      </a>
                    )}
                    <span className="text-xs text-text-tertiary hidden md:inline">
                      {tx.createdAt ? formatDate(tx.createdAt) : ""}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === "policies" && (
        <div>
          {policies.length === 0 ? (
            <div className="py-16 text-center border border-border-subtle">
              <p className="text-text-tertiary text-sm">
                No policies configured. This agent has no spending restrictions.
              </p>
            </div>
          ) : (
            <div className="space-y-px bg-border">
              {policies.map((policy, i) => (
                <motion.div
                  key={policy.id || i}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.05, duration: 0.3 }}
                  className="bg-bg p-5 flex items-center justify-between"
                >
                  <div className="flex items-center gap-4">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        policy.enabled ? "bg-emerald-400" : "bg-text-tertiary"
                      }`}
                    />
                    <div>
                      <div className="text-sm font-display font-600">
                        {policyTypeLabel(policy.type)}
                      </div>
                      <div className="text-xs text-text-tertiary mt-0.5">
                        {formatPolicyConfig(policy.type, policy.config as Record<string, string>)}
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-xs ${
                      policy.enabled
                        ? "text-emerald-400"
                        : "text-text-tertiary"
                    }`}
                  >
                    {policy.enabled ? "Active" : "Disabled"}
                  </span>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      )}
    </motion.div>
  );
}

function formatPolicyConfig(type: string, config: Record<string, string>): string {
  switch (type) {
    case "spending-limit":
      return `Max ${formatWei(config.maxPerTx || "0")}/tx \u00B7 ${formatWei(config.maxPerDay || "0")}/day`;
    case "approved-addresses": {
      const addresses = config.addresses as unknown;
      const count = Array.isArray(addresses) ? addresses.length : 0;
      return `${count} addresses (${config.mode || "whitelist"})`;
    }
    case "auto-approve-threshold":
      return `Auto-approve below ${formatWei(config.threshold || "0")} ETH`;
    case "time-window": {
      const hours = config.allowedHours as unknown;
      const days = config.allowedDays as unknown;
      return `${Array.isArray(hours) ? hours.length : 0} windows \u00B7 ${Array.isArray(days) ? days.length : 7} days`;
    }
    case "rate-limit":
      return `${config.maxTxPerHour || 0}/hour \u00B7 ${config.maxTxPerDay || 0}/day`;
    default:
      return JSON.stringify(config);
  }
}

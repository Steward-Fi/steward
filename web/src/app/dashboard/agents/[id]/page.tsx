"use client";

import type {
  AgentAccountSummary,
  AgentIdentity,
  AgentSigner,
  PolicyRule,
  PolicyType,
  TxRecord,
} from "@stwd/sdk";
import { motion } from "framer-motion";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { ChainBadge } from "@/components/chain-badge";
import { CopyButton } from "@/components/copy-button";
import { StatusBadge } from "@/components/status-badge";
import { steward } from "@/lib/api";
import { getChainSymbol, getExplorerAddressLink, getExplorerTxLink } from "@/lib/chains";
import { formatDate, formatWei, policyTypeLabel, shortenAddress } from "@/lib/utils";

interface BalanceInfo {
  agentId: string;
  walletAddress: string;
  balances: {
    native: string;
    nativeFormatted: string;
    chainId: number;
    symbol: string;
  };
}

type PortfolioAsset = NonNullable<AgentAccountSummary["portfolio"]["native"]>;

const DEFAULT_SIGNER_PERMISSIONS = "sign_message, sign_transaction";

type DashboardAgentSigner = AgentSigner & {
  policyIds: string[];
  credentialSecret?: string;
};

type SignerFormState = {
  signerType: AgentSigner["signerType"];
  subjectType: AgentSigner["subjectType"];
  subjectId: string;
  keyType: AgentSigner["keyType"];
  publicKey: string;
  label: string;
  permissions: string;
  policyIds: string;
  issueCredential: boolean;
};

type SignerEditState = {
  status: AgentSigner["status"];
  policyIds: string;
};

const DEFAULT_SIGNER_FORM: SignerFormState = {
  signerType: "delegated",
  subjectType: "external",
  subjectId: "",
  keyType: "p256",
  publicKey: "",
  label: "",
  permissions: DEFAULT_SIGNER_PERMISSIONS,
  policyIds: "",
  issueCredential: false,
};

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function joinCsv(values: string[] | null | undefined): string {
  return (values ?? []).join(", ");
}

function buildSignerEdits(signers: DashboardAgentSigner[]): Record<string, SignerEditState> {
  return Object.fromEntries(
    signers.map((signer) => [
      signer.id,
      {
        status: signer.status,
        policyIds: joinCsv(signer.policyIds),
      },
    ]),
  );
}

function signerStatusClass(status: AgentSigner["status"]): string {
  if (status === "active") return "text-emerald-400 border-emerald-400/30 bg-emerald-400/5";
  if (status === "paused") return "text-amber-400 border-amber-400/30 bg-amber-400/5";
  return "text-text-tertiary border-border-subtle bg-bg-elevated/40";
}

function formatUsd(value: number | string | null | undefined): string {
  if (value === null || value === undefined || value === "") return "Unavailable";
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric)) return String(value);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: numeric >= 1 ? 2 : 6,
  }).format(numeric);
}

function formatPortfolioAssetValue(asset: PortfolioAsset): string {
  if (asset.usdValueText) return formatUsd(asset.usdValueText);
  if (asset.usdValue !== null) return formatUsd(asset.usdValue);
  return "No USD price";
}

function PortfolioAssetRow({ asset }: { asset: PortfolioAsset }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-[1fr_180px_160px] gap-3 py-4 border-b border-border-subtle last:border-b-0">
      <div className="min-w-0">
        <div className="text-sm font-medium text-text-secondary truncate">{asset.symbol}</div>
        <div className="font-mono text-xs text-text-tertiary mt-1 break-all">{asset.token}</div>
      </div>
      <div>
        <div className="text-xs text-text-tertiary uppercase tracking-wider">Balance</div>
        <div className="text-sm text-text mt-1 tabular-nums break-all">
          {asset.formatted} {asset.symbol}
        </div>
      </div>
      <div>
        <div className="text-xs text-text-tertiary uppercase tracking-wider">USD Value</div>
        <div className="text-sm text-text mt-1 tabular-nums">
          {formatPortfolioAssetValue(asset)}
        </div>
      </div>
    </div>
  );
}

// All canonical policy types with sensible display defaults
const ALL_POLICY_TYPES: {
  type: PolicyType;
  defaultConfig: Record<string, unknown>;
}[] = [
  {
    type: "spending-limit",
    defaultConfig: { maxPerTx: "0", maxPerDay: "0" },
  },
  {
    type: "approved-addresses",
    defaultConfig: { addresses: [], mode: "whitelist" },
  },
  {
    type: "auto-approve-threshold",
    defaultConfig: { threshold: "0" },
  },
  {
    type: "time-window",
    defaultConfig: { allowedHours: [], allowedDays: [] },
  },
  {
    type: "rate-limit",
    defaultConfig: { maxTxPerHour: 0, maxTxPerDay: 0 },
  },
  {
    type: "allowed-chains",
    defaultConfig: { chainIds: [] },
  },
];

/** Merge API-returned policies with default stubs for any missing types */
function mergePolicies(apiPolicies: PolicyRule[]): PolicyRule[] {
  return ALL_POLICY_TYPES.map((pt, i) => {
    const existing = apiPolicies.find((p) => p.type === pt.type);
    if (existing) return existing;
    return {
      id: `default-${pt.type}-${i}`,
      type: pt.type,
      enabled: false,
      config: pt.defaultConfig,
    };
  });
}

export default function AgentDetailPage() {
  const params = useParams();
  const agentId = params?.id as string;

  const [agent, setAgent] = useState<AgentIdentity | null>(null);
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [transactions, setTransactions] = useState<TxRecord[]>([]);
  const [signers, setSigners] = useState<DashboardAgentSigner[]>([]);
  const [balance, setBalance] = useState<BalanceInfo | null>(null);
  const [account, setAccount] = useState<AgentAccountSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [policiesError, setPoliciesError] = useState<string | null>(null);
  const [transactionsError, setTransactionsError] = useState<string | null>(null);
  const [signersError, setSignersError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"transactions" | "policies" | "signers">(
    "transactions",
  );
  const [signerForm, setSignerForm] = useState<SignerFormState>(DEFAULT_SIGNER_FORM);
  const [signerEdits, setSignerEdits] = useState<Record<string, SignerEditState>>({});
  const [creatingSigner, setCreatingSigner] = useState(false);
  const [createSignerError, setCreateSignerError] = useState<string | null>(null);
  const [createdCredential, setCreatedCredential] = useState<{
    signerId: string;
    credentialSecret: string;
  } | null>(null);
  const [savingSignerId, setSavingSignerId] = useState<string | null>(null);

  const loadAgent = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      // Load policies/transactions alongside the agent, but track their failures
      // independently. Collapsing a failed fetch into an empty array would make a
      // load error look identical to "no policies"/"no transactions" — and on a
      // wallet-security page that could read as "this wallet is unprotected".
      setPoliciesError(null);
      setTransactionsError(null);
      setSignersError(null);
      const [agentData, policyResult, txResult, signerResult] = await Promise.all([
        steward.getAgent(agentId),
        steward
          .getPolicies(agentId)
          .then((data) => ({ data }) as const)
          .catch(
            (err: unknown) =>
              ({
                error: err instanceof Error ? err.message : "Failed to load policies",
              }) as const,
          ),
        steward
          .getTransactionHistory(agentId)
          .then((data) => ({ data }) as const)
          .catch(
            (err: unknown) =>
              ({
                error: err instanceof Error ? err.message : "Failed to load transactions",
              }) as const,
          ),
        steward
          .listAgentSigners(agentId)
          .then((data) => ({ data: data as DashboardAgentSigner[] }) as const)
          .catch(
            (err: unknown) =>
              ({
                error: err instanceof Error ? err.message : "Failed to load signers",
              }) as const,
          ),
      ]);
      setAgent(agentData);

      if ("error" in policyResult) {
        setPoliciesError(policyResult.error);
        setPolicies(mergePolicies([]));
      } else {
        setPolicies(mergePolicies(policyResult.data));
      }

      if ("error" in txResult) {
        setTransactionsError(txResult.error);
        setTransactions([]);
      } else {
        setTransactions(txResult.data);
      }

      if ("error" in signerResult) {
        setSignersError(signerResult.error);
        setSigners([]);
        setSignerEdits({});
      } else {
        setSigners(signerResult.data);
        setSignerEdits(buildSignerEdits(signerResult.data));
      }

      // Fetch account aggregation separately so the legacy detail shell still loads
      // if portfolio providers are unavailable.
      try {
        const accountData = await steward.getAgentAccount(agentId);
        setAccount(accountData);
      } catch {
        setAccount(null);
      }

      // Keep the older balance endpoint as a fallback for deployments that have
      // not enabled the richer account aggregation route yet.
      try {
        const balanceData = await steward.getBalance(agentId);
        setBalance(balanceData as BalanceInfo);
      } catch {
        /* balance endpoint may not be available */
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load agent");
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  async function createSigner(e: React.FormEvent) {
    e.preventDefault();
    if (!signerForm.subjectId.trim()) return;
    if (signerForm.keyType === "p256" && !signerForm.publicKey.trim()) return;

    setCreateSignerError(null);
    setCreatedCredential(null);
    try {
      setCreatingSigner(true);
      const created = (await steward.createAgentSigner(agentId, {
        signerType: signerForm.signerType,
        subjectType: signerForm.subjectType,
        subjectId: signerForm.subjectId.trim(),
        keyType: signerForm.keyType,
        publicKey: signerForm.keyType === "p256" ? signerForm.publicKey.trim() : null,
        label: signerForm.label.trim() || null,
        permissions: splitCsv(signerForm.permissions),
        policyIds: splitCsv(signerForm.policyIds),
        issueCredential: signerForm.keyType === "hmac" ? signerForm.issueCredential : undefined,
      } as unknown as Parameters<typeof steward.createAgentSigner>[1])) as DashboardAgentSigner;
      setSigners((prev) => [created, ...prev.filter((signer) => signer.id !== created.id)]);
      setSignerEdits((prev) => ({
        ...prev,
        [created.id]: {
          status: created.status,
          policyIds: joinCsv(created.policyIds),
        },
      }));
      if (created.credentialSecret) {
        setCreatedCredential({ signerId: created.id, credentialSecret: created.credentialSecret });
      }
      setSignerForm(DEFAULT_SIGNER_FORM);
    } catch (err: unknown) {
      setCreateSignerError(err instanceof Error ? err.message : "Failed to create signer");
    } finally {
      setCreatingSigner(false);
    }
  }

  async function saveSigner(signer: DashboardAgentSigner) {
    const edit = signerEdits[signer.id];
    if (!edit) return;

    setSavingSignerId(signer.id);
    setCreateSignerError(null);
    try {
      const updated = (await steward.updateAgentSigner(agentId, signer.id, {
        status: edit.status,
        policyIds: splitCsv(edit.policyIds),
      } as unknown as Parameters<typeof steward.updateAgentSigner>[2])) as DashboardAgentSigner;
      setSigners((prev) => prev.map((current) => (current.id === updated.id ? updated : current)));
      setSignerEdits((prev) => ({
        ...prev,
        [updated.id]: {
          status: updated.status,
          policyIds: joinCsv(updated.policyIds),
        },
      }));
    } catch (err: unknown) {
      setCreateSignerError(err instanceof Error ? err.message : "Failed to update signer");
    } finally {
      setSavingSignerId(null);
    }
  }

  async function revokeSigner(signer: DashboardAgentSigner) {
    const confirmed = window.confirm(`Revoke signer ${signer.subjectId}?`);
    if (!confirmed) return;

    setSavingSignerId(signer.id);
    setCreateSignerError(null);
    try {
      const updated = (await steward.revokeAgentSigner(agentId, signer.id)) as DashboardAgentSigner;
      setSigners((prev) => prev.map((current) => (current.id === updated.id ? updated : current)));
      setSignerEdits((prev) => ({
        ...prev,
        [updated.id]: {
          status: updated.status,
          policyIds: joinCsv(updated.policyIds),
        },
      }));
    } catch (err: unknown) {
      setCreateSignerError(err instanceof Error ? err.message : "Failed to revoke signer");
    } finally {
      setSavingSignerId(null);
    }
  }

  useEffect(() => {
    void loadAgent();
  }, [loadAgent]);

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="h-8 w-64 bg-bg-surface animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-border">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-bg p-8 h-28 animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="py-20 text-center">
        <p className="font-display text-lg font-600 text-text-secondary">Failed to load agent</p>
        <p className="text-sm text-text-tertiary mt-2 font-mono">{error}</p>
        <div className="flex items-center justify-center gap-3 mt-6">
          <button
            onClick={loadAgent}
            className="text-xs px-4 py-2 bg-accent text-bg hover:bg-accent-hover transition-colors"
          >
            Retry
          </button>
          <Link
            href="/dashboard/agents"
            className="text-xs px-4 py-2 text-text-tertiary hover:text-text-secondary transition-colors"
          >
            Back to Agents
          </Link>
        </div>
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="py-20 text-center">
        <p className="font-display text-lg font-600 text-text-secondary">Agent not found</p>
        <p className="text-sm text-text-tertiary mt-2">No agent with ID &ldquo;{agentId}&rdquo;</p>
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
      return sum + BigInt(tx.request?.value || "0");
    } catch {
      return sum;
    }
  }, 0n);

  const pendingCount = transactions.filter((tx) => tx.status === "pending").length;

  const activePolicies = policies.filter((p) => p.enabled).length;
  const availablePolicyIds = policies
    .filter((policy) => !policy.id.startsWith("default-"))
    .map((policy) => policy.id);
  const activeSigners = signers.filter((signer) => signer.status === "active").length;
  const portfolio = account?.portfolio;
  const nativeAsset = portfolio?.native;
  const tokenAssets = portfolio?.tokens ?? [];
  const wallets = account?.wallets ?? [];
  const capabilities = account?.capabilities ?? [];
  const nativeBalanceLabel = nativeAsset
    ? `${nativeAsset.formatted} ${nativeAsset.symbol}`
    : balance
      ? `${balance.balances.nativeFormatted || formatWei(balance.balances.native || "0")} ${balance.balances.symbol || "ETH"}`
      : "—";

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
      className="space-y-10"
    >
      {/* Breadcrumb + Header */}
      <div>
        <Link
          href="/dashboard/agents"
          className="text-xs text-text-tertiary hover:text-text-secondary transition-colors"
        >
          Agents /
        </Link>

        <div className="flex items-start justify-between mt-3">
          <div>
            <h1 className="font-display text-2xl font-700 tracking-tight">{agent.name}</h1>
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              <span className="text-xs text-text-tertiary">{agent.id}</span>
              {agent.platformId && (
                <>
                  <span className="text-border">|</span>
                  <span className="text-xs text-text-tertiary">{agent.platformId}</span>
                </>
              )}
              <span className="text-border">|</span>
              <div className="flex items-center gap-1">
                <span className="font-mono text-xs text-text-secondary">{agent.walletAddress}</span>
                <CopyButton text={agent.walletAddress} />
              </div>
            </div>
          </div>
          <a
            href={
              getExplorerAddressLink(
                transactions[0]?.request?.chainId ?? 8453,
                agent.walletAddress,
              ) || `https://basescan.org/address/${agent.walletAddress}`
            }
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs text-text-tertiary hover:text-text-secondary transition-colors px-3 py-1.5 border border-border hover:border-border flex-shrink-0"
          >
            Explorer ↗
          </a>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-px bg-border">
        {[
          {
            label: "Balance",
            value: nativeBalanceLabel,
          },
          {
            label: "Portfolio",
            value: portfolio ? formatUsd(portfolio.totalUsdText ?? portfolio.totalUsd) : "—",
          },
          {
            label: "Transactions",
            value: transactionsError ? "Unavailable" : transactions.length,
            accent: Boolean(transactionsError),
          },
          {
            label: "Pending",
            value: transactionsError ? "Unavailable" : pendingCount,
            accent: Boolean(transactionsError) || pendingCount > 0,
          },
          {
            label: "Volume",
            value: transactionsError ? "Unavailable" : `${formatWei(totalVolume.toString())} ETH`,
            accent: Boolean(transactionsError),
          },
          {
            label: "Active Policies",
            value: policiesError ? "Unavailable" : `${activePolicies} / ${policies.length}`,
            accent: Boolean(policiesError) || activePolicies === 0,
          },
        ].map((stat, i) => (
          <motion.div
            key={stat.label}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06, duration: 0.3 }}
            className="bg-bg p-6"
          >
            <div className="text-xs text-text-tertiary tracking-wider uppercase">{stat.label}</div>
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

      {/* Account aggregation */}
      <section className="space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="font-display text-lg font-600">Account Portfolio</h2>
            <p className="text-xs text-text-tertiary mt-1">
              Wallets, token assets, sponsorship state, and signing capabilities
            </p>
          </div>
          <span className="text-xs text-text-tertiary">
            {account?.sponsorship.enabled ? "Gas sponsorship enabled" : "Gas sponsorship off"}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border">
          <div className="bg-bg p-5">
            <div className="text-xs text-text-tertiary tracking-wider uppercase">Wallets</div>
            <div className="font-display text-2xl font-700 mt-2 tabular-nums">{wallets.length}</div>
            <div className="text-xs text-text-tertiary mt-1">
              {portfolio?.walletAddress
                ? shortenAddress(portfolio.walletAddress, 6)
                : agent.walletAddress}
            </div>
          </div>
          <div className="bg-bg p-5">
            <div className="text-xs text-text-tertiary tracking-wider uppercase">Native Asset</div>
            <div className="font-display text-2xl font-700 mt-2 tabular-nums">
              {nativeBalanceLabel}
            </div>
            <div className="text-xs text-text-tertiary mt-1">
              {nativeAsset ? formatPortfolioAssetValue(nativeAsset) : portfolio?.unavailableReason}
            </div>
          </div>
          <div className="bg-bg p-5">
            <div className="text-xs text-text-tertiary tracking-wider uppercase">Token Assets</div>
            <div className="font-display text-2xl font-700 mt-2 tabular-nums">
              {tokenAssets.length}
            </div>
            <div className="text-xs text-text-tertiary mt-1">
              {portfolio?.chainId ? `Chain ${portfolio.chainId}` : "Best effort"}
            </div>
          </div>
        </div>

        <div className="border-t border-border-subtle">
          {nativeAsset && <PortfolioAssetRow asset={nativeAsset} />}
          {tokenAssets.map((asset) => (
            <PortfolioAssetRow key={`${asset.token}:${asset.symbol}`} asset={asset} />
          ))}
          {!nativeAsset && tokenAssets.length === 0 && (
            <div className="py-10 text-sm text-text-tertiary">
              {portfolio?.unavailableReason ?? "No portfolio assets returned"}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div>
            <h3 className="text-xs text-text-tertiary tracking-wider uppercase mb-3">
              Wallet Rows
            </h3>
            <div className="border-t border-border-subtle">
              {wallets.length === 0 ? (
                <div className="py-6 text-sm text-text-tertiary">No wallet rows returned</div>
              ) : (
                wallets.map((wallet) => (
                  <div
                    key={wallet.id}
                    className="py-4 border-b border-border-subtle last:border-b-0"
                  >
                    <div className="font-mono text-sm text-text break-all">{wallet.address}</div>
                    <div className="text-xs text-text-tertiary mt-1">
                      {wallet.chainFamily} · {wallet.purpose ?? "agent wallet"}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
          <div>
            <h3 className="text-xs text-text-tertiary tracking-wider uppercase mb-3">
              Capabilities
            </h3>
            <div className="flex flex-wrap gap-2">
              {capabilities.length === 0 ? (
                <span className="text-sm text-text-tertiary">No capabilities returned</span>
              ) : (
                capabilities.map((capability) => (
                  <span
                    key={capability}
                    className="border border-border-subtle px-2.5 py-1 text-xs text-text-secondary font-mono"
                  >
                    {capability}
                  </span>
                ))
              )}
            </div>
          </div>
        </div>
      </section>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border-subtle">
        {(["transactions", "policies", "signers"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`relative px-4 py-2.5 text-sm transition-colors ${
              activeTab === tab ? "text-text" : "text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {tab === "transactions"
              ? `Transactions ${transactionsError ? "(!)" : `(${transactions.length})`}`
              : tab === "policies"
                ? `Policies ${policiesError ? "(!)" : `(${activePolicies}/${policies.length})`}`
                : `Signers ${signersError ? "(!)" : `(${activeSigners}/${signers.length})`}`}
            {activeTab === tab && (
              <motion.div
                layoutId="agent-tab-indicator"
                className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent"
                transition={{
                  type: "tween",
                  duration: 0.2,
                  ease: [0.25, 1, 0.5, 1],
                }}
              />
            )}
          </button>
        ))}
      </div>

      {/* Transactions Tab */}
      {activeTab === "transactions" && (
        <div>
          {transactionsError ? (
            <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
              <p className="text-text-secondary text-sm mb-1">Couldn&apos;t load transactions</p>
              <p className="text-text-tertiary text-xs mb-4 font-mono">{transactionsError}</p>
              <button
                onClick={loadAgent}
                className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
              >
                Retry
              </button>
            </div>
          ) : transactions.length === 0 ? (
            <div className="py-16 text-center border border-border-subtle">
              <p className="text-text-tertiary text-sm">No transactions for this agent yet.</p>
            </div>
          ) : (
            <div className="border-t border-border-subtle">
              {/* Column headers */}
              <div className="hidden md:flex items-center py-2 border-b border-border text-xs text-text-tertiary tracking-wider uppercase px-2">
                <span className="w-28">Status</span>
                <span className="w-20">Chain</span>
                <span className="flex-1">To</span>
                <span className="w-28 text-right">Value</span>
                <span className="w-36 text-right">TX Hash</span>
                <span className="w-32 text-right">Time</span>
              </div>
              {transactions.map((tx, i) => (
                <motion.div
                  key={tx.id || i}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03, duration: 0.3 }}
                  className="flex flex-col md:flex-row md:items-center py-3.5 border-b border-border-subtle hover:bg-bg-elevated/30 transition-colors px-2 gap-2 md:gap-0"
                >
                  <div className="w-28">
                    <StatusBadge status={tx.status} />
                  </div>
                  <div className="w-20">
                    <ChainBadge chainId={tx.request?.chainId ?? 8453} compact />
                  </div>
                  <div className="flex-1 min-w-0">
                    <span className="font-mono text-xs text-text-tertiary">
                      {shortenAddress(tx.request?.to || "0x0", 8)}
                    </span>
                  </div>
                  <div className="w-28 text-right">
                    <span className="text-sm tabular-nums text-text-secondary">
                      {formatWei(
                        tx.request?.value || "0",
                        getChainSymbol(tx.request?.chainId ?? 8453),
                      )}
                    </span>
                  </div>
                  <div className="w-36 text-right">
                    {tx.txHash ? (
                      <a
                        href={getExplorerTxLink(tx.request?.chainId ?? 8453, tx.txHash) || "#"}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-xs text-accent hover:text-accent-hover transition-colors"
                        title={tx.txHash}
                      >
                        {shortenAddress(tx.txHash, 6)} ↗
                      </a>
                    ) : (
                      <span className="text-xs text-text-tertiary">&mdash;</span>
                    )}
                  </div>
                  <div className="w-32 text-right">
                    <span className="text-xs text-text-tertiary">
                      {tx.createdAt ? formatDate(tx.createdAt) : ""}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Policies Tab */}
      {activeTab === "policies" &&
        (policiesError ? (
          // Never collapse a failed policy load into the "all disabled" placeholder
          // list — on a wallet-security page that would falsely imply this wallet has
          // no protections configured. Surface the failure explicitly instead.
          <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
            <p className="text-text-secondary text-sm mb-1">Couldn&apos;t load policies</p>
            <p className="text-text-tertiary text-xs mb-2 font-mono">{policiesError}</p>
            <p className="text-text-tertiary text-xs mb-4 max-w-md mx-auto">
              Policy state is unavailable — this does not mean the wallet is unprotected. Retry to
              load the agent&apos;s active policies.
            </p>
            <button
              onClick={loadAgent}
              className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
            >
              Retry
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            <p className="text-xs text-text-tertiary mb-4">
              All 5 policy types are shown. Disabled policies are placeholders — configure them via
              the API or SDK.
            </p>
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
                      className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                        policy.enabled ? "bg-emerald-400" : "bg-text-tertiary/30"
                      }`}
                    />
                    <div>
                      <div
                        className={`text-sm font-display font-600 ${
                          policy.enabled ? "text-text" : "text-text-tertiary"
                        }`}
                      >
                        {policyTypeLabel(policy.type)}
                      </div>
                      <div className="text-xs text-text-tertiary mt-0.5">
                        {policy.enabled
                          ? formatPolicyConfig(policy.type, policy.config as Record<string, string>)
                          : "Not configured"}
                      </div>
                    </div>
                  </div>
                  <span
                    className={`text-xs flex-shrink-0 ${
                      policy.enabled ? "text-emerald-400" : "text-text-tertiary/50"
                    }`}
                  >
                    {policy.enabled ? "Active" : "Disabled"}
                  </span>
                </motion.div>
              ))}
            </div>
          </div>
        ))}

      {/* Signers Tab */}
      {activeTab === "signers" &&
        (signersError ? (
          <div className="py-16 text-center border border-red-400/20 bg-red-400/5">
            <p className="text-text-secondary text-sm mb-1">Couldn&apos;t load signers</p>
            <p className="text-text-tertiary text-xs mb-4 font-mono">{signersError}</p>
            <button
              onClick={loadAgent}
              className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors"
            >
              Retry
            </button>
          </div>
        ) : (
          <div className="space-y-8">
            <form onSubmit={createSigner} className="border border-border bg-bg-elevated p-5">
              <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4">
                <div>
                  <h3 className="font-display text-sm font-600">Create Authorization Key</h3>
                  <p className="text-xs text-text-tertiary mt-1">
                    {availablePolicyIds.length > 0
                      ? `Available policy IDs: ${availablePolicyIds.join(", ")}`
                      : "No configured policy IDs returned for this agent"}
                  </p>
                </div>
                <button
                  type="submit"
                  disabled={
                    creatingSigner ||
                    !signerForm.subjectId.trim() ||
                    (signerForm.keyType === "p256" && !signerForm.publicKey.trim())
                  }
                  className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40 disabled:cursor-not-allowed font-medium"
                >
                  {creatingSigner ? "Creating..." : "Create Signer"}
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-5">
                <div>
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="signer-type">
                    Signer Type
                  </label>
                  <select
                    id="signer-type"
                    value={signerForm.signerType}
                    onChange={(e) =>
                      setSignerForm({
                        ...signerForm,
                        signerType: e.target.value as AgentSigner["signerType"],
                      })
                    }
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                  >
                    <option value="delegated">Delegated</option>
                    <option value="service">Service</option>
                    <option value="owner">Owner</option>
                    <option value="quorum_member">Quorum member</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="subject-type">
                    Subject Type
                  </label>
                  <select
                    id="subject-type"
                    value={signerForm.subjectType}
                    onChange={(e) =>
                      setSignerForm({
                        ...signerForm,
                        subjectType: e.target.value as AgentSigner["subjectType"],
                      })
                    }
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                  >
                    <option value="external">External</option>
                    <option value="user">User</option>
                    <option value="wallet">Wallet</option>
                    <option value="api_key">API key</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="key-type">
                    Key Type
                  </label>
                  <select
                    id="key-type"
                    value={signerForm.keyType}
                    onChange={(e) =>
                      setSignerForm({
                        ...signerForm,
                        keyType: e.target.value as AgentSigner["keyType"],
                        issueCredential:
                          e.target.value === "hmac" ? signerForm.issueCredential : false,
                      })
                    }
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                  >
                    <option value="p256">P-256 authorization key</option>
                    <option value="hmac">HMAC delegated secret</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="signer-label">
                    Label
                  </label>
                  <input
                    id="signer-label"
                    type="text"
                    value={signerForm.label}
                    onChange={(e) => setSignerForm({ ...signerForm, label: e.target.value })}
                    placeholder="Ops signer"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                  />
                </div>
                <div>
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="subject-id">
                    Subject ID <span className="text-accent">*</span>
                  </label>
                  <input
                    id="subject-id"
                    type="text"
                    value={signerForm.subjectId}
                    onChange={(e) => setSignerForm({ ...signerForm, subjectId: e.target.value })}
                    placeholder="ops-key-1"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                  />
                </div>
                <div>
                  <label
                    className="text-xs text-text-tertiary block mb-1.5"
                    htmlFor="signer-permissions"
                  >
                    Permissions
                  </label>
                  <input
                    id="signer-permissions"
                    type="text"
                    value={signerForm.permissions}
                    onChange={(e) => setSignerForm({ ...signerForm, permissions: e.target.value })}
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                  />
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="policy-ids">
                    Policy IDs
                  </label>
                  <input
                    id="policy-ids"
                    type="text"
                    value={signerForm.policyIds}
                    onChange={(e) => setSignerForm({ ...signerForm, policyIds: e.target.value })}
                    placeholder="policy_daily_limit, policy_sol_transfer"
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                  />
                </div>
              </div>

              {signerForm.keyType === "p256" ? (
                <div className="mt-4">
                  <label className="text-xs text-text-tertiary block mb-1.5" htmlFor="public-key">
                    Public Key <span className="text-accent">*</span>
                  </label>
                  <textarea
                    id="public-key"
                    value={signerForm.publicKey}
                    onChange={(e) => setSignerForm({ ...signerForm, publicKey: e.target.value })}
                    placeholder="BASE64_SPKI_P256_PUBLIC_KEY"
                    rows={3}
                    className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors font-mono resize-y"
                  />
                </div>
              ) : (
                <label className="flex items-center gap-2 mt-4 text-sm text-text-secondary">
                  <input
                    type="checkbox"
                    checked={signerForm.issueCredential}
                    onChange={(e) =>
                      setSignerForm({ ...signerForm, issueCredential: e.target.checked })
                    }
                    className="accent-[oklch(0.75_0.15_55)]"
                  />
                  Issue delegated credential secret
                </label>
              )}

              {createdCredential && (
                <div className="mt-4 border border-amber-400/30 bg-amber-400/5 p-3">
                  <div className="text-xs text-amber-300 mb-1">One-time credential secret</div>
                  <div className="flex items-center gap-2">
                    <code className="font-mono text-xs text-text break-all flex-1">
                      {createdCredential.credentialSecret}
                    </code>
                    <CopyButton text={createdCredential.credentialSecret} />
                  </div>
                  <div className="font-mono text-xs text-text-tertiary mt-1">
                    signerId: {createdCredential.signerId}
                  </div>
                </div>
              )}

              {createSignerError && (
                <p className="text-xs text-red-400 font-mono mt-4">{createSignerError}</p>
              )}
            </form>

            {signers.length === 0 ? (
              <div className="py-16 text-center border border-border-subtle">
                <p className="text-text-tertiary text-sm">No signers for this agent yet.</p>
              </div>
            ) : (
              <div className="space-y-px bg-border">
                {signers.map((signer, i) => {
                  const edit = signerEdits[signer.id] ?? {
                    status: signer.status,
                    policyIds: joinCsv(signer.policyIds),
                  };
                  return (
                    <motion.div
                      key={signer.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: i * 0.04, duration: 0.3 }}
                      className="bg-bg p-5"
                    >
                      <div className="grid grid-cols-1 lg:grid-cols-[1fr_220px_280px] gap-5">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-display font-600 text-sm text-text">
                              {signer.label || signer.subjectId}
                            </span>
                            <span
                              className={`border px-2 py-0.5 text-[11px] uppercase ${signerStatusClass(
                                signer.status,
                              )}`}
                            >
                              {signer.status}
                            </span>
                            <span className="border border-border-subtle px-2 py-0.5 text-[11px] text-text-tertiary uppercase">
                              {signer.keyType}
                            </span>
                          </div>
                          <div className="font-mono text-xs text-text-tertiary mt-2 break-all">
                            {signer.subjectType}:{signer.subjectId}
                          </div>
                          <div className="text-xs text-text-tertiary mt-2">
                            {signer.permissions.length > 0
                              ? signer.permissions.join(", ")
                              : "No permissions"}
                            {signer.hasCredential ? " · credential stored" : ""}
                          </div>
                          {signer.publicKey && (
                            <div className="font-mono text-xs text-text-tertiary mt-2 break-all">
                              publicKey: {signer.publicKey}
                            </div>
                          )}
                        </div>

                        <div>
                          <label
                            className="text-xs text-text-tertiary block mb-1.5"
                            htmlFor={`signer-status-${signer.id}`}
                          >
                            Status
                          </label>
                          <select
                            id={`signer-status-${signer.id}`}
                            value={edit.status}
                            onChange={(e) =>
                              setSignerEdits((prev) => ({
                                ...prev,
                                [signer.id]: {
                                  ...edit,
                                  status: e.target.value as AgentSigner["status"],
                                },
                              }))
                            }
                            className="w-full bg-bg border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent transition-colors"
                          >
                            <option value="active">Active</option>
                            <option value="paused">Paused</option>
                            <option value="revoked">Revoked</option>
                          </select>
                        </div>

                        <div>
                          <label
                            className="text-xs text-text-tertiary block mb-1.5"
                            htmlFor={`signer-policies-${signer.id}`}
                          >
                            Policy IDs
                          </label>
                          <input
                            id={`signer-policies-${signer.id}`}
                            type="text"
                            value={edit.policyIds}
                            onChange={(e) =>
                              setSignerEdits((prev) => ({
                                ...prev,
                                [signer.id]: { ...edit, policyIds: e.target.value },
                              }))
                            }
                            className="w-full bg-bg border border-border px-3 py-2 text-sm text-text placeholder:text-text-tertiary focus:outline-none focus:border-accent transition-colors"
                          />
                          <div className="flex items-center gap-2 mt-3">
                            <button
                              type="button"
                              aria-label={`Save signer ${signer.subjectId}`}
                              onClick={() => saveSigner(signer)}
                              disabled={savingSignerId === signer.id}
                              className="px-3 py-1.5 text-xs bg-accent text-bg hover:bg-accent-hover transition-colors disabled:opacity-40"
                            >
                              {savingSignerId === signer.id ? "Saving..." : "Save"}
                            </button>
                            <button
                              type="button"
                              aria-label={`Revoke signer ${signer.subjectId}`}
                              onClick={() => revokeSigner(signer)}
                              disabled={savingSignerId === signer.id || signer.status === "revoked"}
                              className="px-3 py-1.5 text-xs text-red-300 hover:text-red-200 transition-colors disabled:opacity-40"
                            >
                              Revoke
                            </button>
                          </div>
                        </div>
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </div>
        ))}
    </motion.div>
  );
}

function formatPolicyConfig(type: string, config: Record<string, string>): string {
  switch (type) {
    case "spending-limit":
      return `Max ${formatWei(config.maxPerTx || "0")} ETH/tx · ${formatWei(
        config.maxPerDay || "0",
      )} ETH/day`;
    case "approved-addresses": {
      const addresses = config.addresses as unknown;
      const count = Array.isArray(addresses) ? addresses.length : 0;
      return `${count} address${count !== 1 ? "es" : ""} (${config.mode || "whitelist"})`;
    }
    case "auto-approve-threshold":
      return `Auto-approve below ${formatWei(config.threshold || "0")} ETH`;
    case "time-window": {
      const hours = config.allowedHours as unknown;
      const days = config.allowedDays as unknown;
      return `${Array.isArray(hours) ? hours.length : 0} hour windows · ${
        Array.isArray(days) ? days.length : 7
      } days/week`;
    }
    case "rate-limit":
      return `${config.maxTxPerHour || 0}/hour · ${config.maxTxPerDay || 0}/day`;
    case "allowed-chains": {
      const chainIds = config.chainIds as unknown;
      const count = Array.isArray(chainIds) ? chainIds.length : 0;
      return `${count} chain${count !== 1 ? "s" : ""} allowed`;
    }
    default:
      return JSON.stringify(config);
  }
}

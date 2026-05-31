"use client";

import type {
  GlobalWalletConsent,
  UserAccountSummary,
  UserAccountsResult,
  UserLinkedAccount,
} from "@stwd/sdk";
import { motion } from "framer-motion";
import { useCallback, useEffect, useMemo, useState } from "react";
import { steward } from "@/lib/api";
import { formatDate, formatWei, shortenAddress } from "@/lib/utils";

type LoadState = {
  accounts: UserAccountsResult | null;
  summary: UserAccountSummary | null;
  globalWalletConsents: GlobalWalletConsent[];
};

type PortfolioAsset = NonNullable<UserAccountSummary["portfolio"]["native"]>;

const providerLabels: Record<string, string> = {
  discord: "Discord",
  email: "Email",
  ethereum: "Ethereum",
  farcaster: "Farcaster",
  github: "GitHub",
  google: "Google",
  linkedin: "LinkedIn",
  passkey: "Passkey",
  phone: "Phone",
  sms: "SMS",
  solana: "Solana",
  telegram: "Telegram",
  twitter: "X",
  wallet: "Wallet",
  whatsapp: "WhatsApp",
};

function labelProvider(provider: string): string {
  return (
    providerLabels[provider.toLowerCase()] ??
    provider
      .split(/[-_]/g)
      .filter(Boolean)
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(" ")
  );
}

function displayAccountId(provider: string, accountId: string): string {
  if (/^(0x[a-fA-F0-9]{40}|[1-9A-HJ-NP-Za-km-z]{32,44})$/.test(accountId)) {
    return shortenAddress(accountId, 6);
  }
  if (provider === "passkey" && accountId.length > 24) {
    return `${accountId.slice(0, 10)}...${accountId.slice(-8)}`;
  }
  return accountId;
}

function providerTone(provider: string): string {
  switch (provider.toLowerCase()) {
    case "email":
    case "google":
    case "discord":
    case "github":
    case "linkedin":
    case "twitter":
      return "border-info/30 text-info";
    case "wallet":
    case "ethereum":
    case "solana":
      return "border-accent/40 text-[oklch(0.78_0.15_55)]";
    case "passkey":
      return "border-success/30 text-success";
    case "phone":
    case "sms":
    case "whatsapp":
      return "border-warning/30 text-warning";
    default:
      return "border-border text-text-secondary";
  }
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

function Stat({
  label,
  value,
  detail,
}: {
  label: string;
  value: string | number;
  detail?: string;
}) {
  return (
    <div className="border border-border-subtle p-5 min-h-28">
      <div className="text-xs text-text-tertiary tracking-wider uppercase">{label}</div>
      <div className="font-display text-2xl font-700 mt-2 tabular-nums truncate">{value}</div>
      {detail && <div className="text-xs text-text-tertiary mt-1 truncate">{detail}</div>}
    </div>
  );
}

function MethodRow({
  provider,
  accountId,
  expiresAt,
  action,
  busy,
}: {
  provider: string;
  accountId: string;
  expiresAt?: number | null;
  action?: React.ReactNode;
  busy?: boolean;
}) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 py-4 border-b border-border-subtle last:border-b-0">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center border px-2 py-0.5 text-[11px] leading-5 uppercase tracking-wider ${providerTone(provider)}`}
          >
            {labelProvider(provider)}
          </span>
          {busy && <span className="text-xs text-text-tertiary">Updating...</span>}
        </div>
        <div className="font-mono text-sm text-text mt-2 break-all">
          {displayAccountId(provider, accountId)}
        </div>
        {expiresAt ? (
          <div className="text-xs text-text-tertiary mt-1">
            Token expires {formatDate(new Date(expiresAt * 1000).toISOString())}
          </div>
        ) : null}
      </div>
      {action}
    </div>
  );
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

export default function DashboardAccountPage() {
  const [state, setState] = useState<LoadState>({
    accounts: null,
    summary: null,
    globalWalletConsents: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [unlinking, setUnlinking] = useState<string | null>(null);
  const [revokingConsent, setRevokingConsent] = useState<string | null>(null);

  const loadAccount = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [accounts, summaryResult, globalWalletConsents] = await Promise.allSettled([
        steward.listUserAccounts(),
        steward.getUserAccount(),
        steward.listGlobalWalletConsents(),
      ]);

      if (accounts.status === "rejected") throw accounts.reason;

      setState({
        accounts: accounts.value,
        summary: summaryResult.status === "fulfilled" ? summaryResult.value : null,
        globalWalletConsents:
          globalWalletConsents.status === "fulfilled" ? globalWalletConsents.value.consents : [],
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load account");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAccount();
  }, [loadAccount]);

  const primaryMethods = state.accounts?.primaryLoginMethods ?? [];
  const linkedAccounts = state.accounts?.accounts ?? [];
  const userWallets = state.summary?.wallets ?? [];
  const portfolio = state.summary?.portfolio;
  const nativeAsset = portfolio?.native;
  const tokenAssets = portfolio?.tokens ?? [];
  const spend = state.summary?.spend;
  const capabilities = state.summary?.capabilities ?? [];
  const unlinkableLinkedAccounts = linkedAccounts.filter(
    (account) => account.provider !== "cross_app",
  );
  const canUnlink = primaryMethods.length + unlinkableLinkedAccounts.length > 1;
  const activeGlobalWalletConsents = state.globalWalletConsents.filter(
    (consent) => consent.status === "active",
  );

  const groupedLinkedAccounts = useMemo(() => {
    return linkedAccounts.reduce<Record<string, UserLinkedAccount[]>>((acc, account) => {
      const key = labelProvider(account.provider);
      acc[key] ??= [];
      acc[key].push(account);
      return acc;
    }, {});
  }, [linkedAccounts]);

  async function unlink(account: UserLinkedAccount) {
    const key = `${account.provider}:${account.providerAccountId}`;
    try {
      setUnlinking(key);
      setError(null);
      await steward.unlinkUserAccount(account.provider, account.providerAccountId);
      await loadAccount();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to unlink account");
    } finally {
      setUnlinking(null);
    }
  }

  async function revokeGlobalWalletConsent(consent: GlobalWalletConsent) {
    try {
      setRevokingConsent(consent.id);
      setError(null);
      await steward.revokeGlobalWalletConsent(consent.id);
      await loadAccount();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke global wallet grant");
    } finally {
      setRevokingConsent(null);
    }
  }

  if (loading) {
    return (
      <div className="space-y-8">
        <div className="h-8 w-44 bg-bg-surface animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-border">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="bg-bg p-8 h-28 animate-pulse" />
          ))}
        </div>
        <div className="h-72 bg-bg-surface animate-pulse" />
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.4 }}
      className="space-y-10"
    >
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-2xl font-700 tracking-tight">Account</h1>
          <p className="text-sm text-text-tertiary mt-1">
            Login methods, linked identities, and embedded wallets
          </p>
        </div>
        <button
          type="button"
          onClick={() => void loadAccount()}
          className="self-start sm:self-auto px-4 py-2 text-sm border border-border text-text-secondary hover:text-text hover:border-text-tertiary transition-colors"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div role="alert" className="border border-error/30 bg-error/5 px-4 py-3 text-sm">
          <div className="text-error">Account action failed</div>
          <div className="text-text-tertiary mt-1">{error}</div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border">
        <Stat
          label="Primary methods"
          value={primaryMethods.length}
          detail={primaryMethods.length === 1 ? "One recovery path" : "Multiple recovery paths"}
        />
        <Stat
          label="Linked accounts"
          value={linkedAccounts.length}
          detail="OAuth, wallets, social"
        />
        <Stat
          label="Embedded wallets"
          value={userWallets.length}
          detail={
            state.summary?.walletAddress ? shortenAddress(state.summary.walletAddress, 6) : "None"
          }
        />
      </div>

      <section>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <h2 className="font-display text-lg font-600">Portfolio</h2>
          <span className="text-xs text-text-tertiary">
            {portfolio?.chainId ? `Chain ${portfolio.chainId}` : "Best effort"}
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border mb-5">
          <Stat
            label="Total USD"
            value={formatUsd(portfolio?.totalUsdText ?? portfolio?.totalUsd)}
            detail={
              portfolio?.walletAddress ? shortenAddress(portfolio.walletAddress, 6) : "No wallet"
            }
          />
          <Stat
            label="Native balance"
            value={
              nativeAsset
                ? `${nativeAsset.formatted} ${nativeAsset.symbol}`
                : portfolio?.unavailableReason
                  ? "Unavailable"
                  : "None"
            }
            detail={
              nativeAsset ? formatPortfolioAssetValue(nativeAsset) : portfolio?.unavailableReason
            }
          />
          <Stat
            label="Token assets"
            value={tokenAssets.length}
            detail={tokenAssets.length === 1 ? "One tracked token" : "Tracked tokens"}
          />
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
      </section>

      <section>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <h2 className="font-display text-lg font-600">Spend and Capabilities</h2>
          <span className="text-xs text-text-tertiary">
            {state.summary?.sponsorship.enabled ? "Gas sponsorship enabled" : "Gas sponsorship off"}
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-border mb-5">
          <Stat label="Today" value={formatWei(spend?.todayWei ?? "0", "ETH")} />
          <Stat label="This week" value={formatWei(spend?.weekWei ?? "0", "ETH")} />
          <Stat label="This month" value={formatWei(spend?.monthWei ?? "0", "ETH")} />
        </div>
        <div className="flex flex-wrap gap-2">
          {capabilities.length === 0 ? (
            <span className="text-sm text-text-tertiary">No wallet capabilities returned</span>
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
      </section>

      <section>
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-display text-lg font-600">Primary Login Methods</h2>
          <span className="text-xs text-text-tertiary">Cannot be removed here</span>
        </div>
        <div className="border-t border-border-subtle">
          {primaryMethods.length === 0 ? (
            <div className="py-10 text-sm text-text-tertiary">No primary methods returned</div>
          ) : (
            primaryMethods.map((method) => (
              <MethodRow
                key={`${method.provider}:${method.providerAccountId}`}
                provider={method.provider}
                accountId={method.providerAccountId}
              />
            ))
          )}
        </div>
      </section>

      <section>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <h2 className="font-display text-lg font-600">Linked Accounts</h2>
          <span className="text-xs text-text-tertiary">
            Unlinking revokes sessions issued before the change
          </span>
        </div>
        <div className="border-t border-border-subtle">
          {linkedAccounts.length === 0 ? (
            <div className="py-10 text-sm text-text-tertiary">No linked accounts yet</div>
          ) : (
            Object.entries(groupedLinkedAccounts).map(([group, accounts]) => (
              <div key={group} className="border-b border-border-subtle last:border-b-0">
                <div className="text-xs text-text-tertiary tracking-wider uppercase pt-5 pb-1">
                  {group}
                </div>
                {accounts.map((account) => {
                  const key = `${account.provider}:${account.providerAccountId}`;
                  return (
                    <MethodRow
                      key={account.id}
                      provider={account.provider}
                      accountId={account.providerAccountId}
                      expiresAt={account.expiresAt}
                      busy={unlinking === key}
                      action={
                        account.provider === "cross_app" ? (
                          <span className="text-xs text-text-tertiary">Grant-backed</span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void unlink(account)}
                            disabled={!canUnlink || unlinking === key}
                            className="px-3 py-2 text-xs border border-border text-text-tertiary hover:text-error hover:border-error/50 disabled:opacity-40 disabled:hover:text-text-tertiary disabled:hover:border-border transition-colors"
                          >
                            Unlink
                          </button>
                        )
                      }
                    />
                  );
                })}
              </div>
            ))
          )}
        </div>
      </section>

      <section>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <h2 className="font-display text-lg font-600">Global Wallet Grants</h2>
          <span className="text-xs text-text-tertiary">
            Revocation requires a recent MFA session
          </span>
        </div>
        <div className="border-t border-border-subtle">
          {activeGlobalWalletConsents.length === 0 ? (
            <div className="py-10 text-sm text-text-tertiary">No active global wallet grants</div>
          ) : (
            activeGlobalWalletConsents.map((consent) => (
              <div
                key={consent.id}
                className="grid grid-cols-1 md:grid-cols-[1fr_180px_120px] gap-3 py-4 border-b border-border-subtle last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="font-mono text-sm text-text break-all">{consent.appId}</div>
                  <div className="text-xs text-text-tertiary mt-1 break-all">{consent.origin}</div>
                  <div className="text-xs text-text-tertiary mt-1 font-mono break-all">
                    {consent.scopes.join(", ")}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-text-tertiary uppercase tracking-wider">Granted</div>
                  <div className="text-sm text-text-secondary mt-1">
                    {formatDate(String(consent.grantedAt))}
                  </div>
                </div>
                <div className="md:text-right">
                  <button
                    type="button"
                    onClick={() => void revokeGlobalWalletConsent(consent)}
                    disabled={revokingConsent === consent.id}
                    className="px-3 py-2 text-xs border border-border text-text-tertiary hover:text-error hover:border-error/50 disabled:opacity-40 transition-colors"
                  >
                    {revokingConsent === consent.id ? "Revoking..." : "Revoke"}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between mb-5">
          <h2 className="font-display text-lg font-600">Embedded Wallets</h2>
          <span className="text-xs text-text-tertiary">
            {state.summary?.sponsorship.enabled ? "Sponsored" : "Self funded"}
          </span>
        </div>
        <div className="border-t border-border-subtle">
          {userWallets.length === 0 ? (
            <div className="py-10 text-sm text-text-tertiary">
              No embedded wallets have been created for this user
            </div>
          ) : (
            userWallets.map((wallet) => (
              <div
                key={wallet.id}
                className="grid grid-cols-1 md:grid-cols-[1fr_160px_160px] gap-3 py-4 border-b border-border-subtle last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="font-mono text-sm text-text break-all">{wallet.address}</div>
                  <div className="text-xs text-text-tertiary mt-1">
                    {wallet.purpose ?? "User wallet"}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-text-tertiary uppercase tracking-wider">Chain</div>
                  <div className="text-sm text-text-secondary mt-1">{wallet.chainFamily}</div>
                </div>
                <div>
                  <div className="text-xs text-text-tertiary uppercase tracking-wider">Created</div>
                  <div className="text-sm text-text-secondary mt-1">
                    {formatDate(String(wallet.createdAt))}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </motion.div>
  );
}

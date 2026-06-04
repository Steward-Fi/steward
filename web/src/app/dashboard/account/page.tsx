"use client";

import { useAuth as useStewardAuth } from "@stwd/react";
import type {
  AgentIdentity,
  GlobalWalletConsent,
  StewardRecoveryCodeStatus,
  UserAccountSummary,
  UserAccountsResult,
  UserLinkedAccount,
  UserWalletRecoverySetupResult,
} from "@stwd/sdk";
import { motion } from "framer-motion";
import { useCallback, useEffect, useMemo, useState } from "react";
import { CopyButton } from "@/components/copy-button";
import { steward } from "@/lib/api";
import { formatDate, formatWei, shortenAddress } from "@/lib/utils";

type LoadState = {
  accounts: UserAccountsResult | null;
  summary: UserAccountSummary | null;
  globalWalletConsents: GlobalWalletConsent[];
  agents: AgentIdentity[];
};

type PortfolioAsset = NonNullable<UserAccountSummary["portfolio"]["native"]>;
type RecoverySecretKind = "wallet" | "mfa";

type RecoverySecret = {
  kind: RecoverySecretKind;
  label: string;
  values: string[];
  warning: string;
};

type RecoveryAuditEvent = {
  id: number | string;
  seq: number;
  action: string;
  resource_type?: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
};

type PregeneratedInventoryStatus = "unclaimed" | "claimed" | "expired";

type PregeneratedInventoryItem = {
  agent: AgentIdentity;
  status: PregeneratedInventoryStatus;
  tokenHashPrefix: string;
  claimExpiresAt: Date | null;
};

type PregeneratedDistribution = {
  wallets: Array<{
    agent: AgentIdentity;
    claimToken: string;
    claimExpiresAt: string;
  }>;
  warning: string;
  createdAt: string;
};

type PregeneratedBatchForm = {
  count: string;
  namePrefix: string;
  expiresInDays: string;
};

const RECOVERY_EVENT_ACTIONS = [
  "user.wallet.recovery_setup",
  "mfa.recovery_codes.regenerate",
  "mfa.enabled",
  "mfa.disabled",
  "auth.logout",
] as const;

const PREGENERATED_PREFIX = "pregenerated:";
const CLAIMED_PREGENERATED_PREFIX = "claimed:";
const EXPIRED_PREGENERATED_PREFIX = "expired:";

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

function formatDurationFromNow(date: Date | null): string {
  if (!date) return "Legacy token without expiry";
  const ms = date.getTime() - Date.now();
  if (ms <= 0) return "Expired";
  const minutes = Math.ceil(ms / 60_000);
  if (minutes < 60) return `${minutes}m remaining`;
  const hours = Math.ceil(minutes / 60);
  if (hours < 48) return `${hours}h remaining`;
  return `${Math.ceil(hours / 24)}d remaining`;
}

function parsePregeneratedInventoryItem(agent: AgentIdentity): PregeneratedInventoryItem | null {
  const platformId = agent.platformId ?? "";

  if (platformId.startsWith(PREGENERATED_PREFIX)) {
    const [tokenHash = "", expiresAtMs] = platformId.slice(PREGENERATED_PREFIX.length).split(":");
    const expiresAt =
      expiresAtMs && Number.isSafeInteger(Number(expiresAtMs))
        ? new Date(Number(expiresAtMs))
        : null;
    return {
      agent,
      status: expiresAt && expiresAt.getTime() <= Date.now() ? "expired" : "unclaimed",
      tokenHashPrefix: tokenHash.slice(0, 12),
      claimExpiresAt: expiresAt,
    };
  }

  if (platformId.startsWith(CLAIMED_PREGENERATED_PREFIX)) {
    return {
      agent,
      status: "claimed",
      tokenHashPrefix: platformId.slice(
        CLAIMED_PREGENERATED_PREFIX.length,
        CLAIMED_PREGENERATED_PREFIX.length + 12,
      ),
      claimExpiresAt: null,
    };
  }

  if (platformId.startsWith(EXPIRED_PREGENERATED_PREFIX)) {
    return {
      agent,
      status: "expired",
      tokenHashPrefix: platformId.slice(
        EXPIRED_PREGENERATED_PREFIX.length,
        EXPIRED_PREGENERATED_PREFIX.length + 12,
      ),
      claimExpiresAt: null,
    };
  }

  return null;
}

function pregeneratedStatusTone(status: PregeneratedInventoryStatus): string {
  switch (status) {
    case "unclaimed":
      return "border-info/30 text-info";
    case "claimed":
      return "border-success/30 text-success";
    case "expired":
      return "border-warning/30 text-warning";
  }
}

function pregeneratedStatusLabel(status: PregeneratedInventoryStatus): string {
  switch (status) {
    case "unclaimed":
      return "Unclaimed";
    case "claimed":
      return "Claimed";
    case "expired":
      return "Expired";
  }
}

function recoveryEventLabel(action: string): string {
  switch (action) {
    case "user.wallet.recovery_setup":
      return "Wallet recovery phrase created";
    case "mfa.recovery_codes.regenerate":
      return "MFA recovery codes regenerated";
    case "mfa.enabled":
      return "MFA enabled";
    case "mfa.disabled":
      return "MFA disabled";
    case "auth.logout":
      return "Session signed out";
    default:
      return action;
  }
}

function recoveryEventDetail(event: RecoveryAuditEvent): string {
  const method = typeof event.metadata?.method === "string" ? event.metadata.method : null;
  const factor = typeof event.metadata?.factor === "string" ? event.metadata.factor : null;
  const issued =
    typeof event.metadata?.recoveryCodesIssued === "number"
      ? `${event.metadata.recoveryCodesIssued} codes issued`
      : null;
  return [factor, method, issued].filter(Boolean).join(" / ") || event.resource_type || "audit";
}

function NoStoreSecretDisplay({
  secret,
  onDismiss,
}: {
  secret: RecoverySecret;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = useState(false);

  async function copyAll() {
    const text = secret.values.join(secret.kind === "wallet" ? " " : "\n");
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const el = document.createElement("textarea");
      el.value = text;
      el.setAttribute("readonly", "true");
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div
      role="status"
      className="border border-warning/40 bg-warning/5 p-4 space-y-4"
      data-testid={`one-time-${secret.kind}-secret`}
    >
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div>
          <div className="text-sm font-display font-600 text-text">{secret.label}</div>
          <div className="text-xs text-text-tertiary mt-1">{secret.warning}</div>
          <div className="text-xs text-warning mt-2">
            Shown once. Steward does not store this secret in the dashboard, browser storage, or
            logs. Copy it to an offline password manager before dismissing.
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            type="button"
            onClick={() => void copyAll()}
            className="px-3 py-2 text-xs border border-border text-text-secondary hover:text-text hover:border-text-tertiary transition-colors"
          >
            {copied ? "Copied" : "Copy once"}
          </button>
          <button
            type="button"
            onClick={onDismiss}
            className="px-3 py-2 text-xs border border-border text-text-tertiary hover:text-text transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
      <div
        className={
          secret.kind === "wallet"
            ? "grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2"
            : "grid grid-cols-1 sm:grid-cols-2 gap-2"
        }
      >
        {secret.values.map((value, index) => (
          <div
            key={`${value}:${index}`}
            className="font-mono text-xs text-text bg-bg border border-border-subtle px-3 py-2 break-all"
          >
            {secret.kind === "wallet" ? `${index + 1}. ${value}` : value}
          </div>
        ))}
      </div>
    </div>
  );
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
  const stewardAuth = useStewardAuth();
  const getRecoveryCodeStatus = stewardAuth.getRecoveryCodeStatus;
  const regenerateStewardRecoveryCodes = stewardAuth.regenerateRecoveryCodes;
  const [state, setState] = useState<LoadState>({
    accounts: null,
    summary: null,
    globalWalletConsents: [],
    agents: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [unlinking, setUnlinking] = useState<string | null>(null);
  const [revokingConsent, setRevokingConsent] = useState<string | null>(null);
  const [recoveryStatus, setRecoveryStatus] = useState<StewardRecoveryCodeStatus | null>(null);
  const [recoveryEvents, setRecoveryEvents] = useState<RecoveryAuditEvent[]>([]);
  const [recoverySecret, setRecoverySecret] = useState<RecoverySecret | null>(null);
  const [recoveryBusy, setRecoveryBusy] = useState<string | null>(null);
  const [recoveryMessage, setRecoveryMessage] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [recoverySetupConfirmed, setRecoverySetupConfirmed] = useState(false);
  const [pregeneratedForm, setPregeneratedForm] = useState<PregeneratedBatchForm>({
    count: "3",
    namePrefix: "Pregenerated user wallet",
    expiresInDays: "7",
  });
  const [pregeneratedBusy, setPregeneratedBusy] = useState<string | null>(null);
  const [pregeneratedMessage, setPregeneratedMessage] = useState<string | null>(null);
  const [pregeneratedError, setPregeneratedError] = useState<string | null>(null);
  const [pregeneratedDistribution, setPregeneratedDistribution] =
    useState<PregeneratedDistribution | null>(null);

  const loadRecoveryControls = useCallback(
    async (userId?: string | null) => {
      const [status, ...events] = await Promise.allSettled([
        getRecoveryCodeStatus(),
        ...RECOVERY_EVENT_ACTIONS.map((action) =>
          steward.getAuditEvents({
            action,
            ...(userId ? { actorId: userId } : {}),
            limit: 5,
          }),
        ),
      ]);

      if (status.status === "fulfilled") setRecoveryStatus(status.value);
      else setRecoveryStatus(null);

      const merged = events
        .flatMap((result) => (result.status === "fulfilled" ? result.value.data : []))
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
        .slice(0, 8);
      setRecoveryEvents(merged);
    },
    [getRecoveryCodeStatus],
  );

  const loadAccount = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [accounts, summaryResult, globalWalletConsents, agentsResult] =
        await Promise.allSettled([
          steward.listUserAccounts(),
          steward.getUserAccount(),
          steward.listGlobalWalletConsents(),
          steward.listAgents(),
        ]);

      if (accounts.status === "rejected") throw accounts.reason;

      const nextSummary = summaryResult.status === "fulfilled" ? summaryResult.value : null;
      setState({
        accounts: accounts.value,
        summary: nextSummary,
        globalWalletConsents:
          globalWalletConsents.status === "fulfilled" ? globalWalletConsents.value.consents : [],
        agents: agentsResult.status === "fulfilled" ? agentsResult.value : [],
      });
      void loadRecoveryControls(nextSummary?.userId ?? null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load account");
    } finally {
      setLoading(false);
    }
  }, [loadRecoveryControls]);

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
  const hasEmbeddedWallet = userWallets.length > 0 || Boolean(state.summary?.wallet);
  const activeGlobalWalletConsents = state.globalWalletConsents.filter(
    (consent) => consent.status === "active",
  );
  const pregeneratedInventory = useMemo(
    () =>
      state.agents
        .map(parsePregeneratedInventoryItem)
        .filter((item): item is PregeneratedInventoryItem => item !== null)
        .sort((a, b) => {
          if (a.status !== b.status) {
            const order: Record<PregeneratedInventoryStatus, number> = {
              unclaimed: 0,
              expired: 1,
              claimed: 2,
            };
            return order[a.status] - order[b.status];
          }
          return new Date(b.agent.createdAt).getTime() - new Date(a.agent.createdAt).getTime();
        }),
    [state.agents],
  );
  const pregeneratedCounts = useMemo(
    () =>
      pregeneratedInventory.reduce(
        (acc, item) => {
          acc[item.status] += 1;
          return acc;
        },
        { unclaimed: 0, claimed: 0, expired: 0 } satisfies Record<
          PregeneratedInventoryStatus,
          number
        >,
      ),
    [pregeneratedInventory],
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

  async function copyPregeneratedDistribution() {
    if (!pregeneratedDistribution) return;
    const lines = pregeneratedDistribution.wallets.map((wallet) =>
      [wallet.agent.id, wallet.agent.walletAddress, wallet.claimToken, wallet.claimExpiresAt].join(
        "\t",
      ),
    );
    const text = ["agentId\twalletAddress\tclaimToken\tclaimExpiresAt", ...lines].join("\n");
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const el = document.createElement("textarea");
      el.value = text;
      el.setAttribute("readonly", "true");
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
    }
    setPregeneratedMessage("Copied distribution table to clipboard");
  }

  async function createPregeneratedBatch(reason: "create" | "rotate" = "create") {
    const count = Number(pregeneratedForm.count);
    const expiresInDays = Number(pregeneratedForm.expiresInDays);
    const rotationCount = Math.max(1, pregeneratedCounts.unclaimed + pregeneratedCounts.expired);
    const requestedCount = reason === "rotate" ? rotationCount : count;

    if (!Number.isSafeInteger(requestedCount) || requestedCount < 1 || requestedCount > 100) {
      setPregeneratedError("Batch count must be between 1 and 100");
      return;
    }
    if (!Number.isFinite(expiresInDays) || expiresInDays <= 0 || expiresInDays > 30) {
      setPregeneratedError("Expiry must be between 1 and 30 days");
      return;
    }

    try {
      setPregeneratedBusy(reason);
      setPregeneratedError(null);
      setPregeneratedMessage(null);
      const result = await steward.createPregeneratedUserWallets({
        count: requestedCount,
        namePrefix:
          pregeneratedForm.namePrefix.trim() ||
          (reason === "rotate" ? "Replacement pregenerated wallet" : "Pregenerated user wallet"),
        claimExpiresInSeconds: Math.round(expiresInDays * 24 * 60 * 60),
      });
      setPregeneratedDistribution({
        wallets: result.wallets,
        warning: result.warning,
        createdAt: new Date().toISOString(),
      });
      setPregeneratedMessage(
        reason === "rotate"
          ? `Created ${result.wallets.length} replacement claim token${
              result.wallets.length === 1 ? "" : "s"
            }`
          : `Created ${result.wallets.length} pregenerated wallet${
              result.wallets.length === 1 ? "" : "s"
            }`,
      );
      await loadAccount();
    } catch (err) {
      setPregeneratedError(
        err instanceof Error ? err.message : "Failed to create pregenerated wallets",
      );
    } finally {
      setPregeneratedBusy(null);
    }
  }

  async function setupWalletRecovery() {
    try {
      setRecoveryBusy("wallet");
      setRecoveryMessage(null);
      const result: UserWalletRecoverySetupResult = await steward.setupUserWalletRecovery();
      setRecoverySecret({
        kind: "wallet",
        label: "Wallet recovery phrase",
        values: result.recovery.mnemonic.trim().split(/\s+/g),
        warning: result.recovery.warning,
      });
      setRecoverySetupConfirmed(false);
      await loadAccount();
      await loadRecoveryControls(state.summary?.userId ?? null);
    } catch (err) {
      setRecoveryMessage(err instanceof Error ? err.message : "Wallet recovery setup failed");
    } finally {
      setRecoveryBusy(null);
    }
  }

  async function regenerateRecoveryCodes() {
    try {
      setRecoveryBusy("mfa");
      setRecoveryMessage(null);
      const result = await regenerateStewardRecoveryCodes(totpCode.trim());
      setRecoverySecret({
        kind: "mfa",
        label: "MFA recovery codes",
        values: result.recoveryCodes,
        warning:
          "These recovery codes replace any previous codes and are shown once. Store them offline before leaving this page.",
      });
      setTotpCode("");
      await loadRecoveryControls(state.summary?.userId ?? null);
    } catch (err) {
      setRecoveryMessage(
        err instanceof Error ? err.message : "Failed to regenerate recovery codes",
      );
    } finally {
      setRecoveryBusy(null);
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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <h2 className="font-display text-lg font-600">Pregenerated User Wallets</h2>
          <span className="text-xs text-text-tertiary">
            One-time claim tokens with expiring distribution
          </span>
        </div>

        {pregeneratedError && (
          <div role="alert" className="border border-error/30 bg-error/5 px-4 py-3 text-sm mb-5">
            <div className="text-error">Pregenerated wallet action failed</div>
            <div className="text-text-tertiary mt-1">{pregeneratedError}</div>
          </div>
        )}

        {pregeneratedMessage && (
          <div
            role="status"
            className="border border-success/30 bg-success/5 px-4 py-3 text-sm mb-5"
          >
            <div className="text-success">Pregenerated wallet action completed</div>
            <div className="text-text-tertiary mt-1">{pregeneratedMessage}</div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1fr)_360px] gap-px bg-border mb-5">
          <div className="bg-bg p-5">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-px bg-border mb-5">
              <Stat label="Inventory" value={pregeneratedInventory.length} detail="Total batches" />
              <Stat
                label="Unclaimed"
                value={pregeneratedCounts.unclaimed}
                detail="Ready to distribute"
              />
              <Stat label="Expired" value={pregeneratedCounts.expired} detail="Needs replacement" />
              <Stat label="Claimed" value={pregeneratedCounts.claimed} detail="Already consumed" />
            </div>

            <div className="border-t border-border-subtle" data-testid="pregenerated-inventory">
              {pregeneratedInventory.length === 0 ? (
                <div className="py-10 text-sm text-text-tertiary">
                  No pregenerated user wallets found for this tenant
                </div>
              ) : (
                pregeneratedInventory.slice(0, 12).map((item) => (
                  <div
                    key={item.agent.id}
                    className="grid grid-cols-1 md:grid-cols-[1fr_160px_180px] gap-3 py-4 border-b border-border-subtle last:border-b-0"
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`border px-2 py-0.5 text-[11px] uppercase tracking-wider ${pregeneratedStatusTone(
                            item.status,
                          )}`}
                        >
                          {pregeneratedStatusLabel(item.status)}
                        </span>
                        <span className="font-mono text-xs text-text-tertiary">
                          hash {item.tokenHashPrefix || "legacy"}
                        </span>
                      </div>
                      <div className="font-mono text-sm text-text mt-2 break-all">
                        {item.agent.id}
                      </div>
                      <div className="text-xs text-text-tertiary mt-1">
                        {item.agent.name} / {shortenAddress(item.agent.walletAddress, 6)}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-text-tertiary uppercase tracking-wider">
                        Expires
                      </div>
                      <div className="text-sm text-text-secondary mt-1">
                        {item.claimExpiresAt ? formatDate(item.claimExpiresAt) : "Legacy"}
                      </div>
                      <div className="text-xs text-text-tertiary mt-1">
                        {formatDurationFromNow(item.claimExpiresAt)}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-text-tertiary uppercase tracking-wider">
                        Created
                      </div>
                      <div className="text-sm text-text-secondary mt-1">
                        {item.agent.createdAt ? formatDate(item.agent.createdAt) : "Unknown"}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="bg-bg p-5">
            <h3 className="font-display text-base font-600">Create Distribution Batch</h3>
            <p className="text-xs text-text-tertiary mt-1">
              Claim tokens are displayed once. Store them in your delivery system before leaving
              this page.
            </p>

            <form
              className="mt-5 space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                void createPregeneratedBatch("create");
              }}
            >
              <label className="block">
                <span className="text-xs text-text-tertiary uppercase tracking-wider">Count</span>
                <input
                  value={pregeneratedForm.count}
                  onChange={(event) =>
                    setPregeneratedForm((prev) => ({
                      ...prev,
                      count: event.currentTarget.value,
                    }))
                  }
                  inputMode="numeric"
                  className="mt-2 w-full bg-bg-elevated border border-border px-3 py-2 text-sm font-mono text-text focus:outline-none focus:border-accent"
                />
              </label>
              <label className="block">
                <span className="text-xs text-text-tertiary uppercase tracking-wider">
                  Name Prefix
                </span>
                <input
                  value={pregeneratedForm.namePrefix}
                  onChange={(event) =>
                    setPregeneratedForm((prev) => ({
                      ...prev,
                      namePrefix: event.currentTarget.value,
                    }))
                  }
                  className="mt-2 w-full bg-bg-elevated border border-border px-3 py-2 text-sm text-text focus:outline-none focus:border-accent"
                />
              </label>
              <label className="block">
                <span className="text-xs text-text-tertiary uppercase tracking-wider">
                  Claim Expiry Days
                </span>
                <input
                  value={pregeneratedForm.expiresInDays}
                  onChange={(event) =>
                    setPregeneratedForm((prev) => ({
                      ...prev,
                      expiresInDays: event.currentTarget.value,
                    }))
                  }
                  inputMode="decimal"
                  className="mt-2 w-full bg-bg-elevated border border-border px-3 py-2 text-sm font-mono text-text focus:outline-none focus:border-accent"
                />
              </label>
              <div className="grid grid-cols-2 gap-2">
                {[1, 7, 30].map((days) => (
                  <button
                    key={days}
                    type="button"
                    onClick={() =>
                      setPregeneratedForm((prev) => ({
                        ...prev,
                        expiresInDays: String(days),
                      }))
                    }
                    className="px-3 py-2 text-xs border border-border text-text-tertiary hover:text-text hover:border-text-tertiary transition-colors"
                  >
                    {days}d
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => void createPregeneratedBatch("rotate")}
                  disabled={pregeneratedBusy !== null}
                  className="px-3 py-2 text-xs border border-warning/40 text-warning hover:border-warning transition-colors disabled:opacity-40"
                >
                  {pregeneratedBusy === "rotate" ? "Replacing..." : "Replace stale"}
                </button>
              </div>
              <button
                type="submit"
                disabled={pregeneratedBusy !== null}
                className="w-full px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover disabled:opacity-40 disabled:hover:bg-accent transition-colors"
              >
                {pregeneratedBusy === "create" ? "Creating..." : "Create Claim Tokens"}
              </button>
            </form>
          </div>
        </div>

        {pregeneratedDistribution && (
          <div
            role="status"
            data-testid="pregenerated-distribution"
            className="border border-warning/40 bg-warning/5 p-4 space-y-4"
          >
            <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
              <div>
                <div className="text-sm font-display font-600 text-text">
                  One-time claim-token distribution
                </div>
                <div className="text-xs text-text-tertiary mt-1">
                  Created {formatDate(pregeneratedDistribution.createdAt)}.{" "}
                  {pregeneratedDistribution.warning}
                </div>
                <div className="text-xs text-warning mt-2">
                  Tokens below are not recoverable after refresh. Only distribute them over a secure
                  channel and never paste them into logs or tickets.
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  type="button"
                  onClick={() => void copyPregeneratedDistribution()}
                  className="px-3 py-2 text-xs border border-border text-text-secondary hover:text-text hover:border-text-tertiary transition-colors"
                >
                  Copy TSV
                </button>
                <button
                  type="button"
                  onClick={() => setPregeneratedDistribution(null)}
                  className="px-3 py-2 text-xs border border-border text-text-tertiary hover:text-text transition-colors"
                >
                  Dismiss
                </button>
              </div>
            </div>
            <div className="space-y-2">
              {pregeneratedDistribution.wallets.map((wallet) => (
                <div
                  key={wallet.agent.id}
                  className="grid grid-cols-1 lg:grid-cols-[1fr_1fr_180px] gap-3 border border-border-subtle bg-bg px-3 py-3"
                >
                  <div className="min-w-0">
                    <div className="text-xs text-text-tertiary uppercase tracking-wider">Agent</div>
                    <div className="font-mono text-xs text-text mt-1 break-all">
                      {wallet.agent.id}
                    </div>
                    <div className="text-xs text-text-tertiary mt-1">
                      {shortenAddress(wallet.agent.walletAddress, 6)}
                    </div>
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="text-xs text-text-tertiary uppercase tracking-wider">
                        Claim Token
                      </div>
                      <CopyButton text={wallet.claimToken} />
                    </div>
                    <div className="font-mono text-xs text-text mt-1 break-all">
                      {wallet.claimToken}
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-text-tertiary uppercase tracking-wider">
                      Expires
                    </div>
                    <div className="text-sm text-text-secondary mt-1">
                      {formatDate(wallet.claimExpiresAt)}
                    </div>
                    <div className="text-xs text-text-tertiary mt-1">
                      {formatDurationFromNow(new Date(wallet.claimExpiresAt))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
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
          <h2 className="font-display text-lg font-600">Recovery</h2>
          <span className="text-xs text-text-tertiary">
            Wallet phrases and MFA codes are one-time secrets
          </span>
        </div>

        {recoveryMessage && (
          <div
            role="alert"
            className="border border-warning/30 bg-warning/5 px-4 py-3 text-sm mb-5"
          >
            <div className="text-warning">Recovery action did not complete</div>
            <div className="text-text-tertiary mt-1">{recoveryMessage}</div>
          </div>
        )}

        {recoverySecret && (
          <div className="mb-5">
            <NoStoreSecretDisplay
              secret={recoverySecret}
              onDismiss={() => setRecoverySecret(null)}
            />
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-px bg-border mb-5">
          <div className="bg-bg p-5 min-h-[320px]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="font-display text-base font-600">Wallet Recovery Setup</h3>
                <p className="text-xs text-text-tertiary mt-1">
                  Create a recoverable embedded wallet with a BIP-39 phrase before any user wallet
                  exists.
                </p>
              </div>
              <span
                className={`border px-2 py-0.5 text-[11px] uppercase tracking-wider ${
                  hasEmbeddedWallet
                    ? "border-warning/30 text-warning"
                    : "border-success/30 text-success"
                }`}
              >
                {hasEmbeddedWallet ? "locked" : "available"}
              </span>
            </div>

            <div className="mt-5 space-y-3 text-sm">
              {hasEmbeddedWallet ? (
                <div className="border border-border-subtle p-4">
                  <div className="text-text-secondary">Existing wallet detected</div>
                  <p className="text-xs text-text-tertiary mt-2 leading-relaxed">
                    Existing embedded wallets cannot be assigned a new recovery phrase. Use audited
                    key export for break-glass backup, or create recovery during initial wallet
                    provisioning for new accounts.
                  </p>
                </div>
              ) : (
                <>
                  <label className="flex items-start gap-3 border border-border-subtle p-4 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={recoverySetupConfirmed}
                      onChange={(event) => setRecoverySetupConfirmed(event.currentTarget.checked)}
                      className="mt-0.5"
                    />
                    <span className="text-xs text-text-secondary leading-relaxed">
                      I understand this phrase is displayed once, is not recoverable from Steward,
                      and should only be copied into secure offline storage.
                    </span>
                  </label>
                  <button
                    type="button"
                    onClick={() => void setupWalletRecovery()}
                    disabled={!recoverySetupConfirmed || recoveryBusy !== null}
                    className="px-4 py-2 text-sm bg-accent text-bg hover:bg-accent-hover disabled:opacity-40 disabled:hover:bg-accent transition-colors"
                  >
                    {recoveryBusy === "wallet" ? "Creating..." : "Set Up Recoverable Wallet"}
                  </button>
                  <p className="text-xs text-text-tertiary">
                    Requires a current session with recent MFA. If this fails, complete MFA and try
                    again.
                  </p>
                </>
              )}
            </div>
          </div>

          <div className="bg-bg p-5 min-h-[320px]">
            <div className="flex items-start justify-between gap-4">
              <div>
                <h3 className="font-display text-base font-600">MFA Recovery Codes</h3>
                <p className="text-xs text-text-tertiary mt-1">
                  Check remaining one-time codes and regenerate them after authenticator
                  verification.
                </p>
              </div>
              <span className="border border-border-subtle px-2 py-0.5 text-[11px] uppercase tracking-wider text-text-tertiary">
                {recoveryStatus
                  ? recoveryStatus.enabled
                    ? `${recoveryStatus.remaining} left`
                    : "off"
                  : "unknown"}
              </span>
            </div>

            <div className="mt-5 space-y-4">
              <div className="grid grid-cols-2 gap-px bg-border">
                <Stat
                  label="Codes enabled"
                  value={recoveryStatus?.enabled ? "Yes" : "No"}
                  detail="Backs up TOTP MFA"
                />
                <Stat
                  label="Remaining"
                  value={recoveryStatus?.remaining ?? "--"}
                  detail="Unused codes"
                />
              </div>
              {recoveryStatus?.enabled ? (
                <form
                  className="space-y-3"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void regenerateRecoveryCodes();
                  }}
                >
                  <label className="block">
                    <span className="text-xs text-text-tertiary uppercase tracking-wider">
                      Authenticator Code
                    </span>
                    <input
                      value={totpCode}
                      onChange={(event) => setTotpCode(event.currentTarget.value)}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      pattern="[0-9]*"
                      placeholder="000000"
                      className="mt-2 w-full bg-bg-elevated border border-border px-3 py-2 text-sm font-mono text-text focus:outline-none focus:border-accent"
                    />
                  </label>
                  <button
                    type="submit"
                    disabled={recoveryBusy !== null || !/^\d{6}$/.test(totpCode.trim())}
                    className="px-4 py-2 text-sm border border-border text-text-secondary hover:text-text hover:border-text-tertiary disabled:opacity-40 transition-colors"
                  >
                    {recoveryBusy === "mfa" ? "Regenerating..." : "Regenerate Codes"}
                  </button>
                </form>
              ) : (
                <div className="border border-border-subtle p-4 text-xs text-text-tertiary leading-relaxed">
                  Enable authenticator MFA first. Steward issues recovery codes when TOTP is enabled
                  and replaces them when you regenerate.
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="border-t border-border-subtle">
          <div className="text-xs text-text-tertiary tracking-wider uppercase py-3">
            Recovery History
          </div>
          {recoveryEvents.length === 0 ? (
            <div className="py-8 text-sm text-text-tertiary">
              No recovery audit events are visible for this session
            </div>
          ) : (
            recoveryEvents.map((event) => (
              <div
                key={`${event.seq}:${event.action}:${event.created_at}`}
                className="grid grid-cols-1 md:grid-cols-[1fr_180px_160px] gap-3 py-4 border-b border-border-subtle last:border-b-0"
              >
                <div className="min-w-0">
                  <div className="text-sm text-text-secondary">
                    {recoveryEventLabel(event.action)}
                  </div>
                  <div className="text-xs text-text-tertiary mt-1 font-mono break-all">
                    {event.action}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-text-tertiary uppercase tracking-wider">Detail</div>
                  <div className="text-sm text-text-secondary mt-1">
                    {recoveryEventDetail(event)}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-text-tertiary uppercase tracking-wider">When</div>
                  <div className="text-sm text-text-secondary mt-1">
                    {formatDate(event.created_at)}
                  </div>
                </div>
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

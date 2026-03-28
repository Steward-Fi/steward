// ─── Provider ───
export { StewardProvider } from "./provider.js";

// ─── Components ───
export { WalletOverview } from "./components/WalletOverview.js";
export { TransactionHistory } from "./components/TransactionHistory.js";
export { PolicyControls } from "./components/PolicyControls.js";
export { ApprovalQueue } from "./components/ApprovalQueue.js";
export { SpendDashboard } from "./components/SpendDashboard.js";

// ─── Hooks ───
export { useSteward } from "./hooks/useSteward.js";
export { useWallet } from "./hooks/useWallet.js";
export { useTransactions } from "./hooks/useTransactions.js";
export { usePolicies } from "./hooks/usePolicies.js";
export { useApprovals } from "./hooks/useApprovals.js";
export { useSpend } from "./hooks/useSpend.js";

// ─── Utilities ───
export {
  truncateAddress,
  formatWei,
  formatBalance,
  formatTimestamp,
  formatRelativeTime,
  copyToClipboard,
  getExplorerTxUrl,
  getExplorerAddressUrl,
  getStatusColor,
  calcPercent,
} from "./utils/format.js";
export { themeToCSS, mergeTheme, DEFAULT_THEME } from "./utils/theme.js";

// ─── Types ───
export type {
  // Tenant config
  TenantControlPlaneConfig,
  TenantFeatureFlags,
  TenantTheme,
  PolicyExposure,
  PolicyExposureConfig,
  PolicyTemplate,
  CustomizableField,
  EnforcedPolicyOverride,
  ApprovalConfig,
  ApproverConfig,
  SecretRoutePreset,
  // Component data
  AgentDashboardResponse,
  PaginatedTransactionsResponse,
  SpendStats,
  ApprovalQueueEntry,
  // Component props
  StewardProviderProps,
  StewardContextValue,
  WalletOverviewProps,
  TransactionHistoryProps,
  PolicyControlsProps,
  ApprovalQueueProps,
  SpendDashboardProps,
  // Re-exported SDK types
  StewardClient,
  PolicyRule,
  PolicyType,
  TxStatus,
  TxRecord,
  AgentIdentity,
  AgentBalance,
  ChainFamily,
  PolicyResult,
} from "./types.js";

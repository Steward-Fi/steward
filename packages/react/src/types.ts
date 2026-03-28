import type { StewardClient, PolicyRule, PolicyType, TxStatus, TxRecord, AgentIdentity, AgentBalance, ChainFamily, PolicyResult } from "@stwd/sdk";

// ─── Tenant Configuration Types ───

export type PolicyExposure = "visible" | "hidden" | "enforced";

export type PolicyExposureConfig = Record<PolicyType, PolicyExposure>;

export interface EnforcedPolicyOverride {
  type: PolicyType;
  config: Record<string, unknown>;
  allowTightening?: boolean;
}

export interface CustomizableField {
  path: string;
  label: string;
  description: string;
  type: "currency" | "number" | "toggle" | "address-list" | "chain-select";
  default: unknown;
  min?: unknown;
  max?: unknown;
}

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
  policies: PolicyRule[];
  customizableFields: CustomizableField[];
}

export interface SecretRoutePreset {
  id: string;
  name: string;
  hostPattern: string;
  pathPattern: string;
  injectAs: "header" | "query" | "bearer";
  injectKey: string;
  injectFormat: string;
  provisioning: "platform" | "user";
  platformSecretId?: string;
}

export interface ApprovalNotificationChannel {
  type: "webhook" | "email" | "in-app";
  config: Record<string, string>;
}

export interface ApproverConfig {
  mode: "owner" | "tenant-admin" | "list";
  allowedApprovers?: string[];
}

export interface ApprovalConfig {
  notificationChannels: ApprovalNotificationChannel[];
  autoExpireSeconds: number;
  approvers: ApproverConfig;
  approvalWebhookUrl?: string;
  webhookCallbackEnabled: boolean;
}

export interface TenantTheme {
  primaryColor: string;
  accentColor: string;
  backgroundColor: string;
  surfaceColor: string;
  textColor: string;
  mutedColor: string;
  successColor: string;
  errorColor: string;
  warningColor: string;
  borderRadius: number;
  fontFamily?: string;
  colorScheme: "light" | "dark" | "system";
}

export interface TenantFeatureFlags {
  showFundingQR: boolean;
  showTransactionHistory: boolean;
  showSpendDashboard: boolean;
  showPolicyControls: boolean;
  showApprovalQueue: boolean;
  showSecretManager: boolean;
  enableSolana: boolean;
  showChainSelector: boolean;
  allowAddressExport: boolean;
}

export interface TenantControlPlaneConfig {
  tenantId: string;
  displayName: string;
  exposedPolicies: PolicyExposureConfig;
  policyTemplates: PolicyTemplate[];
  secretRoutePresets: SecretRoutePreset[];
  approvalConfig: ApprovalConfig;
  theme?: TenantTheme;
  features: TenantFeatureFlags;
}

// ─── Component Data Types ───

export interface AgentDashboardResponse {
  agent: AgentIdentity;
  balances: {
    evm?: { native: string; nativeFormatted: string; chainId: number; symbol: string };
    solana?: { native: string; nativeFormatted: string; chainId: number; symbol: string };
  };
  spend: {
    today: string;
    thisWeek: string;
    thisMonth: string;
    todayFormatted: string;
    thisWeekFormatted: string;
    thisMonthFormatted: string;
  };
  policies: PolicyRule[];
  pendingApprovals: number;
  recentTransactions: TxRecord[];
}

export interface PaginatedTransactionsResponse {
  transactions: TxRecord[];
  pagination: {
    page: number;
    pageSize: number;
    total: number;
    totalPages: number;
  };
}

export interface SpendStats {
  range: "24h" | "7d" | "30d" | "all";
  totalSpent: string;
  totalSpentFormatted: string;
  txCount: number;
  avgTxValue: string;
  avgTxValueFormatted: string;
  largestTx: { value: string; txHash: string; timestamp: string };
  daily: Array<{ date: string; spent: string; spentFormatted: string; txCount: number }>;
  topDestinations: Array<{ address: string; totalSent: string; txCount: number }>;
  budgetUsage?: {
    dailyLimit: string;
    dailyUsed: string;
    dailyPercent: number;
    weeklyLimit: string;
    weeklyUsed: string;
    weeklyPercent: number;
  };
}

export interface ApprovalQueueEntry {
  id: string;
  agentId: string;
  txId: string;
  status: "pending" | "approved" | "rejected";
  to: string;
  value: string;
  chainId: number;
  policyResults: PolicyResult[];
  createdAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

// ─── Provider Types ───

export interface StewardProviderProps {
  client: StewardClient;
  agentId: string;
  features?: Partial<TenantFeatureFlags>;
  theme?: Partial<TenantTheme>;
  pollInterval?: number;
  children: React.ReactNode;
}

export interface StewardContextValue {
  client: StewardClient;
  agentId: string;
  features: TenantFeatureFlags;
  theme: TenantTheme;
  tenantConfig: TenantControlPlaneConfig | null;
  isLoading: boolean;
  pollInterval: number;
}

// ─── Component Props ───

export interface WalletOverviewProps {
  chains?: ChainFamily[];
  showQR?: boolean;
  showCopy?: boolean;
  className?: string;
  onCopyAddress?: (address: string, chain: ChainFamily) => void;
}

export interface TransactionHistoryProps {
  pageSize?: number;
  statusFilter?: TxStatus[];
  chainFilter?: number[];
  showPolicyDetails?: boolean;
  renderTransaction?: (tx: TxRecord) => React.ReactNode;
  onTransactionClick?: (tx: TxRecord) => void;
  className?: string;
}

export interface PolicyControlsProps {
  showTemplates?: boolean;
  onSave?: (policies: PolicyRule[]) => void;
  readOnly?: boolean;
  labels?: Partial<Record<PolicyType, string>>;
  className?: string;
}

export interface ApprovalQueueProps {
  refreshInterval?: number;
  onResolve?: (txId: string, action: "approved" | "rejected") => void;
  showPolicyReason?: boolean;
  className?: string;
}

export interface SpendDashboardProps {
  range?: "24h" | "7d" | "30d" | "all";
  showBudgetUsage?: boolean;
  showChart?: boolean;
  showTopDestinations?: boolean;
  className?: string;
}

// Re-export SDK types consumers will need
export type { StewardClient, PolicyRule, PolicyType, TxStatus, TxRecord, AgentIdentity, AgentBalance, ChainFamily, PolicyResult };

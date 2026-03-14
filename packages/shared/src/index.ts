// @steward/shared — types, constants, utils

// ─── Tenancy ───

export interface Tenant {
  id: string;
  name: string;
  apiKeyHash: string;
  createdAt: Date;
}

export interface TenantConfig {
  id: string;
  name: string;
  webhookUrl?: string;
  defaultPolicies?: PolicyRule[];
}

export interface WebhookEvent {
  type: "approval_required" | "tx_signed" | "tx_confirmed" | "tx_failed" | "tx_rejected";
  tenantId: string;
  agentId: string;
  data: Record<string, unknown>;
  timestamp: Date;
}

// ─── Agent Identity ───

export interface AgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  walletAddress: string;
  erc8004TokenId?: string;
  platformId?: string; // e.g. waifu.fun agent ID
  createdAt: Date;
}

// ─── Policies ───

export type PolicyType =
  | "spending-limit"
  | "approved-addresses"
  | "auto-approve-threshold"
  | "time-window"
  | "rate-limit";

export interface PolicyRule {
  id: string;
  type: PolicyType;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface SpendingLimitConfig {
  maxPerTx: string; // wei
  maxPerDay: string;
  maxPerWeek: string;
}

export interface ApprovedAddressesConfig {
  addresses: string[];
  mode: "whitelist" | "blacklist";
}

export interface AutoApproveConfig {
  threshold: string; // wei — below this, auto-approve
}

export interface TimeWindowConfig {
  allowedHours: { start: number; end: number }[]; // UTC hours
  allowedDays: number[]; // 0=Sun, 6=Sat
}

export interface RateLimitConfig {
  maxTxPerHour: number;
  maxTxPerDay: number;
}

// ─── Transactions ───

export type TxStatus = "pending" | "approved" | "rejected" | "signed" | "broadcast" | "confirmed" | "failed";

export interface SignRequest {
  agentId: string;
  tenantId: string;
  to: string;
  value: string; // wei
  data?: string; // calldata
  chainId: number;
  nonce?: number;
  gasLimit?: string;
}

export interface TxRecord {
  id: string;
  agentId: string;
  status: TxStatus;
  request: SignRequest;
  txHash?: string;
  policyResults: PolicyResult[];
  createdAt: Date;
  signedAt?: Date;
  confirmedAt?: Date;
}

export interface PolicyResult {
  policyId: string;
  type: PolicyType;
  passed: boolean;
  reason?: string;
}

// ─── API Responses ───

export interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

// ─── Balance ───

export interface AgentBalance {
  agentId: string;
  walletAddress: string;
  balances: {
    native: string;          // wei as string
    nativeFormatted: string; // human-readable (e.g. "0.005")
    chainId: number;
    symbol: string;          // e.g. "ETH", "BNB"
  };
}

// ─── Constants ───

export const SUPPORTED_CHAINS = {
  base: 8453,
  baseSepolia: 84532,
  bsc: 56,
  bscTestnet: 97,
} as const;

export const DEFAULT_CHAIN_ID = SUPPORTED_CHAINS.base;

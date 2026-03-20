// Standalone type definitions for the published SDK
// These mirror @stwd/shared but are bundled here for npm distribution

export interface AgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  walletAddress: string;
  erc8004TokenId?: string;
  platformId?: string;
  createdAt: Date;
}

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

export interface PolicyResult {
  policyId: string;
  type: PolicyType;
  passed: boolean;
  reason?: string;
}

export interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

export interface AgentBalance {
  agentId: string;
  walletAddress: string;
  balances: {
    native: string;
    nativeFormatted: string;
    chainId: number;
    symbol: string;
  };
}

export interface SpendingLimitConfig {
  maxPerTx: string;
  maxPerDay: string;
  maxPerWeek: string;
}

export interface ApprovedAddressesConfig {
  addresses: string[];
  mode: "whitelist" | "blacklist";
}

export interface AutoApproveConfig {
  threshold: string;
}

export interface TimeWindowConfig {
  allowedHours: { start: number; end: number }[];
  allowedDays: number[];
}

export interface RateLimitConfig {
  maxTxPerHour: number;
  maxTxPerDay: number;
}

export type TxStatus = "pending" | "approved" | "rejected" | "signed" | "broadcast" | "confirmed" | "failed";

export interface SignRequest {
  agentId: string;
  tenantId: string;
  to: string;
  value: string;
  data?: string;
  chainId: number;
  nonce?: number;
  gasLimit?: string;
  broadcast?: boolean;
}

export interface TypedDataDomain {
  name?: string;
  version?: string;
  chainId?: number;
  verifyingContract?: string;
  salt?: string;
}

export interface TypedDataField {
  name: string;
  type: string;
}

export interface SignTypedDataRequest {
  agentId: string;
  tenantId: string;
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  value: Record<string, unknown>;
}

export interface SignSolanaTransactionRequest {
  agentId: string;
  tenantId: string;
  transaction: string;
  chainId?: number;
  broadcast?: boolean;
}

export interface RpcRequest {
  method: string;
  params?: unknown[];
  chainId: number;
}

export interface RpcResponse {
  jsonrpc: string;
  id: number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
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

export const SUPPORTED_CHAINS = {
  base: 8453,
  baseSepolia: 84532,
  bsc: 56,
  bscTestnet: 97,
} as const;

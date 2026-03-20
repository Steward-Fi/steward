// @stwd/shared — types, constants, utils

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
  broadcast?: boolean; // default true — set false to return signed tx without broadcasting
}

/**
 * EIP-712 typed data signing request (`eth_signTypedData_v4`).
 */
export interface SignTypedDataRequest {
  agentId: string;
  tenantId: string;
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  value: Record<string, unknown>;
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

/**
 * Solana transaction signing request.
 */
export interface SignSolanaTransactionRequest {
  agentId: string;
  tenantId: string;
  transaction: string; // base64-encoded serialized transaction
  chainId?: number; // 101 = mainnet, 102 = devnet
  broadcast?: boolean; // default true
}

/**
 * Generic RPC passthrough request for read-only operations.
 */
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
  ethereum: 1,
  bsc: 56,
  bscTestnet: 97,
  polygon: 137,
  base: 8453,
  arbitrum: 42161,
  baseSepolia: 84532,
  // Solana — convention IDs (not EVM chainIds)
  solana: 101,
  solanaDevnet: 102,
} as const;

export const DEFAULT_CHAIN_ID = SUPPORTED_CHAINS.base;

// ─── Chain Metadata ───

export interface ChainMeta {
  id: number;
  name: string;
  symbol: string;
  explorerUrl: string;
  explorerTxUrl: string; // append tx hash to this
}

export const CHAIN_META: Record<number, ChainMeta> = {
  1: { id: 1, name: "Ethereum", symbol: "ETH", explorerUrl: "https://etherscan.io", explorerTxUrl: "https://etherscan.io/tx/" },
  56: { id: 56, name: "BSC", symbol: "BNB", explorerUrl: "https://bscscan.com", explorerTxUrl: "https://bscscan.com/tx/" },
  97: { id: 97, name: "BSC Testnet", symbol: "tBNB", explorerUrl: "https://testnet.bscscan.com", explorerTxUrl: "https://testnet.bscscan.com/tx/" },
  137: { id: 137, name: "Polygon", symbol: "POL", explorerUrl: "https://polygonscan.com", explorerTxUrl: "https://polygonscan.com/tx/" },
  8453: { id: 8453, name: "Base", symbol: "ETH", explorerUrl: "https://basescan.org", explorerTxUrl: "https://basescan.org/tx/" },
  42161: { id: 42161, name: "Arbitrum", symbol: "ETH", explorerUrl: "https://arbiscan.io", explorerTxUrl: "https://arbiscan.io/tx/" },
  84532: { id: 84532, name: "Base Sepolia", symbol: "ETH", explorerUrl: "https://sepolia.basescan.org", explorerTxUrl: "https://sepolia.basescan.org/tx/" },
  // Solana
  101: { id: 101, name: "Solana", symbol: "SOL", explorerUrl: "https://explorer.solana.com", explorerTxUrl: "https://explorer.solana.com/tx/" },
  102: { id: 102, name: "Solana Devnet", symbol: "SOL", explorerUrl: "https://explorer.solana.com?cluster=devnet", explorerTxUrl: "https://explorer.solana.com/tx/" },
};

export function getChainMeta(chainId: number): ChainMeta | undefined {
  return CHAIN_META[chainId];
}

export function getExplorerTxLink(chainId: number, txHash: string): string | undefined {
  const meta = CHAIN_META[chainId];
  return meta ? `${meta.explorerTxUrl}${txHash}` : undefined;
}

// @stwd/shared - types, constants, utils

import { CHAIN_PROVIDERS, type ChainProvider } from "./chains/index.js";
import type { VenueId } from "./types/venue.js";

// ─── Chain providers (extensible registry) ───
export * from "./chains/index.js";
export type { PriceOracle } from "./price-oracle.js";
export { createPriceOracle } from "./price-oracle.js";
// ─── Token Registry & Price Oracle ───
export * from "./tokens.js";
// ─── Trading venues (Sprint 4) ───
export * from "./types/venue.js";

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

export const WEBHOOK_EVENT_TYPES = [
  "tx.pending",
  "tx.approved",
  "tx.denied",
  "tx.signed",
  "spend.threshold",
  "policy.violation",
  "user.created",
  "user.authenticated",
  "user.linked_account",
  "user.unlinked_account",
  "user.updated_account",
  "user.transferred_account",
  "user.wallet_created",
  "mfa.enabled",
  "mfa.disabled",
  "private_key.exported",
  "wallet.recovery_setup",
  "wallet.recovered",
  "wallet.funds_deposited",
  "wallet.funds_withdrawn",
  "transaction.broadcasted",
  "transaction.confirmed",
  "transaction.execution_reverted",
  "transaction.replaced",
  "transaction.failed",
  "transaction.provider_error",
  "transaction.still_pending",
  "user_operation.completed",
  "user_operation.failed",
  "intent.created",
  "intent.authorized",
  "intent.executed",
  "intent.failed",
  "intent.rejected",
  "intent.canceled",
  "intent.expired",
  "wallet_action.transfer.created",
  "wallet_action.transfer.succeeded",
  "wallet_action.transfer.rejected",
  "wallet_action.transfer.failed",
  "wallet_action.swap.created",
  "wallet_action.swap.succeeded",
  "wallet_action.swap.rejected",
  "wallet_action.swap.failed",
  "wallet_action.send_calls.created",
  "wallet_action.send_calls.succeeded",
  "wallet_action.send_calls.rejected",
  "wallet_action.send_calls.failed",
  "wallet_action.earn_deposit.created",
  "wallet_action.earn_deposit.succeeded",
  "wallet_action.earn_deposit.rejected",
  "wallet_action.earn_deposit.failed",
  "wallet_action.earn_withdraw.created",
  "wallet_action.earn_withdraw.succeeded",
  "wallet_action.earn_withdraw.rejected",
  "wallet_action.earn_withdraw.failed",
  "wallet_action.earn_incentive_claim.created",
  "wallet_action.earn_incentive_claim.succeeded",
  "wallet_action.earn_incentive_claim.rejected",
  "wallet_action.earn_incentive_claim.failed",
] as const;

export type WebhookCatalogEventType = (typeof WEBHOOK_EVENT_TYPES)[number];

// Legacy event types kept for backwards-compatible dispatch inputs.
export type LegacyWebhookEventType =
  | "approval_required"
  | "tx_signed"
  | "tx_confirmed"
  | "tx_failed"
  | "tx_rejected";

export type WebhookEventType = WebhookCatalogEventType | LegacyWebhookEventType;

export interface WebhookEvent {
  type: WebhookEventType;
  tenantId: string;
  agentId?: string;
  deliveryId?: string;
  // Unix-seconds the canonical signature was first computed; fixed at first send and reused on retries so the signature stays stable.
  signedAt?: number;
  data: Record<string, unknown>;
  timestamp: Date;
}

export interface WebhookConfigRecord {
  id: string;
  tenantId: string;
  url: string;
  secret: string;
  events: WebhookEventType[];
  enabled: boolean;
  maxRetries: number;
  retryBackoffMs: number;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface AutoApprovalRuleRecord {
  id: string;
  tenantId: string;
  maxAmountWei: string;
  autoDenyAfterHours: number | null;
  escalateAboveWei: string | null;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// ─── Chain Family ───

/** Identifies the blockchain family for a wallet key/address. */
export type ChainFamily = "evm" | "solana";

// ─── Agent Identity ───

export interface AgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  /** Primary EVM address — kept for backwards compatibility. */
  walletAddress: string;
  /**
   * All addresses for this agent, keyed by chain family.
   * Present for agents created with multi-wallet support.
   */
  walletAddresses?: { evm?: string; solana?: string };
  erc8004TokenId?: string;
  platformId?: string; // e.g. waifu.fun agent ID
  createdAt: Date;
}

// ─── CAIP-2 Chain Identifiers ───

/**
 * A chain identifier following the CAIP-2 standard.
 * See https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md
 */
export interface ChainIdentifier {
  caip2: string;
  numericId: number;
  family: "evm" | "solana";
  name: string;
  symbol: string;
  testnet: boolean;
}

/**
 * Registry of all supported chains, keyed by CAIP-2 identifier.
 *
 * Derived from the per-chain `ChainProvider` modules under `chains/`. To add
 * a new chain, create a new file there and register it in `chains/index.ts`.
 *
 * CAIP-2 format:
 *   EVM:    `eip155:{chainId}`
 *   Solana: `solana:{genesisHashPrefix}`
 *
 * Solana convention IDs used internally: 101 = mainnet-beta, 102 = devnet.
 */
export const CHAINS: Record<string, ChainIdentifier> = Object.freeze(
  Object.fromEntries(
    CHAIN_PROVIDERS.map((p: ChainProvider): [string, ChainIdentifier] => [
      p.caip2,
      {
        caip2: p.caip2,
        numericId: p.numericId,
        family: p.family,
        name: p.name,
        symbol: p.symbol,
        testnet: p.testnet,
      },
    ]),
  ),
);

/** Look up a chain by its internal numeric ID. Returns undefined if not found. */
export function chainFromNumeric(id: number): ChainIdentifier | undefined {
  return Object.values(CHAINS).find((c) => c.numericId === id);
}

/** Look up a chain by its CAIP-2 string (e.g. `"eip155:8453"`). Returns undefined if not found. */
export function chainFromCaip2(caip2: string): ChainIdentifier | undefined {
  return CHAINS[caip2];
}

/**
 * Convert an internal numeric chain ID to its CAIP-2 string.
 * Returns undefined for unrecognised chain IDs.
 */
export function toCaip2(numericId: number): string | undefined {
  return chainFromNumeric(numericId)?.caip2;
}

/**
 * Convert a CAIP-2 string back to the internal numeric chain ID.
 * Returns undefined for unrecognised CAIP-2 strings.
 */
export function fromCaip2(caip2: string): number | undefined {
  return CHAINS[caip2]?.numericId;
}

// ─── Policies ───

export type PolicyType =
  | "spending-limit"
  | "approved-addresses"
  | "auto-approve-threshold"
  | "time-window"
  | "rate-limit"
  | "allowed-chains"
  | "condition-set"
  | "contract-allowlist"
  | "reputation-threshold"
  | "reputation-scaling"
  | "venue-allowlist"
  | "leverage-cap";

export interface PolicyRule {
  id: string;
  type: PolicyType;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface SpendingLimitConfig {
  // Wei-based (legacy/direct)
  maxPerTx?: string;
  maxPerDay?: string;
  maxPerWeek?: string;
  // USD-based (preferred — takes precedence when price oracle is available)
  maxPerTxUsd?: number;
  maxPerDayUsd?: number;
  maxPerWeekUsd?: number;
}

export interface ApprovedAddressesConfig {
  addresses: string[];
  mode: "whitelist" | "blacklist";
}

export interface AutoApproveConfig {
  threshold?: string; // wei — below this, auto-approve (legacy)
  thresholdUsd?: number; // USD — below this, auto-approve (preferred)
}

export interface TimeWindowConfig {
  allowedHours: { start: number; end: number }[]; // UTC hours
  allowedDays: number[]; // 0=Sun, 6=Sat
}

export interface RateLimitConfig {
  maxTxPerHour: number;
  maxTxPerDay: number;
}

export interface AllowedChainsConfig {
  /** Array of CAIP-2 chain identifiers that are permitted. e.g. ["eip155:8453", "eip155:1"] */
  chains: string[];
}

export interface ConditionSetConfig {
  /** Condition set id whose items are evaluated against. */
  conditionSetId: string;
  /** Request field to compare. Defaults to `ethereum_transaction.to`. */
  field?:
    | "to"
    | "ethereum_transaction.to"
    | "ethereum_transaction.chain_id"
    | "ethereum_transaction.value"
    | "ethereum_transaction.data"
    | "solana_system_program_instruction.Transfer.to"
    | "chain_id"
    | "value"
    | "data";
  /** Privy-style operator. Defaults to `in_condition_set`. */
  operator?: "in_condition_set" | "not_in_condition_set";
  /** Defaults to false for address/string allowlists. */
  caseSensitive?: boolean;
}

export interface ContractAllowlistConfig {
  contracts: Array<{
    address: string;
    selectors: string[];
    constraints?: Record<
      string,
      {
        recipientAllowlist?: string[];
        recipientBlocklist?: string[];
        spenderAllowlist?: string[];
        spenderBlocklist?: string[];
        fromAllowlist?: string[];
        fromBlocklist?: string[];
        maxAmount?: string;
      }
    >;
  }>;
}

/**
 * `venue-allowlist` policy config (Sprint 4).
 *
 * Allows trades only on the named venues. Evaluator NACKs if the eval
 * context's `venue` is absent or not in the list.
 */
export interface VenueAllowlistConfig {
  allowedVenues: string[];
}

/**
 * `leverage-cap` policy config (Sprint 4).
 *
 * Caps requested leverage at `maxLeverage`. Non-leveraged trades (no
 * `leverage` in eval context) always pass. Per-venue refinement is
 * Phase 2 work; for now this is a single cap per agent.
 */
export interface LeverageCapConfig {
  maxLeverage: number;
}

// ─── Transactions ───

export type TxStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "signed"
  | "broadcast"
  | "confirmed"
  | "failed";

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
  /**
   * Optional venue selector. When set, the vault looks up the venue-scoped
   * signing key for (agentId, chainFamily, venue) instead of the legacy
   * NULL-venue key. Used by venue-aware integrations like Hyperliquid where
   * the agent has a per-venue wallet distinct from its main EVM wallet.
   */
  venue?: string;
  /**
   * Optional explicit wallet address selector. When set, validates the
   * resolved key derives this address (defense-in-depth). If venue is set,
   * this serves as an assertion; otherwise it's used to disambiguate when
   * multiple non-venue keys exist (which should not happen but defends).
   */
  walletAddress?: string;
}

/**
 * EIP-712 typed data signing request (`eth_signTypedData_v4`).
 */
export interface SignTypedDataRequest {
  agentId: string;
  tenantId: string;
  /**
   * Sprint 4: optional venue scope. When set, vault.signTypedData will
   * look up the venue-scoped wallet under (agentId, venue) instead of
   * the legacy NULL-venue row. Phase 1 is hyperliquid-only; the field is
   * accepted but not yet routed through the new lookup path.
   */
  venue?: VenueId;
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
    native: string; // wei as string
    nativeFormatted: string; // human-readable (e.g. "0.005")
    chainId: number;
    symbol: string; // e.g. "ETH", "BNB"
  };
}

// ─── Control Plane Types ───

export type PolicyExposure = "visible" | "hidden" | "enforced";

export type PolicyExposureConfig = Partial<Record<PolicyType, PolicyExposure>>;

export interface PolicyTemplate {
  id: string;
  name: string;
  description: string;
  icon: string;
  policies: PolicyRule[];
  customizableFields: CustomizableField[];
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

export interface ApprovalConfig {
  notificationChannels?: ApprovalNotificationChannel[];
  autoExpireSeconds?: number;
  approvers?: ApproverConfig;
  approvalWebhookUrl?: string;
  webhookCallbackEnabled?: boolean;
}

export interface ApprovalNotificationChannel {
  type: "webhook" | "email" | "in-app";
  config: Record<string, string>;
}

export interface ApproverConfig {
  mode: "owner" | "tenant-admin" | "list";
  allowedApprovers?: string[];
}

export interface TenantFeatureFlags {
  showFundingQR?: boolean;
  showTransactionHistory?: boolean;
  showSpendDashboard?: boolean;
  showPolicyControls?: boolean;
  showApprovalQueue?: boolean;
  showSecretManager?: boolean;
  enableSolana?: boolean;
  showChainSelector?: boolean;
  allowAddressExport?: boolean;
}

export interface TenantTheme {
  primaryColor?: string;
  accentColor?: string;
  backgroundColor?: string;
  surfaceColor?: string;
  textColor?: string;
  mutedColor?: string;
  successColor?: string;
  errorColor?: string;
  warningColor?: string;
  borderRadius?: number;
  fontFamily?: string;
  colorScheme?: "light" | "dark" | "system";
}

export interface TenantOidcProviderConfig {
  id: string;
  enabled: boolean;
  issuer: string;
  audience: string[];
  jwksUri: string;
  clientId?: string;
  clientSecretEnv?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  scopes?: string[];
  subjectClaim?: "sub";
  emailClaim?: string;
  emailVerifiedClaim?: string;
  nameClaim?: string;
  pictureClaim?: string;
  allowedAlgs?: Array<"RS256" | "ES256">;
  allowJitProvisioning?: boolean;
}

export type TenantSamlSsoStatus = "pending" | "active" | "error";

export interface TenantSamlSsoConfig {
  tenantId: string;
  enabled: boolean;
  status: TenantSamlSsoStatus;
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
  nameIdFormat?: string;
  emailAttribute: string;
  groupsAttribute?: string;
  allowJitProvisioning: boolean;
  jitDefaultRole: "viewer";
  lastTestedAt?: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface TenantSamlSsoUpdate {
  enabled?: boolean;
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpCertPems?: string[];
  nameIdFormat?: string;
  emailAttribute?: string;
  groupsAttribute?: string;
  allowJitProvisioning?: boolean;
}

export interface TenantSsoDomain {
  id: string;
  tenantId: string;
  domain: string;
  verificationToken: string;
  status: "pending" | "verified";
  ssoRequired: boolean;
  verifiedAt?: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface SsoDiscoveryResult {
  domain: string;
  tenantId: string | null;
  ssoRequired: boolean;
  available: boolean;
}

export interface TenantControlPlaneConfig {
  tenantId: string;
  displayName?: string;
  policyExposure: PolicyExposureConfig;
  policyTemplates: PolicyTemplate[];
  secretRoutePresets: SecretRoutePreset[];
  approvalConfig: ApprovalConfig;
  featureFlags: TenantFeatureFlags;
  theme?: TenantTheme;
  /** Allowed CORS origins for this tenant. Empty array = wildcard (*) in dev mode. */
  allowedOrigins?: string[];
  createdAt?: Date;
  updatedAt?: Date;
}

export const DEFAULT_FEATURE_FLAGS: TenantFeatureFlags = {
  showFundingQR: true,
  showTransactionHistory: true,
  showSpendDashboard: true,
  showPolicyControls: true,
  showApprovalQueue: true,
  showSecretManager: false,
  enableSolana: true,
  showChainSelector: false,
  allowAddressExport: true,
};

/** Aggregated dashboard response for a single agent */
export interface AgentDashboardResponse {
  agent: AgentIdentity;
  balances: {
    evm?: {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
    };
    solana?: {
      native: string;
      nativeFormatted: string;
      chainId: number;
      symbol: string;
    };
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

// ─── Constants ───

export const SUPPORTED_CHAINS = {
  ethereum: 1,
  bsc: 56,
  bscTestnet: 97,
  gnosis: 100,
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
  1: {
    id: 1,
    name: "Ethereum",
    symbol: "ETH",
    explorerUrl: "https://etherscan.io",
    explorerTxUrl: "https://etherscan.io/tx/",
  },
  56: {
    id: 56,
    name: "BSC",
    symbol: "BNB",
    explorerUrl: "https://bscscan.com",
    explorerTxUrl: "https://bscscan.com/tx/",
  },
  97: {
    id: 97,
    name: "BSC Testnet",
    symbol: "tBNB",
    explorerUrl: "https://testnet.bscscan.com",
    explorerTxUrl: "https://testnet.bscscan.com/tx/",
  },
  100: {
    id: 100,
    name: "Gnosis",
    symbol: "xDAI",
    explorerUrl: "https://gnosisscan.io",
    explorerTxUrl: "https://gnosisscan.io/tx/",
  },
  137: {
    id: 137,
    name: "Polygon",
    symbol: "POL",
    explorerUrl: "https://polygonscan.com",
    explorerTxUrl: "https://polygonscan.com/tx/",
  },
  8453: {
    id: 8453,
    name: "Base",
    symbol: "ETH",
    explorerUrl: "https://basescan.org",
    explorerTxUrl: "https://basescan.org/tx/",
  },
  42161: {
    id: 42161,
    name: "Arbitrum",
    symbol: "ETH",
    explorerUrl: "https://arbiscan.io",
    explorerTxUrl: "https://arbiscan.io/tx/",
  },
  84532: {
    id: 84532,
    name: "Base Sepolia",
    symbol: "ETH",
    explorerUrl: "https://sepolia.basescan.org",
    explorerTxUrl: "https://sepolia.basescan.org/tx/",
  },
  // Solana
  101: {
    id: 101,
    name: "Solana",
    symbol: "SOL",
    explorerUrl: "https://explorer.solana.com",
    explorerTxUrl: "https://explorer.solana.com/tx/",
  },
  102: {
    id: 102,
    name: "Solana Devnet",
    symbol: "SOL",
    explorerUrl: "https://explorer.solana.com?cluster=devnet",
    explorerTxUrl: "https://explorer.solana.com/tx/",
  },
};

export function getChainMeta(chainId: number): ChainMeta | undefined {
  return CHAIN_META[chainId];
}

export function getExplorerTxLink(chainId: number, txHash: string): string | undefined {
  const meta = CHAIN_META[chainId];
  return meta ? `${meta.explorerTxUrl}${txHash}` : undefined;
}

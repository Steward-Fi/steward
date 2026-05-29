import type {
  AgentAccountSummary,
  AgentBalance,
  AgentDashboardResponse,
  AgentIdentity,
  AgentKeyQuorum,
  AgentKeyQuorumCreate,
  AgentKeyQuorumStatus,
  AgentKeyQuorumUpdate,
  AgentSigner,
  AgentSignerCreate,
  AgentSignerCreateResult,
  AgentSignerStatus,
  AgentSignerUpdate,
  AgentSpendSummary,
  ApiResponse,
  ApprovalQueueEntry,
  ApprovalStats,
  AuditLogResponse,
  AuditSummaryResponse,
  AutoApprovalRule,
  ChainFamily,
  ConditionSet,
  ConditionSetCreate,
  ConditionSetItem,
  ConditionSetItemInput,
  ConditionSetUpdate,
  CreateRoutePayload,
  CreateSecretPayload,
  ExportKeyResult,
  Intent,
  IntentCreate,
  IntentListOptions,
  PlatformLinkAccountResult,
  PlatformTenantUser,
  PlatformTransferAccountResult,
  PlatformUserDeactivateResult,
  PlatformUserDeleteResult,
  PlatformUserIdentity,
  PlatformUserLookupResult,
  PlatformUserSearchResult,
  PolicyResult,
  PolicyRule,
  PolicySimulateInput,
  PolicySimulateResult,
  PolicyTemplate,
  PolicyTemplateCreate,
  PolicyTemplateUpdate,
  RouteRecord,
  RpcResponse,
  SecretRecord,
  SponsoredGasSpendSummary,
  SsoDiscoveryResult,
  TenantAccessAllowlistEntry,
  TenantAccessAllowlistEntryInput,
  TenantAdminUser,
  TenantAdminUserSearchResult,
  TenantAppClient,
  TenantAppClientSecret,
  TenantAppClientSecretCreateResult,
  TenantAuthAbuseConfig,
  TenantControlPlaneConfig,
  TenantGasSponsorshipConfig,
  TenantMembership,
  TenantOidcProviderConfig,
  TenantSamlSsoConfig,
  TenantSamlSsoUpdate,
  TenantSsoDomain,
  TenantTeamRole,
  TenantTestAccountConfig,
  TxRecord,
  TypedDataDomain,
  TypedDataField,
  UpdateRoutePayload,
  UserAccountSummary,
  WebhookConfig,
  WebhookDelivery,
} from "./types.ts";

export interface BatchAgentSpec {
  id: string;
  name: string;
  platformId?: string;
}

export interface BatchCreateResult {
  created: AgentIdentity[];
  errors: Array<{ id: string; error: string }>;
}

export type GetBalanceResult = AgentBalance;

export interface StewardClientConfig {
  baseUrl: string;
  apiKey?: string;
  /** Privy-style app id for server auth, sent as Basic auth username and X-Steward-App-Id. */
  appId?: string;
  /** Privy-style app secret for server auth, sent only through Basic auth. */
  appSecret?: string;
  /** Platform management key - sent as `X-Steward-Platform-Key`. */
  platformKey?: string;
  /** Agent-scoped JWT - sent as `Authorization: Bearer <token>`. Preferred over apiKey when both are set. */
  bearerToken?: string;
  tenantId?: string;
  /** Optional HMAC secret used to sign sensitive mutating requests. */
  requestSigningSecret?: string;
  /**
   * Server-grade credentials are blocked in browser runtimes by default because
   * injected scripts can read request headers. Prefer bearerToken in browsers.
   */
  allowUnsafeBrowserSecrets?: boolean;
}

export interface QuorumSignerCredential {
  signerId: string;
  signerSecret: string;
}

export interface StewardSignerAuthOptions {
  /** Delegated signer id for non-admin flows. */
  signerId?: string;
  /** One-time-issued signer credential secret for delegated flows. */
  signerSecret?: string;
  /** Key quorum id for multi-signer non-admin flows. */
  keyQuorumId?: string;
  /** Signer-bound credentials that satisfy the key quorum threshold. */
  keyQuorumCredentials?: QuorumSignerCredential[];
}

export interface SignTransactionInput {
  to: string;
  value: string;
  data?: string;
  chainId?: number;
  broadcast?: boolean; // default true; set false to get signed tx without broadcasting
}

export type SignTransactionOptions = StewardSignerAuthOptions;

export interface SignTypedDataInput {
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  value: Record<string, unknown>;
}

export type SignTypedDataOptions = StewardSignerAuthOptions;

export interface SignUserOperationInput {
  userOperation: {
    sender: string;
    nonce: string;
    initCode?: string;
    callData: string;
    verificationGasLimit: string;
    callGasLimit: string;
    preVerificationGas: string;
    maxPriorityFeePerGas: string;
    maxFeePerGas: string;
    paymasterAndData?: string;
  };
  entryPoint?: string;
  chainId: number;
  /** Explicit policy recipient until calldata-level extraction is configured. */
  to: string;
  /** Explicit policy value in wei until calldata-level extraction is configured. */
  value: string;
  /** Optional caller-supplied ID mirrored in action payloads and lifecycle webhooks. */
  referenceId?: string;
}

export type SignUserOperationOptions = StewardSignerAuthOptions;

export interface SignAuthorizationInput {
  contractAddress: string;
  /** EIP-7702 allows 0 to designate any chain. */
  chainId: number;
  nonce: number;
  /** Optional caller-supplied ID mirrored in action payloads and lifecycle webhooks. */
  referenceId?: string;
}

export type SignAuthorizationOptions = StewardSignerAuthOptions;

export interface SignSolanaTransactionInput {
  transaction: string; // base64-encoded serialized Solana transaction
  chainId?: number; // 101 = mainnet, 102 = devnet
  broadcast?: boolean; // default true
}

export interface RpcPassthroughInput {
  method: string;
  params?: unknown[];
  chainId: number;
}

export interface StewardPendingApproval {
  status: "pending_approval";
  results: PolicyResult[];
}

export interface StewardHistoryEntry {
  timestamp: number;
  value: string;
}

export interface SignMessageResult {
  signature: string;
}

export type SignMessageOptions = StewardSignerAuthOptions;

export interface SignRawHashInput {
  hash: `0x${string}`;
  /** Optional caller-supplied ID mirrored in audit metadata. */
  referenceId?: string;
  /** Delegated signer or key quorum authentication for non-admin unsafe signing flows. */
  signerId?: StewardSignerAuthOptions["signerId"];
  signerSecret?: StewardSignerAuthOptions["signerSecret"];
  keyQuorumId?: StewardSignerAuthOptions["keyQuorumId"];
  keyQuorumCredentials?: StewardSignerAuthOptions["keyQuorumCredentials"];
}

export interface SignRawHashResult {
  signature: string;
  hash: `0x${string}`;
  walletAddress: string;
}

export type HyperliquidAsset =
  | "BTC"
  | "ETH"
  | "BNB"
  | "SOL"
  | "AVAX"
  | "ARB"
  | "OP"
  | "NEAR"
  | "HYPE"
  | "ZEC"
  | "XMR";

export interface CreateTradeSessionInput {
  agentId?: string;
  venue: "hyperliquid";
  walletAddress?: string;
  dailyCap?: number;
  perOrderCap?: number;
  leverageCap?: number;
  allowedAssets?: HyperliquidAsset[];
  ttlSeconds?: number;
}

export interface CreateTradeSessionResult {
  sessionId: string;
  expiresAt: string;
}

export interface RevokeTradeSessionResult {
  sessionId: string;
  revokedAt: string;
}

export interface TradeSessionState {
  id: string;
  agentId: string;
  tenantId: string;
  venue: "hyperliquid" | string;
  walletId: string;
  status: "active" | "revoked" | "expired";
  dailySpendUsd: number;
  dailyCapUsd: number;
  remainingCapUsd: number;
  perOrderCapUsd: number;
  leverageCap: number;
  allowedAssets: HyperliquidAsset[];
  createdAt: string;
  expiresAt: string;
  revokedAt?: string | null;
  revokedBy?: string | null;
}

const SENSITIVE_SIGNED_PATHS = [
  "/vault",
  "/agents",
  "/policies",
  "/secrets",
  "/trade",
  "/v1/trade",
  "/approvals",
  "/intents",
  "/user",
  "/webhooks",
  "/tenants",
  "/platform",
  "/condition-sets",
  "/condition_sets",
  "/v1/condition_sets",
];
const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret: string, canonical: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return [...new Uint8Array(signature)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomIdempotencyKey(): string {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function isSensitiveMutatingRequest(path: string, method: string): boolean {
  return (
    MUTATING_METHODS.has(method.toUpperCase()) &&
    SENSITIVE_SIGNED_PATHS.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
  );
}

export interface HyperliquidSubmitOrderInput {
  sessionId: string;
  asset: HyperliquidAsset;
  side: "buy" | "sell";
  size: number;
  leverage: number;
  reduceOnly?: boolean;
  idempotencyKey?: string;
}

export interface HyperliquidOrderResult {
  orderId: string;
  status: string;
  filledQty: number;
  avgPrice: number;
  txHash: string | null;
}

/**
 * Result of creating a wallet. For new agents, includes `walletAddresses`
 * with both EVM and Solana addresses.
 */
export type CreateWalletResult = AgentIdentity;

export interface GetAddressesResult {
  agentId: string;
  addresses: Array<{ chainFamily: ChainFamily; address: string }>;
}
export type GetHistoryResult = StewardHistoryEntry[];
export type SignTransactionResult =
  | { txHash: string; caip2?: string }
  | { signedTx: string; caip2?: string }
  | StewardPendingApproval;
export interface TransferActionQuoteInput {
  to: string;
  /** ERC20 token contract address. Defaults to native chain asset. */
  token?: "native" | string;
  value?: string;
  amountWei?: string;
  chainId?: number;
  broadcast?: boolean;
  /** Optional caller-supplied ID mirrored in action payloads and lifecycle webhooks. */
  referenceId?: string;
  /** Request tenant-configured gas sponsorship for supported execution paths. */
  sponsor?: boolean;
}

export type WalletActionOptions = StewardSignerAuthOptions;

export interface UserLinkedAccount {
  id: string;
  provider: string;
  providerAccountId: string;
  expiresAt: number | null;
}

export interface UserAccountsResult {
  accounts: UserLinkedAccount[];
  primaryLoginMethods: Array<{ provider: "email" | "wallet"; providerAccountId: string }>;
}

export interface UserAccountUnlinkResult {
  deleted: boolean;
  issuedBefore: number;
}

export interface UserEthereumWalletLinkNonce {
  nonce: string;
  message: string;
  expiresIn: number;
  address?: string;
}

export interface UserEthereumWalletLinkResult {
  account: UserLinkedAccount;
  isNew: boolean;
}

export interface UserSolanaWalletLinkNonce {
  nonce: string;
  message: string;
  expiresIn: number;
  publicKey?: string;
}

export interface UserSolanaWalletLinkResult {
  account: UserLinkedAccount;
  isNew: boolean;
}

export interface UserOAuthAccountLinkResult {
  account: UserLinkedAccount;
  isNew: boolean;
}

export interface UserOAuthAccountLinkChallenge {
  state: string;
  redirectUri: string;
  expiresIn: number;
}

export interface UserPhoneAccountLinkSendResult {
  phone: string;
  expiresAt: string;
}

export interface UserPhoneAccountLinkResult {
  account: UserLinkedAccount;
  isNew: boolean;
}

export interface UserSocialAccountLinkResult {
  account: UserLinkedAccount;
  isNew: boolean;
}

export interface UserSocialAccountLinkChallenge {
  challengeId?: string;
  nonce?: string;
  expiresIn: number;
}

export type AgentPolicyRuleCreate = Omit<PolicyRule, "id" | "enabled"> & {
  id?: string;
  enabled?: boolean;
};

export type AgentPolicyRuleUpdate = Partial<Omit<PolicyRule, "id">> & {
  id?: never;
};

export interface TransferActionQuote {
  quoteId: string;
  type: "transfer";
  chainId: number;
  from: string;
  to: string;
  value: string;
  token: "native" | string;
  expiresAt: string;
  request: {
    to: string;
    token: "native" | string;
    value: string;
    chainId: number;
    broadcast: boolean;
    referenceId?: string;
    sponsor?: boolean;
  };
}
export interface SendCallsActionInput {
  calls: Array<{ to: string; value?: string; data?: string }>;
  chainId?: number;
  broadcast?: boolean;
  /** Optional caller-supplied ID mirrored in action payloads and lifecycle webhooks. */
  referenceId?: string;
  /** Request tenant-configured gas sponsorship for supported execution paths. */
  sponsor?: boolean;
}
export type TransferActionStatus =
  | "pending_approval"
  | "rejected"
  | "signed"
  | "broadcast"
  | "failed";
export interface TransferAction {
  id: string;
  type: "transfer";
  status: TransferActionStatus;
  chainId: number;
  to: string;
  value: string;
  token: "native" | string;
  txHash?: string;
  signedTx?: string;
  sponsorship?: {
    requested: boolean;
    sponsored: boolean;
    provider?: string;
    mode?: string;
    estimatedUsd?: number | null;
  };
  policyResults?: PolicyResult[];
  createdAt?: string;
  signedAt?: string;
  confirmedAt?: string;
}
export interface SendCallsAction {
  id: string;
  type: "send_calls";
  status: "pending_approval" | "rejected";
  chainId: number;
  calls: Array<{ to: string; value: string; data?: string }>;
  totalValue: string;
  sponsorship?: {
    requested: boolean;
    sponsored: boolean;
    provider?: string;
    mode?: string;
    estimatedUsd?: number | null;
  };
  policyResults?: Array<PolicyResult & { callIndex?: number }>;
}
export type SignTypedDataResult = { signature: string };
export type SignUserOperationResult = {
  signature: string;
  userOperationHash: string;
  entryPoint: string;
  chainId: number;
  txId: string;
};
export type SignAuthorizationResult = {
  authorization: {
    contractAddress: string;
    chainId: number;
    nonce: number;
    r: string;
    s: string;
    yParity: 0 | 1;
  };
  txId: string;
};
export type SignSolanaTransactionResult = {
  signature: string;
  broadcast: boolean;
  chainId?: number;
  caip2?: string;
};
export type RpcPassthroughResult = RpcResponse;
export type TransactionListResult = {
  transactions: TxRecord[];
  limit: number;
  offset: number;
};
export type TransactionLifecycleEventType =
  | "transaction.broadcasted"
  | "transaction.confirmed"
  | "transaction.execution_reverted"
  | "transaction.replaced"
  | "transaction.failed"
  | "transaction.provider_error"
  | "transaction.still_pending";
export interface TransactionLifecycleUpdateInput {
  type: TransactionLifecycleEventType;
  txHash?: string;
  replacementTxHash?: string;
  reason?: string;
  error?: string;
  provider?: string;
  blockNumber?: string | number;
  confirmations?: number;
}
export interface TransactionReplaceInput {
  replacementTxHash: string;
  reason?: string;
  provider?: string;
  blockNumber?: string | number;
  confirmations?: number;
}
export type StewardErrorResponse = { results?: PolicyResult[] };

type ApiRequestResult<TSuccess, TFailure> =
  | { ok: true; status: number; data: TSuccess }
  | { ok: false; status: number; error: string; data?: TFailure };

function parseAgentIdentity(agent: AgentIdentity): AgentIdentity {
  return {
    ...agent,
    createdAt: new Date(agent.createdAt),
  };
}

function parsePlatformTenantUser(user: PlatformTenantUser): PlatformTenantUser {
  return {
    ...user,
    joinedAt: new Date(user.joinedAt),
    createdAt: new Date(user.createdAt),
    updatedAt: new Date(user.updatedAt),
  };
}

function parseTenantAdminUser(user: TenantAdminUser): TenantAdminUser {
  return {
    ...user,
    joinedAt: new Date(user.joinedAt),
    createdAt: new Date(user.createdAt),
    updatedAt: new Date(user.updatedAt),
  };
}

function parsePlatformUserIdentity(user: PlatformUserIdentity): PlatformUserIdentity {
  return {
    ...user,
    deactivatedAt: user.deactivatedAt ? new Date(user.deactivatedAt) : null,
    createdAt: new Date(user.createdAt),
    updatedAt: new Date(user.updatedAt),
  };
}

function parseTxRecord(tx: TxRecord): TxRecord {
  return {
    ...tx,
    createdAt: tx.createdAt instanceof Date ? tx.createdAt : new Date(tx.createdAt),
    signedAt: tx.signedAt
      ? tx.signedAt instanceof Date
        ? tx.signedAt
        : new Date(tx.signedAt)
      : undefined,
    confirmedAt: tx.confirmedAt
      ? tx.confirmedAt instanceof Date
        ? tx.confirmedAt
        : new Date(tx.confirmedAt)
      : undefined,
  };
}

function signerHeaders(options?: StewardSignerAuthOptions): HeadersInit | undefined {
  if (
    !options?.signerId &&
    !options?.signerSecret &&
    !options?.keyQuorumId &&
    !options?.keyQuorumCredentials?.length
  ) {
    return undefined;
  }
  const headers: Record<string, string> = {};
  if (options.signerId) headers["X-Steward-Signer-Id"] = options.signerId;
  if (options.signerSecret) headers["X-Steward-Signer-Secret"] = options.signerSecret;
  if (options.keyQuorumId) headers["X-Steward-Key-Quorum-Id"] = options.keyQuorumId;
  if (options.keyQuorumCredentials?.length) {
    headers["X-Steward-Key-Quorum-Credentials"] = JSON.stringify(options.keyQuorumCredentials);
  }
  return headers;
}

export class StewardApiError<TData = unknown> extends Error {
  readonly status: number;
  readonly data?: TData;

  constructor(message: string, status: number, data?: TData) {
    super(message);
    this.name = "StewardApiError";
    this.status = status;
    this.data = data;
  }
}

function isBrowserRuntime(): boolean {
  return typeof globalThis.window !== "undefined" && typeof globalThis.document !== "undefined";
}

export class StewardClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly appId?: string;
  private readonly appSecret?: string;
  private readonly platformKey?: string;
  private readonly bearerToken?: string;
  private readonly tenantId?: string;
  private readonly requestSigningSecret?: string;

  constructor({
    baseUrl,
    apiKey,
    appId,
    appSecret,
    platformKey,
    bearerToken,
    tenantId,
    requestSigningSecret,
    allowUnsafeBrowserSecrets,
  }: StewardClientConfig) {
    if (
      isBrowserRuntime() &&
      !allowUnsafeBrowserSecrets &&
      (apiKey || appSecret || platformKey || requestSigningSecret)
    ) {
      throw new StewardApiError(
        "apiKey, appSecret, platformKey, and requestSigningSecret must not be used in browser runtimes; use bearerToken or set allowUnsafeBrowserSecrets only for audited local tools.",
        0,
      );
    }
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.appId = appId;
    this.appSecret = appSecret;
    this.platformKey = platformKey;
    this.bearerToken = bearerToken;
    this.tenantId = tenantId;
    this.requestSigningSecret = requestSigningSecret;
  }

  readonly tradeSessions = {
    create: async (input: CreateTradeSessionInput): Promise<CreateTradeSessionResult> => {
      const response = await this.request<CreateTradeSessionResult, StewardErrorResponse>(
        "/v1/trade/sessions",
        {
          method: "POST",
          body: JSON.stringify(input),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },
    revoke: async (sessionId: string): Promise<RevokeTradeSessionResult> => {
      const response = await this.request<RevokeTradeSessionResult, StewardErrorResponse>(
        `/v1/trade/sessions/${encodeURIComponent(sessionId)}/revoke`,
        {
          method: "POST",
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },
    get: async (sessionId: string): Promise<TradeSessionState> => {
      const response = await this.request<TradeSessionState, StewardErrorResponse>(
        `/v1/trade/sessions/${encodeURIComponent(sessionId)}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },
  };

  readonly trade = {
    hyperliquid: {
      submitOrder: async (
        input: HyperliquidSubmitOrderInput,
        options?: { idempotencyKey?: string },
      ): Promise<HyperliquidOrderResult> => {
        const idempotencyKey = options?.idempotencyKey ?? input.idempotencyKey;
        const response = await this.request<HyperliquidOrderResult, StewardErrorResponse>(
          "/v1/trade/hyperliquid/order",
          {
            method: "POST",
            headers: idempotencyKey ? { "Idempotency-Key": idempotencyKey } : undefined,
            body: JSON.stringify(input),
          },
        );
        if (!response.ok) {
          throw new StewardApiError(response.error, response.status, response.data);
        }
        return response.data;
      },
    },
  };

  getBaseUrl(): string {
    return this.baseUrl;
  }

  readonly platformUsers = {
    getIdentity: async (userId: string): Promise<PlatformUserIdentity> => {
      const response = await this.request<PlatformUserIdentity, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return parsePlatformUserIdentity(response.data);
    },

    updateCustomMetadata: async (
      userId: string,
      customMetadata: Record<string, unknown>,
    ): Promise<PlatformUserIdentity> => {
      const response = await this.request<PlatformUserIdentity, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}/metadata`,
        {
          method: "PATCH",
          body: JSON.stringify({ customMetadata }),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return parsePlatformUserIdentity(response.data);
    },

    deactivate: async (
      userId: string,
      deactivated = true,
    ): Promise<PlatformUserDeactivateResult> => {
      const response = await this.request<PlatformUserDeactivateResult, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}/deactivate`,
        {
          method: "PATCH",
          body: JSON.stringify({ deactivated }),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return {
        ...response.data,
        deactivatedAt: response.data.deactivatedAt ? new Date(response.data.deactivatedAt) : null,
      };
    },

    delete: async (userId: string): Promise<PlatformUserDeleteResult> => {
      const response = await this.request<PlatformUserDeleteResult, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },

    lookup: async (opts: {
      email?: string;
      phone?: string;
      walletAddress?: string;
      smartWalletId?: string;
      customAuthId?: string;
      provider?: string;
      providerAccountId?: string;
      tenantId?: string;
    }): Promise<PlatformUserLookupResult> => {
      const params = new URLSearchParams();
      if (opts.email) params.set("email", opts.email);
      if (opts.phone) params.set("phone", opts.phone);
      if (opts.walletAddress) params.set("walletAddress", opts.walletAddress);
      if (opts.smartWalletId) params.set("smartWalletId", opts.smartWalletId);
      if (opts.customAuthId) params.set("customAuthId", opts.customAuthId);
      if (opts.provider) params.set("provider", opts.provider);
      if (opts.providerAccountId) params.set("providerAccountId", opts.providerAccountId);
      if (opts.tenantId) params.set("tenantId", opts.tenantId);
      const response = await this.request<PlatformUserLookupResult, StewardErrorResponse>(
        `/platform/users/lookup?${params.toString()}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return {
        user: response.data.user ? parsePlatformUserIdentity(response.data.user) : null,
      };
    },

    getUserByEmailAddress: async (
      email: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ email, tenantId: opts?.tenantId }),

    getUserByPhoneNumber: async (
      phone: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ phone, tenantId: opts?.tenantId }),

    getUserByWalletAddress: async (
      walletAddress: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ walletAddress, tenantId: opts?.tenantId }),

    getUserBySmartWalletAddress: async (
      smartWalletId: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ smartWalletId, tenantId: opts?.tenantId }),

    getUserByCustomAuthId: async (
      customAuthId: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ customAuthId, tenantId: opts?.tenantId }),

    getUserByProviderAccount: async (
      provider: string,
      providerAccountId: string,
      opts?: { tenantId?: string },
    ): Promise<PlatformUserLookupResult> =>
      this.platformUsers.lookup({ provider, providerAccountId, tenantId: opts?.tenantId }),

    getUserByDiscordUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("discord", username, opts),
    getUserByGithubUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("github", username, opts),
    getUserByFarcasterId: async (fid: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("farcaster", fid, opts),
    getUserByInstagramUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("instagram", username, opts),
    getUserBySpotifySubject: async (subject: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("spotify", subject, opts),
    getUserByTelegramUserId: async (id: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("telegram", id, opts),
    getUserByTelegramUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("telegram", username, opts),
    getUserByTwitchUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("twitch", username, opts),
    getUserByTwitterSubject: async (subject: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("twitter", subject, opts),
    getUserByTwitterUsername: async (username: string, opts?: { tenantId?: string }) =>
      this.platformUsers.getUserByProviderAccount("twitter", username, opts),

    search: async (
      tenantId: string,
      opts?: { q?: string; email?: string; limit?: number; offset?: number },
    ): Promise<PlatformUserSearchResult> => {
      const params = new URLSearchParams();
      if (opts?.q) params.set("q", opts.q);
      if (opts?.email) params.set("email", opts.email);
      if (opts?.limit) params.set("limit", String(opts.limit));
      if (opts?.offset) params.set("offset", String(opts.offset));
      const qs = params.toString();
      const response = await this.request<PlatformUserSearchResult, StewardErrorResponse>(
        `/platform/tenants/${encodeURIComponent(tenantId)}/users${qs ? `?${qs}` : ""}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return {
        ...response.data,
        users: response.data.users.map(parsePlatformTenantUser),
      };
    },

    get: async (tenantId: string, userId: string): Promise<PlatformTenantUser> => {
      const response = await this.request<PlatformTenantUser, StewardErrorResponse>(
        `/platform/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return parsePlatformTenantUser(response.data);
    },

    updateMetadata: async (
      tenantId: string,
      userId: string,
      metadata: {
        customMetadata?: Record<string, unknown>;
        tenantCustomMetadata?: Record<string, unknown>;
      },
    ): Promise<PlatformTenantUser> => {
      const response = await this.request<PlatformTenantUser, StewardErrorResponse>(
        `/platform/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/metadata`,
        {
          method: "PATCH",
          body: JSON.stringify(metadata),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return parsePlatformTenantUser(response.data);
    },

    linkAccount: async (
      userId: string,
      input: { provider: string; providerAccountId: string },
    ): Promise<PlatformLinkAccountResult> => {
      const response = await this.request<PlatformLinkAccountResult, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}/accounts`,
        {
          method: "POST",
          body: JSON.stringify(input),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },

    unlinkAccount: async (
      userId: string,
      provider: string,
      providerAccountId: string,
      opts?: { force?: boolean },
    ): Promise<void> => {
      const params = new URLSearchParams();
      if (opts?.force) params.set("force", "true");
      const qs = params.toString();
      const response = await this.request<Record<string, never>, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(userId)}/accounts/${encodeURIComponent(provider)}/${encodeURIComponent(providerAccountId)}${qs ? `?${qs}` : ""}`,
        { method: "DELETE" },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    },

    transferAccount: async (
      fromUserId: string,
      provider: string,
      providerAccountId: string,
      input: { toUserId: string; force?: boolean },
    ): Promise<PlatformTransferAccountResult> => {
      const response = await this.request<PlatformTransferAccountResult, StewardErrorResponse>(
        `/platform/users/${encodeURIComponent(fromUserId)}/accounts/${encodeURIComponent(provider)}/${encodeURIComponent(providerAccountId)}/transfer`,
        {
          method: "POST",
          body: JSON.stringify(input),
        },
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },
  };

  readonly platformApps = {
    getGasSpend: async (input: {
      tenantId: string;
      walletIds: string[];
      startTimestamp?: number;
      endTimestamp?: number;
    }): Promise<SponsoredGasSpendSummary> => {
      const params = new URLSearchParams();
      params.set("tenant_id", input.tenantId);
      params.set("wallet_ids", input.walletIds.join(","));
      if (input.startTimestamp !== undefined) {
        params.set("start_timestamp", String(input.startTimestamp));
      }
      if (input.endTimestamp !== undefined) {
        params.set("end_timestamp", String(input.endTimestamp));
      }
      const response = await this.request<SponsoredGasSpendSummary, StewardErrorResponse>(
        `/platform/apps/gas_spend?${params.toString()}`,
      );
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data;
    },
  };

  readonly platformTestAccounts = {
    get: async (tenantId: string): Promise<TenantTestAccountConfig> => {
      const response = await this.request<
        { testAccount: TenantTestAccountConfig },
        StewardErrorResponse
      >(`/platform/tenants/${encodeURIComponent(tenantId)}/test-account`);
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data.testAccount;
    },

    enable: async (tenantId: string): Promise<TenantTestAccountConfig> => {
      const response = await this.request<
        { testAccount: TenantTestAccountConfig },
        StewardErrorResponse
      >(`/platform/tenants/${encodeURIComponent(tenantId)}/test-account`, {
        method: "POST",
      });
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data.testAccount;
    },

    disable: async (tenantId: string): Promise<TenantTestAccountConfig> => {
      const response = await this.request<
        { testAccount: TenantTestAccountConfig },
        StewardErrorResponse
      >(`/platform/tenants/${encodeURIComponent(tenantId)}/test-account`, {
        method: "DELETE",
      });
      if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
      return response.data.testAccount;
    },
  };

  async createWallet(
    agentId: string,
    name: string,
    platformId?: string,
  ): Promise<CreateWalletResult> {
    const response = await this.request<AgentIdentity, StewardErrorResponse>("/agents", {
      method: "POST",
      body: JSON.stringify({ id: agentId, name, platformId }),
    });

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return parseAgentIdentity(response.data);
  }

  async signTransaction(
    agentId: string,
    tx: SignTransactionInput,
    options?: SignTransactionOptions,
  ): Promise<SignTransactionResult> {
    const response = await this.request<
      { txHash: string },
      StewardPendingApproval | StewardErrorResponse
    >(`/vault/${encodeURIComponent(agentId)}/sign`, {
      method: "POST",
      headers: signerHeaders(options),
      body: JSON.stringify(tx),
    });

    if (response.ok) {
      return response.data;
    }

    if (response.status === 202 && this.isPendingApproval(response.data)) {
      return response.data;
    }

    throw new StewardApiError(response.error, response.status, response.data);
  }

  async quoteTransfer(
    agentId: string,
    input: TransferActionQuoteInput,
  ): Promise<TransferActionQuote> {
    const response = await this.request<TransferActionQuote, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/actions/transfer/quote`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async createTransferAction(
    agentId: string,
    input: TransferActionQuoteInput,
    options?: WalletActionOptions,
  ): Promise<TransferAction> {
    const response = await this.request<TransferAction, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/actions/transfer`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async createSendCallsAction(
    agentId: string,
    input: SendCallsActionInput,
    options?: WalletActionOptions,
  ): Promise<SendCallsAction> {
    const response = await this.request<SendCallsAction, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/actions/send-calls`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async getTransferAction(agentId: string, actionId: string): Promise<TransferAction> {
    const response = await this.request<TransferAction, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/actions/${encodeURIComponent(actionId)}`,
    );

    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async getPolicies(agentId: string): Promise<PolicyRule[]> {
    const response = await this.request<PolicyRule[], StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Replace the policy set for an agent. Returns the stored policies
   * (with server-assigned ids where applicable).
   */
  async setPolicies(agentId: string, policies: PolicyRule[]): Promise<PolicyRule[]> {
    const response = await this.request<PolicyRule[] | undefined, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies`,
      {
        method: "PUT",
        body: JSON.stringify(policies),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    // Older API builds returned no body; fall back to the input on void.
    return response.data ?? policies;
  }

  async listPolicyRules(agentId: string): Promise<PolicyRule[]> {
    const response = await this.request<{ rules: PolicyRule[] }, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies/rules`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data.rules;
  }

  async createPolicyRule(agentId: string, rule: AgentPolicyRuleCreate): Promise<PolicyRule> {
    const response = await this.request<PolicyRule, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies/rules`,
      {
        method: "POST",
        body: JSON.stringify(rule),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  async getPolicyRule(agentId: string, ruleId: string): Promise<PolicyRule> {
    const response = await this.request<PolicyRule, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies/rules/${encodeURIComponent(ruleId)}`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  async updatePolicyRule(
    agentId: string,
    ruleId: string,
    update: AgentPolicyRuleUpdate,
  ): Promise<PolicyRule> {
    const response = await this.request<PolicyRule, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies/rules/${encodeURIComponent(ruleId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(update),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  async deletePolicyRule(agentId: string, ruleId: string): Promise<PolicyRule> {
    const response = await this.request<PolicyRule, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies/rules/${encodeURIComponent(ruleId)}`,
      { method: "DELETE" },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  async getAgent(agentId: string): Promise<AgentIdentity> {
    const response = await this.request<AgentIdentity, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return parseAgentIdentity(response.data);
  }

  async listAgents(): Promise<AgentIdentity[]> {
    const response = await this.request<AgentIdentity[], StewardErrorResponse>("/agents");

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data.map(parseAgentIdentity);
  }

  /**
   * Return a compact history feed for an agent. Each entry is a
   * `{ timestamp, value }` pair - suitable for trend charts and volume
   * windows. For the full signed-transaction objects, prefer
   * {@link getTransactionHistory}.
   */
  async getHistory(agentId: string): Promise<GetHistoryResult> {
    const records = await this.getTransactionHistory(agentId);
    return records.map((tx) => ({
      timestamp: Math.floor(
        (tx.createdAt instanceof Date ? tx.createdAt.getTime() : new Date(tx.createdAt).getTime()) /
          1000,
      ),
      value: tx.request?.value ?? "0",
    }));
  }

  /**
   * Return the full transaction history for an agent as `TxRecord[]`.
   * Includes status, policy results, tx hash, timestamps, and the
   * original sign request.
   */
  async getTransactionHistory(agentId: string): Promise<TxRecord[]> {
    const response = await this.request<TxRecord[] | TransactionListResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/history`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    const records = Array.isArray(response.data) ? response.data : response.data.transactions;
    return records.map(parseTxRecord);
  }

  async listTransactions(
    agentId: string,
    opts?: {
      status?: string;
      actionType?: string;
      txHash?: string;
      limit?: number;
      offset?: number;
    },
  ): Promise<TransactionListResult> {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    if (opts?.actionType) params.set("actionType", opts.actionType);
    if (opts?.txHash) params.set("txHash", opts.txHash);
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    const response = await this.request<TransactionListResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/transactions${qs ? `?${qs}` : ""}`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return {
      ...response.data,
      transactions: response.data.transactions.map(parseTxRecord),
    };
  }

  async getTransaction(agentId: string, txId: string): Promise<TxRecord> {
    const response = await this.request<TxRecord, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/transactions/${encodeURIComponent(txId)}`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return parseTxRecord(response.data);
  }

  async updateTransactionLifecycle(
    agentId: string,
    txId: string,
    input: TransactionLifecycleUpdateInput,
  ): Promise<TxRecord> {
    const response = await this.request<TxRecord, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/transactions/${encodeURIComponent(txId)}/lifecycle`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return parseTxRecord(response.data);
  }

  async replaceTransaction(
    agentId: string,
    txId: string,
    input: TransactionReplaceInput,
  ): Promise<TxRecord> {
    const response = await this.request<TxRecord, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/transactions/${encodeURIComponent(txId)}/replace`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return parseTxRecord(response.data);
  }

  async signMessage(
    agentId: string,
    message: string,
    options?: SignMessageOptions,
  ): Promise<SignMessageResult> {
    const response = await this.request<SignMessageResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-message`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify({ message }),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  async signRawHash(agentId: string, input: SignRawHashInput): Promise<SignRawHashResult> {
    const {
      signerId: _signerId,
      signerSecret: _signerSecret,
      keyQuorumId: _keyQuorumId,
      keyQuorumCredentials: _keyQuorumCredentials,
      ...body
    } = input;
    const response = await this.request<SignRawHashResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-raw-hash`,
      {
        method: "POST",
        headers: signerHeaders(input),
        body: JSON.stringify(body),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Sign EIP-712 typed data (`eth_signTypedData_v4`).
   * Used for DEX approvals, ERC-20 permits, and structured data signatures.
   */
  async signTypedData(
    agentId: string,
    input: SignTypedDataInput,
    options?: SignTypedDataOptions,
  ): Promise<SignTypedDataResult> {
    const response = await this.request<SignTypedDataResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-typed-data`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Sign an ERC-4337 EntryPoint v0.7 user operation (`eth_signUserOperation`).
   * `to` and `value` are required for policy evaluation until calldata extraction is configured.
   */
  async signUserOperation(
    agentId: string,
    input: SignUserOperationInput,
    options?: SignUserOperationOptions,
  ): Promise<SignUserOperationResult> {
    const response = await this.request<SignUserOperationResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-user-operation`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Sign an EIP-7702 set-code authorization for inclusion in an authorizationList.
   */
  async signAuthorization(
    agentId: string,
    input: SignAuthorizationInput,
    options?: SignAuthorizationOptions,
  ): Promise<SignAuthorizationResult> {
    const response = await this.request<SignAuthorizationResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-authorization`,
      {
        method: "POST",
        headers: signerHeaders(options),
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Sign a serialized Solana transaction.
   * Pass a base64-encoded transaction; optionally broadcast via Solana RPC.
   */
  async signSolanaTransaction(
    agentId: string,
    input: SignSolanaTransactionInput,
  ): Promise<SignSolanaTransactionResult> {
    const response = await this.request<SignSolanaTransactionResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-solana`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Proxy a read-only RPC call to the appropriate chain provider.
   * Signing/state-modifying methods are blocked server-side.
   */
  async rpcPassthrough(agentId: string, input: RpcPassthroughInput): Promise<RpcPassthroughResult> {
    const response = await this.request<RpcPassthroughResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/rpc`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Get the on-chain native balance for an agent wallet.
   * Optionally pass a chainId to query a specific network (defaults to the server's active chain).
   */
  async getBalance(agentId: string, chainId?: number): Promise<GetBalanceResult> {
    const params = chainId ? `?chainId=${chainId}` : "";
    const response = await this.request<AgentBalance, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/balance${params}`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Get all wallet addresses for an agent across all chain families.
   * New agents have both EVM and Solana addresses; legacy agents have EVM only.
   */
  async getAddresses(agentId: string): Promise<GetAddressesResult> {
    const response = await this.request<GetAddressesResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/addresses`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /**
   * Export the private keys for the authenticated user's personal wallet.
   * Requires a user session token (Bearer JWT).
   */
  async exportUserWalletKey(): Promise<ExportKeyResult> {
    const response = await this.request<ExportKeyResult, StewardErrorResponse>(
      "/user/me/wallet/export",
      { method: "POST" },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  /** List linked accounts for the authenticated user. Requires user JWT. */
  async listUserAccounts(): Promise<UserAccountsResult> {
    const response = await this.request<UserAccountsResult, StewardErrorResponse>(
      "/user/me/accounts",
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get the authenticated user's aggregated account, wallets, portfolio, and spend. */
  async getUserAccount(
    opts: { chainId?: number; tokens?: string[] } = {},
  ): Promise<UserAccountSummary> {
    const params = new URLSearchParams();
    if (opts.chainId) params.set("chainId", String(opts.chainId));
    if (opts.tokens?.length) params.set("tokens", opts.tokens.join(","));
    const qs = params.toString();
    const response = await this.request<UserAccountSummary, StewardErrorResponse>(
      `/user/me/account${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a one-time message for linking an Ethereum wallet to the authenticated user. */
  async createUserEthereumWalletLinkNonce(address?: string): Promise<UserEthereumWalletLinkNonce> {
    const response = await this.request<UserEthereumWalletLinkNonce, StewardErrorResponse>(
      "/user/me/accounts/wallet/ethereum/nonce",
      {
        method: "POST",
        body: JSON.stringify(address ? { address } : {}),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link an Ethereum wallet to the authenticated user using the signed nonce message. */
  async linkUserEthereumWallet(input: {
    address: string;
    message: string;
    signature: string;
  }): Promise<UserEthereumWalletLinkResult> {
    const response = await this.request<UserEthereumWalletLinkResult, StewardErrorResponse>(
      "/user/me/accounts/wallet/ethereum",
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a one-time message for linking a Solana wallet to the authenticated user. */
  async createUserSolanaWalletLinkNonce(publicKey?: string): Promise<UserSolanaWalletLinkNonce> {
    const response = await this.request<UserSolanaWalletLinkNonce, StewardErrorResponse>(
      "/user/me/accounts/wallet/solana/nonce",
      {
        method: "POST",
        body: JSON.stringify(publicKey ? { publicKey } : {}),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link a Solana wallet to the authenticated user using the signed nonce message. */
  async linkUserSolanaWallet(input: {
    publicKey: string;
    message: string;
    signature: string;
  }): Promise<UserSolanaWalletLinkResult> {
    const response = await this.request<UserSolanaWalletLinkResult, StewardErrorResponse>(
      "/user/me/accounts/wallet/solana",
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a one-time state challenge for linking an OAuth account. */
  async createUserOAuthAccountLinkChallenge(
    provider: string,
    input: { redirectUri: string; codeChallenge?: string; codeChallengeMethod?: string },
  ): Promise<UserOAuthAccountLinkChallenge> {
    const response = await this.request<UserOAuthAccountLinkChallenge, StewardErrorResponse>(
      `/user/me/accounts/oauth/${encodeURIComponent(provider)}/challenge`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link an OAuth account to the authenticated user using an authorization code and state. */
  async linkUserOAuthAccount(
    provider: string,
    input: { code: string; redirectUri: string; state: string; codeVerifier?: string },
  ): Promise<UserOAuthAccountLinkResult> {
    const response = await this.request<UserOAuthAccountLinkResult, StewardErrorResponse>(
      `/user/me/accounts/oauth/${encodeURIComponent(provider)}/token`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Send an OTP for linking a phone number to the authenticated user. */
  async sendUserPhoneAccountLinkOtp(
    phone: string,
    channel: "sms" | "whatsapp" = "sms",
  ): Promise<UserPhoneAccountLinkSendResult> {
    const response = await this.request<UserPhoneAccountLinkSendResult, StewardErrorResponse>(
      `/user/me/accounts/phone/${channel}/send`,
      {
        method: "POST",
        body: JSON.stringify({ phone }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Verify an OTP and link a phone number to the authenticated user. */
  async verifyUserPhoneAccountLinkOtp(
    input: { phone: string; code: string },
    channel: "sms" | "whatsapp" = "sms",
  ): Promise<UserPhoneAccountLinkResult> {
    const response = await this.request<UserPhoneAccountLinkResult, StewardErrorResponse>(
      `/user/me/accounts/phone/${channel}/verify`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link a Telegram Login Widget account to the authenticated user. */
  async createUserTelegramAccountLinkChallenge(): Promise<UserSocialAccountLinkChallenge> {
    const response = await this.request<UserSocialAccountLinkChallenge, StewardErrorResponse>(
      "/user/me/accounts/telegram/challenge",
      { method: "POST", body: JSON.stringify({}) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link a Telegram Login Widget account to the authenticated user. */
  async linkUserTelegramAccount(
    input: Record<string, unknown>,
  ): Promise<UserSocialAccountLinkResult> {
    const response = await this.request<UserSocialAccountLinkResult, StewardErrorResponse>(
      "/user/me/accounts/telegram",
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a one-time nonce for linking a Farcaster account to the authenticated user. */
  async createUserFarcasterAccountLinkNonce(): Promise<UserSocialAccountLinkChallenge> {
    const response = await this.request<UserSocialAccountLinkChallenge, StewardErrorResponse>(
      "/user/me/accounts/farcaster/nonce",
      { method: "POST", body: JSON.stringify({}) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Link a Farcaster SIWF account to the authenticated user. */
  async linkUserFarcasterAccount(input: {
    message: string;
    signature: string;
    custodyAddress?: string;
    address?: string;
    fid?: string | number;
    username?: string;
    displayName?: string;
    pfpUrl?: string;
    pfp?: string;
  }): Promise<UserSocialAccountLinkResult> {
    const response = await this.request<UserSocialAccountLinkResult, StewardErrorResponse>(
      "/user/me/accounts/farcaster",
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Unlink a linked account from the authenticated user. Requires another login method. */
  async unlinkUserAccount(
    provider: string,
    providerAccountId: string,
  ): Promise<UserAccountUnlinkResult> {
    const response = await this.request<UserAccountUnlinkResult, StewardErrorResponse>(
      `/user/me/accounts/${encodeURIComponent(provider)}/${encodeURIComponent(providerAccountId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /**
   * Export the private keys for a vault agent.
   * Requires tenant-level authentication.
   */
  async exportAgentKey(agentId: string): Promise<ExportKeyResult> {
    const response = await this.request<ExportKeyResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/export`,
      { method: "POST" },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
  }

  // ─── Tenant Config ─────────────────────────────────────────────

  /** Get the control-plane configuration for a tenant. */
  async getTenantConfig(tenantId: string): Promise<TenantControlPlaneConfig> {
    const response = await this.request<TenantControlPlaneConfig, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/config`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Update the control-plane configuration for a tenant. */
  async updateTenantConfig(
    tenantId: string,
    config: Partial<TenantControlPlaneConfig>,
  ): Promise<TenantControlPlaneConfig> {
    const response = await this.request<TenantControlPlaneConfig, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/config`,
      {
        method: "PUT",
        body: JSON.stringify(config),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** List tenant app origins used for CORS, passkeys, SIWE/SIWS, and OAuth redirects. */
  async listAppOrigins(tenantId: string): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-origins`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Add one or more tenant app origins. Requires tenant-admin MFA server-side. */
  async addAppOrigin(tenantId: string, origin: string): Promise<string[]> {
    return this.addAppOrigins(tenantId, [origin]);
  }

  /** Add one or more tenant app origins. Requires tenant-admin MFA server-side. */
  async addAppOrigins(tenantId: string, origins: string[]): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-origins`,
      {
        method: "POST",
        body: JSON.stringify({ origins }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Remove one tenant app origin. Requires tenant-admin MFA server-side. */
  async removeAppOrigin(tenantId: string, origin: string): Promise<string[]> {
    return this.removeAppOrigins(tenantId, [origin]);
  }

  /** Remove one or more tenant app origins. Requires tenant-admin MFA server-side. */
  async removeAppOrigins(tenantId: string, origins: string[]): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-origins`,
      {
        method: "DELETE",
        body: JSON.stringify({ origins }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** List tenant redirect URLs used for OAuth and email auth callbacks. */
  async listRedirectUrls(tenantId: string): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/redirect-urls`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Add one tenant redirect URL. Requires tenant-admin MFA server-side. */
  async addRedirectUrl(tenantId: string, url: string): Promise<string[]> {
    return this.addRedirectUrls(tenantId, [url]);
  }

  /** Add one or more tenant redirect URLs. Requires tenant-admin MFA server-side. */
  async addRedirectUrls(tenantId: string, urls: string[]): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/redirect-urls`,
      {
        method: "POST",
        body: JSON.stringify({ urls }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Remove one tenant redirect URL. Requires tenant-admin MFA server-side. */
  async removeRedirectUrl(tenantId: string, url: string): Promise<string[]> {
    return this.removeRedirectUrls(tenantId, [url]);
  }

  /** Remove one or more tenant redirect URLs. Requires tenant-admin MFA server-side. */
  async removeRedirectUrls(tenantId: string, urls: string[]): Promise<string[]> {
    const response = await this.request<{ entries: string[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/redirect-urls`,
      {
        method: "DELETE",
        body: JSON.stringify({ urls }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** List tenant app clients/environments. Requires tenant-admin MFA server-side. */
  async listTenantAppClients(tenantId: string): Promise<TenantAppClient[]> {
    const response = await this.request<{ clients: TenantAppClient[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.clients;
  }

  /** Replace the tenant app client/environment registry. Requires tenant-admin MFA server-side. */
  async replaceTenantAppClients(
    tenantId: string,
    clients: TenantAppClient[],
  ): Promise<TenantAppClient[]> {
    const response = await this.request<{ clients: TenantAppClient[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients`,
      {
        method: "PUT",
        body: JSON.stringify({ clients }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.clients;
  }

  /** Create one tenant app client/environment. Requires tenant-admin MFA server-side. */
  async createTenantAppClient(tenantId: string, client: TenantAppClient): Promise<TenantAppClient> {
    const response = await this.request<{ client: TenantAppClient }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients`,
      {
        method: "POST",
        body: JSON.stringify({ client }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.client;
  }

  /** Delete one tenant app client/environment. Requires tenant-admin MFA server-side. */
  async deleteTenantAppClient(tenantId: string, clientId: string): Promise<TenantAppClient[]> {
    const response = await this.request<{ clients: TenantAppClient[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients/${encodeURIComponent(clientId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.clients;
  }

  /** List app-client secret metadata. Raw secrets are never returned by this endpoint. */
  async listTenantAppClientSecrets(
    tenantId: string,
    clientId: string,
  ): Promise<{ appId: string; secrets: TenantAppClientSecret[] }> {
    const response = await this.request<
      { appId: string; secrets: TenantAppClientSecret[] },
      StewardErrorResponse
    >(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients/${encodeURIComponent(clientId)}/secrets`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Rotate an app-client secret. Returns the raw appSecret once. */
  async rotateTenantAppClientSecret(
    tenantId: string,
    clientId: string,
  ): Promise<TenantAppClientSecretCreateResult> {
    const response = await this.request<TenantAppClientSecretCreateResult, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients/${encodeURIComponent(clientId)}/secrets`,
      { method: "POST" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Revoke one app-client secret immediately. */
  async revokeTenantAppClientSecret(
    tenantId: string,
    clientId: string,
    secretId: string,
  ): Promise<TenantAppClientSecret> {
    const response = await this.request<{ secret: TenantAppClientSecret }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/app-clients/${encodeURIComponent(
        clientId,
      )}/secrets/${encodeURIComponent(secretId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.secret;
  }

  /** List tenant app access allowlist entries for email, domain, wallet, and phone login. */
  async listAccessAllowlistEntries(tenantId: string): Promise<TenantAccessAllowlistEntry[]> {
    const response = await this.request<
      { entries: TenantAccessAllowlistEntry[] },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/access-allowlist`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Add one tenant app access allowlist entry. Requires tenant-admin MFA server-side. */
  async addAccessAllowlistEntry(
    tenantId: string,
    entry: TenantAccessAllowlistEntryInput,
  ): Promise<TenantAccessAllowlistEntry[]> {
    return this.addAccessAllowlistEntries(tenantId, [entry]);
  }

  /** Add one or more tenant app access allowlist entries. Requires tenant-admin MFA server-side. */
  async addAccessAllowlistEntries(
    tenantId: string,
    entries: TenantAccessAllowlistEntryInput[],
  ): Promise<TenantAccessAllowlistEntry[]> {
    const response = await this.request<
      { entries: TenantAccessAllowlistEntry[] },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/access-allowlist`, {
      method: "POST",
      body: JSON.stringify({ entries }),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Remove one tenant app access allowlist entry. Requires tenant-admin MFA server-side. */
  async removeAccessAllowlistEntry(
    tenantId: string,
    entry: TenantAccessAllowlistEntryInput | { id: string },
  ): Promise<TenantAccessAllowlistEntry[]> {
    if ("id" in entry) {
      return this.removeAccessAllowlistEntries(tenantId, { ids: [entry.id] });
    }
    return this.removeAccessAllowlistEntries(tenantId, { entries: [entry] });
  }

  /** Remove tenant app access allowlist entries by id or by type/value pair. */
  async removeAccessAllowlistEntries(
    tenantId: string,
    input: { ids?: string[]; entries?: TenantAccessAllowlistEntryInput[] },
  ): Promise<TenantAccessAllowlistEntry[]> {
    const response = await this.request<
      { entries: TenantAccessAllowlistEntry[] },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/access-allowlist`, {
      method: "DELETE",
      body: JSON.stringify(input),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.entries;
  }

  /** Get tenant-scoped OIDC/JWT login provider configuration. */
  async getTenantOidcProviders(tenantId: string): Promise<TenantOidcProviderConfig[]> {
    const response = await this.request<
      { providers: TenantOidcProviderConfig[] },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/oidc-providers`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.providers;
  }

  /** Discover whether an email domain should route to tenant SSO. */
  async discoverSso(email: string): Promise<SsoDiscoveryResult> {
    const response = await this.request<SsoDiscoveryResult, StewardErrorResponse>(
      "/auth/sso/discover",
      {
        method: "POST",
        body: JSON.stringify({ email }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** List tenant verified/draft SSO email domains. Requires tenant-admin MFA server-side. */
  async listTenantSsoDomains(tenantId: string): Promise<TenantSsoDomain[]> {
    const response = await this.request<{ domains: TenantSsoDomain[] }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/sso-domains`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.domains;
  }

  /** Create or reset a tenant SSO email-domain verification token. */
  async createTenantSsoDomain(
    tenantId: string,
    input: { domain: string; ssoRequired?: boolean },
  ): Promise<TenantSsoDomain> {
    const response = await this.request<{ domain: TenantSsoDomain }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/sso-domains`,
      { method: "POST", body: JSON.stringify(input) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.domain;
  }

  /** Mark a tenant SSO domain verified after out-of-band DNS/manual verification. */
  async verifyTenantSsoDomain(tenantId: string, domain: string): Promise<TenantSsoDomain> {
    const response = await this.request<{ domain: TenantSsoDomain }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/sso-domains/${encodeURIComponent(domain)}/verify`,
      { method: "POST" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.domain;
  }

  /** Delete a tenant SSO domain. */
  async deleteTenantSsoDomain(tenantId: string, domain: string): Promise<void> {
    const response = await this.request<{ deleted: boolean }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/sso-domains/${encodeURIComponent(domain)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  /** Get tenant SAML dashboard/team SSO config and generated SP URLs. */
  async getTenantSamlSso(tenantId: string): Promise<{
    config: TenantSamlSsoConfig | null;
    serviceProvider: { spEntityId: string; acsUrl: string; metadataUrl: string };
  }> {
    const response = await this.request<
      {
        config: TenantSamlSsoConfig | null;
        serviceProvider: { spEntityId: string; acsUrl: string; metadataUrl: string };
      },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/saml-sso`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Replace tenant SAML dashboard/team SSO config. Requires tenant-admin MFA server-side. */
  async updateTenantSamlSso(
    tenantId: string,
    input: TenantSamlSsoUpdate,
  ): Promise<TenantSamlSsoConfig> {
    const response = await this.request<{ config: TenantSamlSsoConfig }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/saml-sso`,
      { method: "PUT", body: JSON.stringify(input) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.config;
  }

  /** Delete tenant SAML dashboard/team SSO config. */
  async deleteTenantSamlSso(tenantId: string): Promise<void> {
    const response = await this.request<{ deleted: boolean }, StewardErrorResponse>(
      `/tenants/${encodeURIComponent(tenantId)}/saml-sso`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  /** Replace tenant-scoped OIDC/JWT login provider configuration. */
  async updateTenantOidcProviders(
    tenantId: string,
    providers: TenantOidcProviderConfig[],
  ): Promise<TenantOidcProviderConfig[]> {
    const response = await this.request<
      { providers: TenantOidcProviderConfig[] },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/oidc-providers`, {
      method: "PUT",
      body: JSON.stringify({ providers }),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.providers;
  }

  /** Get tenant-scoped auth abuse and login method controls. */
  async getTenantAuthAbuseConfig(tenantId: string): Promise<TenantAuthAbuseConfig> {
    const response = await this.request<
      { authAbuseConfig: TenantAuthAbuseConfig },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/auth-abuse-config`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.authAbuseConfig;
  }

  /** Replace tenant-scoped auth abuse and login method controls. */
  async updateTenantAuthAbuseConfig(
    tenantId: string,
    authAbuseConfig: TenantAuthAbuseConfig,
  ): Promise<TenantAuthAbuseConfig> {
    const response = await this.request<
      { authAbuseConfig: TenantAuthAbuseConfig },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/auth-abuse-config`, {
      method: "PUT",
      body: JSON.stringify({ authAbuseConfig }),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.authAbuseConfig;
  }

  /** Get tenant gas sponsorship/paymaster configuration. */
  async getTenantGasSponsorshipConfig(tenantId: string): Promise<TenantGasSponsorshipConfig> {
    const response = await this.request<
      { gasSponsorshipConfig: TenantGasSponsorshipConfig },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/gas-sponsorship`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.gasSponsorshipConfig;
  }

  /** Replace tenant gas sponsorship/paymaster configuration. Requires tenant-admin MFA server-side. */
  async updateTenantGasSponsorshipConfig(
    tenantId: string,
    gasSponsorshipConfig: TenantGasSponsorshipConfig,
  ): Promise<TenantGasSponsorshipConfig> {
    const response = await this.request<
      { gasSponsorshipConfig: TenantGasSponsorshipConfig },
      StewardErrorResponse
    >(`/tenants/${encodeURIComponent(tenantId)}/gas-sponsorship`, {
      method: "PATCH",
      body: JSON.stringify({ gasSponsorshipConfig }),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.gasSponsorshipConfig;
  }

  // ─── Agent Dashboard ──────────────────────────────────────────

  /** Get the aggregated dashboard for an agent (balance, spend, policies, recent tx, pending approvals). */
  async getAgentDashboard(agentId: string): Promise<AgentDashboardResponse> {
    const response = await this.request<AgentDashboardResponse, StewardErrorResponse>(
      `/dashboard/${encodeURIComponent(agentId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get on-chain and realtime spend accounting for an agent. */
  async getAgentSpend(agentId: string): Promise<AgentSpendSummary> {
    const response = await this.request<AgentSpendSummary, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/spend`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get the aggregated digital asset account for an agent. */
  async getAgentAccount(
    agentId: string,
    opts: { chainId?: number; tokens?: string[] } = {},
  ): Promise<AgentAccountSummary> {
    const params = new URLSearchParams();
    if (opts.chainId) params.set("chainId", String(opts.chainId));
    if (opts.tokens?.length) params.set("tokens", opts.tokens.join(","));
    const qs = params.toString();
    const response = await this.request<AgentAccountSummary, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/account${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async listAgentSigners(
    agentId: string,
    opts?: { status?: AgentSignerStatus },
  ): Promise<AgentSigner[]> {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    const qs = params.toString();
    const response = await this.request<{ signers: AgentSigner[] }, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/signers${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.signers;
  }

  async createAgentSigner(
    agentId: string,
    input: AgentSignerCreate,
  ): Promise<AgentSignerCreateResult> {
    const response = await this.request<AgentSignerCreateResult, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/signers`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async updateAgentSigner(
    agentId: string,
    signerId: string,
    input: AgentSignerUpdate,
  ): Promise<AgentSigner> {
    const response = await this.request<AgentSigner, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/signers/${encodeURIComponent(signerId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async revokeAgentSigner(agentId: string, signerId: string): Promise<AgentSigner> {
    const response = await this.request<AgentSigner, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/signers/${encodeURIComponent(signerId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async listAgentKeyQuorums(
    agentId: string,
    opts?: { status?: AgentKeyQuorumStatus },
  ): Promise<AgentKeyQuorum[]> {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    const qs = params.toString();
    const response = await this.request<{ quorums: AgentKeyQuorum[] }, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/key-quorums${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data.quorums;
  }

  async createAgentKeyQuorum(
    agentId: string,
    input: AgentKeyQuorumCreate,
  ): Promise<AgentKeyQuorum> {
    const response = await this.request<AgentKeyQuorum, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/key-quorums`,
      {
        method: "POST",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async updateAgentKeyQuorum(
    agentId: string,
    quorumId: string,
    input: AgentKeyQuorumUpdate,
  ): Promise<AgentKeyQuorum> {
    const response = await this.request<AgentKeyQuorum, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/key-quorums/${encodeURIComponent(quorumId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(input),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async revokeAgentKeyQuorum(agentId: string, quorumId: string): Promise<AgentKeyQuorum> {
    const response = await this.request<AgentKeyQuorum, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/key-quorums/${encodeURIComponent(quorumId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Approvals ────────────────────────────────────────────────

  /** List approval queue entries for the tenant. */
  async listApprovals(opts?: {
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApprovalQueueEntry[]> {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    const response = await this.request<ApprovalQueueEntry[], StewardErrorResponse>(
      `/approvals${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Approve a pending transaction. */
  async approveTransaction(
    txId: string,
    opts?: { comment?: string; approvedBy?: string },
  ): Promise<ApprovalQueueEntry> {
    const response = await this.request<ApprovalQueueEntry, StewardErrorResponse>(
      `/approvals/${encodeURIComponent(txId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify(opts ?? {}),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Deny a pending transaction. */
  async denyTransaction(
    txId: string,
    reason: string,
    deniedBy?: string,
  ): Promise<ApprovalQueueEntry> {
    const response = await this.request<ApprovalQueueEntry, StewardErrorResponse>(
      `/approvals/${encodeURIComponent(txId)}/deny`,
      {
        method: "POST",
        body: JSON.stringify({ reason, deniedBy }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get approval statistics for the tenant. */
  async getApprovalStats(): Promise<ApprovalStats> {
    const response = await this.request<ApprovalStats, StewardErrorResponse>("/approvals/stats");
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Intents ─────────────────────────────────────────────────

  async listIntents(opts?: IntentListOptions): Promise<{
    intents: Intent[];
    limit: number;
    offset: number;
  }> {
    const params = new URLSearchParams();
    if (opts?.status) params.set("status", opts.status);
    if (opts?.intentType) params.set("intentType", opts.intentType);
    if (opts?.agentId) params.set("agentId", opts.agentId);
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    const response = await this.request<
      { intents: Intent[]; limit: number; offset: number },
      StewardErrorResponse
    >(`/intents${qs ? `?${qs}` : ""}`);
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async createIntent(input: IntentCreate): Promise<Intent> {
    const response = await this.request<Intent, StewardErrorResponse>("/intents", {
      method: "POST",
      body: JSON.stringify(input),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async getIntent(intentId: string): Promise<Intent> {
    const response = await this.request<Intent, StewardErrorResponse>(
      `/intents/${encodeURIComponent(intentId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async authorizeIntent(intentId: string, input?: { reason?: string }): Promise<Intent> {
    return this.updateIntentLifecycle(intentId, "authorize", input);
  }

  async rejectIntent(intentId: string, input?: { reason?: string }): Promise<Intent> {
    return this.updateIntentLifecycle(intentId, "reject", input);
  }

  async cancelIntent(intentId: string, input?: { reason?: string }): Promise<Intent> {
    return this.updateIntentLifecycle(intentId, "cancel", input);
  }

  async executeIntent(
    intentId: string,
    input?: { executionResult?: Record<string, unknown> },
  ): Promise<Intent> {
    return this.updateIntentLifecycle(intentId, "execute", input);
  }

  async failIntent(
    intentId: string,
    input?: { reason?: string; executionResult?: Record<string, unknown> },
  ): Promise<Intent> {
    return this.updateIntentLifecycle(intentId, "fail", input);
  }

  private async updateIntentLifecycle(
    intentId: string,
    action: "authorize" | "reject" | "execute" | "fail" | "cancel",
    input?: Record<string, unknown>,
  ): Promise<Intent> {
    const response = await this.request<Intent, StewardErrorResponse>(
      `/intents/${encodeURIComponent(intentId)}/${action}`,
      {
        method: "POST",
        body: JSON.stringify(input ?? {}),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Auto-Approval Rules ─────────────────────────────────────

  /** Get auto-approval rules for the tenant. */
  async getAutoApprovalRules(): Promise<AutoApprovalRule | null> {
    const response = await this.request<AutoApprovalRule | null, StewardErrorResponse>(
      "/approvals/rules",
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create or update auto-approval rules. */
  async updateAutoApprovalRules(rules: Partial<AutoApprovalRule>): Promise<AutoApprovalRule> {
    const response = await this.request<AutoApprovalRule, StewardErrorResponse>(
      "/approvals/rules",
      {
        method: "PUT",
        body: JSON.stringify(rules),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Webhooks ─────────────────────────────────────────────────

  /** List webhook configurations for the tenant. */
  async listWebhooks(): Promise<WebhookConfig[]> {
    const response = await this.request<WebhookConfig[], StewardErrorResponse>("/webhooks");
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Register a new webhook. */
  async createWebhook(webhook: {
    url: string;
    events?: string[];
    description?: string;
    maxRetries?: number;
    retryBackoffMs?: number;
  }): Promise<WebhookConfig> {
    const response = await this.request<WebhookConfig, StewardErrorResponse>("/webhooks", {
      method: "POST",
      body: JSON.stringify(webhook),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Update an existing webhook. */
  async updateWebhook(
    webhookId: string,
    updates: Partial<{
      url: string;
      events: string[];
      enabled: boolean;
      description: string;
      maxRetries: number;
      retryBackoffMs: number;
    }>,
  ): Promise<WebhookConfig> {
    const response = await this.request<WebhookConfig, StewardErrorResponse>(
      `/webhooks/${encodeURIComponent(webhookId)}`,
      { method: "PUT", body: JSON.stringify(updates) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Delete a webhook. */
  async deleteWebhook(webhookId: string): Promise<void> {
    const response = await this.request<{ deleted: boolean }, StewardErrorResponse>(
      `/webhooks/${encodeURIComponent(webhookId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  /** Get delivery history for a webhook. */
  async getWebhookDeliveries(
    webhookId: string,
    opts?: { limit?: number; offset?: number },
  ): Promise<WebhookDelivery[]> {
    const params = new URLSearchParams();
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    const response = await this.request<WebhookDelivery[], StewardErrorResponse>(
      `/webhooks/${encodeURIComponent(webhookId)}/deliveries${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Retry a failed webhook delivery. */
  async retryDelivery(deliveryId: string): Promise<WebhookDelivery> {
    const response = await this.request<WebhookDelivery, StewardErrorResponse>(
      `/webhooks/deliveries/${encodeURIComponent(deliveryId)}/retry`,
      { method: "POST" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Secrets ────────────────────────────────

  /** List all secrets for the tenant. Values are never returned. */
  async listSecrets(): Promise<SecretRecord[]> {
    const response = await this.request<SecretRecord[], StewardErrorResponse>("/secrets");
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a new secret. */
  async createSecret(payload: CreateSecretPayload): Promise<SecretRecord> {
    const response = await this.request<SecretRecord, StewardErrorResponse>("/secrets", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get a single secret by id (value is not returned). */
  async getSecret(secretId: string): Promise<SecretRecord> {
    const response = await this.request<SecretRecord, StewardErrorResponse>(
      `/secrets/${encodeURIComponent(secretId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Rotate a secret's value. Bumps the secret's version. */
  async rotateSecret(secretId: string, value: string): Promise<SecretRecord> {
    const response = await this.request<SecretRecord, StewardErrorResponse>(
      `/secrets/${encodeURIComponent(secretId)}/rotate`,
      {
        method: "POST",
        body: JSON.stringify({ value }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Delete a secret and all of its routes. */
  async deleteSecret(secretId: string): Promise<void> {
    const response = await this.request<{ deleted: boolean } | undefined, StewardErrorResponse>(
      `/secrets/${encodeURIComponent(secretId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  // ─── Secret Routes ─────────────────────────────

  /** List credential injection routes, optionally filtered by secretId. */
  async listRoutes(secretId?: string): Promise<RouteRecord[]> {
    const qs = secretId ? `?secretId=${encodeURIComponent(secretId)}` : "";
    const response = await this.request<RouteRecord[], StewardErrorResponse>(
      `/secrets/routes${qs}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a credential injection route for a secret. */
  async createRoute(payload: CreateRoutePayload): Promise<RouteRecord> {
    const response = await this.request<RouteRecord, StewardErrorResponse>("/secrets/routes", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Update an existing route. */
  async updateRoute(routeId: string, payload: UpdateRoutePayload): Promise<RouteRecord> {
    const response = await this.request<RouteRecord, StewardErrorResponse>(
      `/secrets/routes/${encodeURIComponent(routeId)}`,
      { method: "PUT", body: JSON.stringify(payload) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Delete a route. */
  async deleteRoute(routeId: string): Promise<void> {
    const response = await this.request<{ deleted: boolean } | undefined, StewardErrorResponse>(
      `/secrets/routes/${encodeURIComponent(routeId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  // ─── Policy Templates ────────────────────────────

  /** List policy templates for the tenant. */
  async listPolicyTemplates(): Promise<PolicyTemplate[]> {
    const response = await this.request<PolicyTemplate[], StewardErrorResponse>("/policies");
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Get a single policy template by id. */
  async getPolicyTemplate(templateId: string): Promise<PolicyTemplate> {
    const response = await this.request<PolicyTemplate, StewardErrorResponse>(
      `/policies/${encodeURIComponent(templateId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Create a new policy template. */
  async createPolicyTemplate(payload: PolicyTemplateCreate): Promise<PolicyTemplate> {
    const response = await this.request<PolicyTemplate, StewardErrorResponse>("/policies", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Update an existing policy template. */
  async updatePolicyTemplate(
    templateId: string,
    payload: PolicyTemplateUpdate,
  ): Promise<PolicyTemplate> {
    const response = await this.request<PolicyTemplate, StewardErrorResponse>(
      `/policies/${encodeURIComponent(templateId)}`,
      { method: "PUT", body: JSON.stringify(payload) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Delete a policy template. */
  async deletePolicyTemplate(templateId: string): Promise<void> {
    const response = await this.request<{ deleted: boolean } | undefined, StewardErrorResponse>(
      `/policies/${encodeURIComponent(templateId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  /** Assign a policy template to one or more agents (overwrites their existing rules). */
  async assignPolicyTemplate(
    templateId: string,
    agentIds: string[],
  ): Promise<{
    templateId: string;
    assignedAgents: string[];
    rulesApplied: number;
  }> {
    const response = await this.request<
      { templateId: string; assignedAgents: string[]; rulesApplied: number },
      StewardErrorResponse
    >(`/policies/${encodeURIComponent(templateId)}/assign`, {
      method: "POST",
      body: JSON.stringify({ agentIds }),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Simulate policy evaluation against a mock transaction. */
  async simulatePolicy(input: PolicySimulateInput): Promise<PolicySimulateResult> {
    const response = await this.request<PolicySimulateResult, StewardErrorResponse>(
      "/policies/simulate",
      { method: "POST", body: JSON.stringify(input) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  // ─── Condition Sets ────────────────────────────

  async listConditionSets(): Promise<ConditionSet[]> {
    const response = await this.request<ConditionSet[], StewardErrorResponse>("/condition-sets");
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async createConditionSet(payload: ConditionSetCreate): Promise<ConditionSet> {
    const response = await this.request<ConditionSet, StewardErrorResponse>("/condition-sets", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async getConditionSet(conditionSetId: string): Promise<ConditionSet> {
    const response = await this.request<ConditionSet, StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async updateConditionSet(
    conditionSetId: string,
    payload: ConditionSetUpdate,
  ): Promise<ConditionSet> {
    const response = await this.request<ConditionSet, StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}`,
      { method: "PATCH", body: JSON.stringify(payload) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async deleteConditionSet(conditionSetId: string): Promise<void> {
    const response = await this.request<Record<string, never> | undefined, StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}`,
      {
        method: "DELETE",
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  async listConditionSetItems(conditionSetId: string): Promise<ConditionSetItem[]> {
    const response = await this.request<ConditionSetItem[], StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}/items`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async upsertConditionSetItem(
    conditionSetId: string,
    payload: ConditionSetItemInput,
  ): Promise<ConditionSetItem> {
    const response = await this.request<ConditionSetItem, StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}/items`,
      { method: "POST", body: JSON.stringify(payload) },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async replaceConditionSetItems(
    conditionSetId: string,
    items: ConditionSetItemInput[],
  ): Promise<ConditionSetItem[]> {
    const response = await this.request<ConditionSetItem[], StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}/items`,
      {
        method: "PUT",
        body: JSON.stringify({ items }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  async deleteConditionSetItem(conditionSetId: string, itemId: string): Promise<void> {
    const response = await this.request<Record<string, never> | undefined, StewardErrorResponse>(
      `/condition-sets/${encodeURIComponent(conditionSetId)}/items/${encodeURIComponent(itemId)}`,
      { method: "DELETE" },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
  }

  // ─── Audit ──────────────────────────────────

  /**
   * Fetch a page of audit log entries for the tenant. Supports filter by
   * agent, action (`sign` | `approve` | `reject` | `proxy`), status, and
   * date range. Pagination is page/limit-based.
   */
  async getAuditLog(params?: {
    agentId?: string;
    action?: string;
    status?: string;
    dateFrom?: string;
    dateTo?: string;
    page?: number;
    limit?: number;
  }): Promise<AuditLogResponse> {
    const search = new URLSearchParams();
    if (params?.agentId) search.set("agentId", params.agentId);
    if (params?.action) search.set("action", params.action);
    if (params?.status) search.set("status", params.status);
    if (params?.dateFrom) search.set("dateFrom", params.dateFrom);
    if (params?.dateTo) search.set("dateTo", params.dateTo);
    if (params?.page) search.set("page", String(params.page));
    if (params?.limit) search.set("limit", String(params.limit));
    const qs = search.toString();
    const response = await this.request<AuditLogResponse, StewardErrorResponse>(
      `/audit/log${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Aggregate audit counters + top agents + daily activity. */
  async getAuditSummary(range?: "24h" | "7d" | "30d" | "all"): Promise<AuditSummaryResponse> {
    const qs = range ? `?range=${range}` : "";
    const response = await this.request<AuditSummaryResponse, StewardErrorResponse>(
      `/audit/summary${qs}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /**
   * Download the audit log as CSV. Returns the raw CSV body as a string.
   * Does not use the `/api/v1` JSON envelope - streams text directly.
   */
  async exportAuditCsv(params?: {
    agentId?: string;
    action?: string;
    status?: string;
    dateFrom?: string;
    dateTo?: string;
  }): Promise<string> {
    const search = new URLSearchParams();
    if (params?.agentId) search.set("agentId", params.agentId);
    if (params?.action) search.set("action", params.action);
    if (params?.status) search.set("status", params.status);
    if (params?.dateFrom) search.set("dateFrom", params.dateFrom);
    if (params?.dateTo) search.set("dateTo", params.dateTo);
    const qs = search.toString();
    const url = `${this.baseUrl}/audit/export${qs ? `?${qs}` : ""}`;
    let response: Response;
    try {
      response = await fetch(url, { headers: this.buildHeaders() });
    } catch (error) {
      throw new StewardApiError(
        error instanceof Error ? error.message : "Network request failed",
        0,
      );
    }
    if (!response.ok) {
      throw new StewardApiError(`Audit export failed: ${response.status}`, response.status);
    }
    return response.text();
  }

  // ─── User Tenants ─────────────────────────────

  /** List the tenants the authenticated user is a member of. Requires user JWT. */
  async listUserTenants(): Promise<TenantMembership[]> {
    const response = await this.request<TenantMembership[], StewardErrorResponse>(
      "/user/me/tenants",
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return response.data;
  }

  /** Search users in a tenant directory. Requires user JWT, tenant admin role, and recent MFA. */
  async listTenantUsers(
    tenantId: string,
    opts?: { q?: string; email?: string; limit?: number; offset?: number },
  ): Promise<TenantAdminUserSearchResult> {
    const params = new URLSearchParams();
    if (opts?.q) params.set("q", opts.q);
    if (opts?.email) params.set("email", opts.email);
    if (opts?.limit) params.set("limit", String(opts.limit));
    if (opts?.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    const response = await this.request<TenantAdminUserSearchResult, StewardErrorResponse>(
      `/user/me/tenants/${encodeURIComponent(tenantId)}/users${qs ? `?${qs}` : ""}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return {
      ...response.data,
      users: response.data.users.map(parseTenantAdminUser),
    };
  }

  /** Read a tenant-scoped user record. Requires user JWT, tenant admin role, and recent MFA. */
  async getTenantUser(tenantId: string, userId: string): Promise<TenantAdminUser> {
    const response = await this.request<TenantAdminUser, StewardErrorResponse>(
      `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}`,
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return parseTenantAdminUser(response.data);
  }

  /** Update a tenant user's team role. Requires user JWT, tenant admin role, and recent MFA. */
  async updateTenantUserRole(
    tenantId: string,
    userId: string,
    role: TenantTeamRole,
  ): Promise<TenantAdminUser> {
    const response = await this.request<TenantAdminUser, StewardErrorResponse>(
      `/user/me/tenants/${encodeURIComponent(tenantId)}/users/${encodeURIComponent(userId)}/role`,
      {
        method: "PATCH",
        body: JSON.stringify({ role }),
      },
    );
    if (!response.ok) throw new StewardApiError(response.error, response.status, response.data);
    return parseTenantAdminUser(response.data);
  }

  /**
   * Create multiple agent wallets in a single request.
   * Optionally supply a shared policy set to apply to every created agent.
   */
  async createWalletBatch(
    agents: BatchAgentSpec[],
    policies?: PolicyRule[],
  ): Promise<BatchCreateResult> {
    const response = await this.request<BatchCreateResult, StewardErrorResponse>("/agents/batch", {
      method: "POST",
      body: JSON.stringify({ agents, applyPolicies: policies }),
    });

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    const result = response.data;
    return {
      ...result,
      created: result.created.map(parseAgentIdentity),
    };
  }

  private async request<TSuccess, TFailure = unknown>(
    path: string,
    init: RequestInit = {},
  ): Promise<ApiRequestResult<TSuccess, TFailure>> {
    let response: Response;

    try {
      const headers = await this.buildRequestHeaders(path, init);
      response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers,
      });
    } catch (error) {
      throw new StewardApiError(
        error instanceof Error ? error.message : "Network request failed",
        0,
      );
    }

    const payload = await this.parseJson<ApiResponse<TSuccess | TFailure>>(response);

    if (!payload.ok) {
      return {
        ok: false,
        status: response.status,
        error: payload.error ?? `Request failed with status ${response.status}`,
        data: payload.data as TFailure | undefined,
      };
    }

    if (typeof payload.data === "undefined") {
      return { ok: true, status: response.status, data: undefined as TSuccess };
    }

    return {
      ok: true,
      status: response.status,
      data: payload.data as TSuccess,
    };
  }

  private buildHeaders(headers?: HeadersInit): Headers {
    const merged = new Headers(headers);

    if (!merged.has("Content-Type")) {
      merged.set("Content-Type", "application/json");
    }
    if (!merged.has("Accept")) {
      merged.set("Accept", "application/json");
    }
    if (this.platformKey) {
      merged.set("X-Steward-Platform-Key", this.platformKey);
    } else if (this.bearerToken) {
      merged.set("Authorization", `Bearer ${this.bearerToken}`);
    } else if (this.appId && this.appSecret) {
      merged.set("Authorization", `Basic ${btoa(`${this.appId}:${this.appSecret}`)}`);
      merged.set("X-Steward-App-Id", this.appId);
    } else if (this.apiKey) {
      merged.set("X-Steward-Key", this.apiKey);
    }
    if (this.tenantId) {
      merged.set("X-Steward-Tenant", this.tenantId);
    }

    return merged;
  }

  private async buildRequestHeaders(path: string, init: RequestInit): Promise<Headers> {
    const headers = this.buildHeaders(init.headers);
    const method = (init.method ?? "GET").toUpperCase();
    if (!this.requestSigningSecret || !isSensitiveMutatingRequest(path, method)) return headers;

    if (!headers.has("X-Steward-Request-Timestamp")) {
      headers.set("X-Steward-Request-Timestamp", String(Math.floor(Date.now() / 1000)));
    }
    if (!headers.has("Idempotency-Key")) {
      headers.set("Idempotency-Key", randomIdempotencyKey());
    }

    const body = typeof init.body === "string" ? init.body : "";
    const bodyHash = await sha256Hex(body);
    const authHash = await sha256Hex(headers.get("Authorization") ?? "");
    const apiKeyHash = await sha256Hex(headers.get("X-Steward-Key") ?? "");
    const platformKeyHash = await sha256Hex(headers.get("X-Steward-Platform-Key") ?? "");
    const signerIdHash = await sha256Hex(headers.get("X-Steward-Signer-Id") ?? "");
    const signerSecretHash = await sha256Hex(headers.get("X-Steward-Signer-Secret") ?? "");
    const quorumIdHash = await sha256Hex(headers.get("X-Steward-Key-Quorum-Id") ?? "");
    const quorumCredentialsHash = await sha256Hex(
      headers.get("X-Steward-Key-Quorum-Credentials") ?? "",
    );
    const canonical = [
      "steward-request-signature-v1",
      method,
      path,
      headers.get("X-Steward-Tenant") ?? "",
      authHash,
      apiKeyHash,
      platformKeyHash,
      signerIdHash,
      signerSecretHash,
      quorumIdHash,
      quorumCredentialsHash,
      headers.get("X-Steward-Request-Timestamp") ?? "",
      headers.get("X-Steward-Request-Expires-At") ?? "",
      headers.get("Idempotency-Key") ?? "",
      bodyHash,
    ].join("\n");
    headers.set(
      "X-Steward-Signature",
      `v1=${await hmacSha256Hex(this.requestSigningSecret, canonical)}`,
    );
    return headers;
  }

  private async parseJson<T>(response: Response): Promise<T> {
    const text = await response.text();

    if (!text) {
      return { ok: response.ok } as T;
    }

    try {
      return JSON.parse(text) as T;
    } catch {
      throw new StewardApiError("Received invalid JSON from Steward API", response.status);
    }
  }

  private isPendingApproval(
    data: StewardPendingApproval | StewardErrorResponse | undefined,
  ): data is StewardPendingApproval {
    return typeof data !== "undefined" && "status" in data && data.status === "pending_approval";
  }
}

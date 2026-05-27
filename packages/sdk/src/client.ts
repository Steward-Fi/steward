import type {
  AgentBalance,
  AgentDashboardResponse,
  AgentIdentity,
  ApiResponse,
  ApprovalQueueEntry,
  ApprovalStats,
  AuditLogResponse,
  AuditSummaryResponse,
  AutoApprovalRule,
  ChainFamily,
  CreateRoutePayload,
  CreateSecretPayload,
  ExportKeyResult,
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
  TenantControlPlaneConfig,
  TenantMembership,
  TxRecord,
  TypedDataDomain,
  TypedDataField,
  UpdateRoutePayload,
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
  /** Agent-scoped JWT - sent as `Authorization: Bearer <token>`. Preferred over apiKey when both are set. */
  bearerToken?: string;
  tenantId?: string;
}

export interface SignTransactionInput {
  to: string;
  value: string;
  data?: string;
  chainId?: number;
  broadcast?: boolean; // default true; set false to get signed tx without broadcasting
}

export interface SignTypedDataInput {
  domain: TypedDataDomain;
  types: Record<string, TypedDataField[]>;
  primaryType: string;
  value: Record<string, unknown>;
}

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
export type SignTypedDataResult = { signature: string };
export type SignSolanaTransactionResult = {
  signature: string;
  broadcast: boolean;
  chainId?: number;
  caip2?: string;
};
export type RpcPassthroughResult = RpcResponse;
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

export class StewardClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly bearerToken?: string;
  private readonly tenantId?: string;

  constructor({ baseUrl, apiKey, bearerToken, tenantId }: StewardClientConfig) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.bearerToken = bearerToken;
    this.tenantId = tenantId;
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
        { method: "POST" },
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

  async signTransaction(agentId: string, tx: SignTransactionInput): Promise<SignTransactionResult> {
    const response = await this.request<
      { txHash: string },
      StewardPendingApproval | StewardErrorResponse
    >(`/vault/${encodeURIComponent(agentId)}/sign`, {
      method: "POST",
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
    const response = await this.request<TxRecord[], StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/history`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data.map((tx) => ({
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
    }));
  }

  async signMessage(agentId: string, message: string): Promise<SignMessageResult> {
    const response = await this.request<SignMessageResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-message`,
      {
        method: "POST",
        body: JSON.stringify({ message }),
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
  async signTypedData(agentId: string, input: SignTypedDataInput): Promise<SignTypedDataResult> {
    const response = await this.request<SignTypedDataResult, StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign-typed-data`,
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

  // ─── Agent Dashboard ──────────────────────────────────────────

  /** Get the aggregated dashboard for an agent (balance, spend, policies, recent tx, pending approvals). */
  async getAgentDashboard(agentId: string): Promise<AgentDashboardResponse> {
    const response = await this.request<AgentDashboardResponse, StewardErrorResponse>(
      `/dashboard/${encodeURIComponent(agentId)}`,
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
  ): Promise<{ templateId: string; assignedAgents: string[]; rulesApplied: number }> {
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
      response = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers: this.buildHeaders(init.headers),
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
    if (this.bearerToken) {
      merged.set("Authorization", `Bearer ${this.bearerToken}`);
    } else if (this.apiKey) {
      merged.set("X-Steward-Key", this.apiKey);
    }
    if (this.tenantId) {
      merged.set("X-Steward-Tenant", this.tenantId);
    }

    return merged;
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

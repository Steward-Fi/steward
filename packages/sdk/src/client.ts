import type {
  AgentBalance,
  AgentIdentity,
  ApiResponse,
  ChainFamily,
  PolicyResult,
  PolicyRule,
  RpcRequest,
  RpcResponse,
  SignTypedDataRequest,
  TypedDataDomain,
  TypedDataField,
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
  /** Agent-scoped JWT — sent as `Authorization: Bearer <token>`. Preferred over apiKey when both are set. */
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
  chainId?: number;    // 101 = mainnet, 102 = devnet
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
export type SignTransactionResult = { txHash: string; caip2?: string } | { signedTx: string; caip2?: string } | StewardPendingApproval;
export type SignTypedDataResult = { signature: string };
export type SignSolanaTransactionResult = { signature: string; broadcast: boolean; chainId?: number; caip2?: string };
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

  async createWallet(agentId: string, name: string, platformId?: string): Promise<CreateWalletResult> {
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
    const response = await this.request<{ txHash: string }, StewardPendingApproval | StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/sign`,
      {
        method: "POST",
        body: JSON.stringify(tx),
      },
    );

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

  async setPolicies(agentId: string, policies: PolicyRule[]): Promise<void> {
    const response = await this.request<void, StewardErrorResponse>(
      `/agents/${encodeURIComponent(agentId)}/policies`,
      {
        method: "PUT",
        body: JSON.stringify(policies),
      },
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }
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

  async getHistory(agentId: string): Promise<GetHistoryResult> {
    const response = await this.request<StewardHistoryEntry[], StewardErrorResponse>(
      `/vault/${encodeURIComponent(agentId)}/history`,
    );

    if (!response.ok) {
      throw new StewardApiError(response.error, response.status, response.data);
    }

    return response.data;
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
  async signSolanaTransaction(agentId: string, input: SignSolanaTransactionInput): Promise<SignSolanaTransactionResult> {
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
   * Create multiple agent wallets in a single request.
   * Optionally supply a shared policy set to apply to every created agent.
   */
  async createWalletBatch(agents: BatchAgentSpec[], policies?: PolicyRule[]): Promise<BatchCreateResult> {
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

    return { ok: true, status: response.status, data: payload.data as TSuccess };
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

  private isPendingApproval(data: StewardPendingApproval | StewardErrorResponse | undefined): data is StewardPendingApproval {
    return typeof data !== "undefined" && "status" in data && data.status === "pending_approval";
  }
}

import { type IAgentRuntime, Service } from "@elizaos/core";
import { StewardProxyClient } from "@stwd/proxy-client";
import {
  type AgentDashboardResponse,
  type AgentIdentity,
  type ApprovalQueueEntry,
  type ApprovalStats,
  type GetBalanceResult,
  type GetHistoryResult,
  type PendingProxyRequest,
  type PolicyRule,
  type ProviderActionInvokeInput,
  type ProviderActionInvokeResult,
  type ProviderActionStatus,
  type SignMessageResult,
  type SignTransactionInput,
  type SignTransactionResult,
  StewardApiError,
  StewardClient,
} from "@stwd/sdk";
import type { StewardPluginConfig } from "../types.js";

export interface HyperliquidSubmitOrderInput {
  sessionId: string;
  asset: "BTC" | "ETH";
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

export type TrackedProviderAction =
  | { polling: "ok"; action: ProviderActionStatus }
  | {
      polling: "error";
      id: string;
      lastKnown?: ProviderActionStatus;
      error: { message: string; httpStatus?: number; retryable: true };
    };

/**
 * Reject plaintext `http://` API URLs for non-localhost hosts. Talking to a
 * remote Steward API over http would expose API keys / bearer tokens and signed
 * transactions to network observers. The localhost default stays usable for dev.
 */
function assertSecureApiUrl(apiUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(apiUrl);
  } catch {
    throw new Error(`[Steward] Invalid apiUrl: ${apiUrl}`);
  }
  if (parsed.protocol === "http:") {
    const host = parsed.hostname;
    const isLocal =
      host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
    if (!isLocal) {
      throw new Error(
        `[Steward] Insecure apiUrl "${apiUrl}": http:// is only allowed for localhost. Use https:// for remote hosts.`,
      );
    }
  }
}

/**
 * Singleton service wrapping StewardClient for the ElizaOS runtime.
 *
 * Handles initialization, health checks, auto-discovery, and auto-registration.
 * Access via `runtime.getService("STEWARD")`.
 */
export class StewardService extends Service {
  static serviceType = "steward" as const;
  capabilityDescription =
    "Steward managed wallet - policy-enforced signing, balances, and approval flows";

  private client: StewardClient | null = null;
  private pluginConfig: StewardPluginConfig | null = null;
  private agentIdentity: AgentIdentity | null = null;
  private _connected = false;
  private readonly trackedProviderActionIds = new Set<string>();
  private readonly providerActionLastKnown = new Map<string, ProviderActionStatus>();

  static async start(runtime: IAgentRuntime): Promise<StewardService> {
    const service = new StewardService(runtime);
    await service.initialize(runtime);
    return service;
  }

  async stop(): Promise<void> {
    this.client = null;
    this._connected = false;
    this.agentIdentity = null;
    this.trackedProviderActionIds.clear();
    this.providerActionLastKnown.clear();
  }

  // ── Initialization ──────────────────────────────────────────────

  private async initialize(runtime: IAgentRuntime): Promise<void> {
    this.pluginConfig = this.resolveConfig(runtime);

    if (!this.pluginConfig) {
      console.warn("[Steward] No configuration found, plugin disabled");
      return;
    }

    this.client = new StewardClient({
      baseUrl: this.pluginConfig.apiUrl,
      apiKey: this.pluginConfig.apiKey,
      bearerToken: this.pluginConfig.bearerToken,
      tenantId: this.pluginConfig.tenantId,
    });

    // Probe health + fetch agent identity
    try {
      this.agentIdentity = await this.client.getAgent(this.pluginConfig.agentId);
      this._connected = true;
      console.info(`[Steward] Connected. Wallet: ${this.agentIdentity.walletAddress}`);
    } catch (err) {
      if (err instanceof StewardApiError && err.status === 404 && this.pluginConfig.autoRegister) {
        await this.tryAutoRegister(runtime);
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[Steward] Could not connect: ${msg}`);
        if (this.pluginConfig.fallbackLocal) {
          console.info("[Steward] Falling back to local signing");
        }
      }
    }
  }

  private async tryAutoRegister(runtime: IAgentRuntime): Promise<void> {
    try {
      const name = this.getRuntimeState(runtime).character?.name ?? this.getAgentId();
      this.agentIdentity = await this.getClient().createWallet(this.getAgentId(), name);
      this._connected = true;
      console.info(`[Steward] Registered new wallet: ${this.agentIdentity.walletAddress}`);
    } catch (regErr) {
      const msg = regErr instanceof Error ? regErr.message : String(regErr);
      console.error(`[Steward] Failed to auto-register agent: ${msg}`);
    }
  }

  // ── Config Resolution ───────────────────────────────────────────

  private resolveConfig(runtime: IAgentRuntime): StewardPluginConfig | null {
    const runtimeState = this.getRuntimeState(runtime);
    const settings = runtimeState.character?.settings?.steward ?? {};
    const env = process.env;

    const apiUrl = settings.apiUrl ?? env.STEWARD_API_URL ?? "http://localhost:7860";
    assertSecureApiUrl(apiUrl);

    return {
      apiUrl,
      proxyUrl: settings.proxyUrl ?? env.STEWARD_PROXY_URL ?? apiUrl,
      proxyRequestSigningSecret:
        settings.proxyRequestSigningSecret ??
        env.STEWARD_PROXY_REQUEST_SIGNING_SECRET ??
        env.STEWARD_PROXY_REQUEST_SIGNING_SECRETS?.split(",")[0]?.trim(),
      apiKey: settings.apiKey ?? env.STEWARD_API_KEY,
      bearerToken: settings.bearerToken ?? env.STEWARD_JWT,
      agentId: settings.agentId ?? env.STEWARD_AGENT_ID ?? runtimeState.agentId ?? "default",
      tenantId: settings.tenantId ?? env.STEWARD_TENANT_ID,
      autoRegister: settings.autoRegister ?? env.STEWARD_AUTO_REGISTER !== "false",
      // `fallbackLocal` only gates a single informational log line (see connect()):
      // it does not itself create or expose a local signing key, so the
      // historical default of `true` is inert and left as-is.
      fallbackLocal: settings.fallbackLocal ?? env.STEWARD_FALLBACK_LOCAL !== "false",
    };
  }

  // ── Public API ──────────────────────────────────────────────────

  isConnected(): boolean {
    return this._connected && this.client !== null;
  }

  getConfig(): StewardPluginConfig | null {
    return this.pluginConfig;
  }

  async signTransaction(tx: SignTransactionInput): Promise<SignTransactionResult> {
    this.assertConnected();
    return this.getClient().signTransaction(this.getAgentId(), tx);
  }

  async signMessage(message: string): Promise<SignMessageResult> {
    this.assertConnected();
    return this.getClient().signMessage(this.getAgentId(), message);
  }

  async getBalance(chainId?: number): Promise<GetBalanceResult> {
    this.assertConnected();
    return this.getClient().getBalance(this.getAgentId(), chainId);
  }

  async getAgent(): Promise<AgentIdentity> {
    this.assertConnected();
    if (!this.agentIdentity) {
      throw new Error("Steward agent identity not loaded");
    }
    return this.agentIdentity;
  }

  async getPolicies(): Promise<PolicyRule[]> {
    this.assertConnected();
    return this.getClient().getPolicies(this.getAgentId());
  }

  async getHistory(): Promise<GetHistoryResult> {
    this.assertConnected();
    return this.getClient().getHistory(this.getAgentId());
  }

  async getDashboard(): Promise<AgentDashboardResponse> {
    this.assertConnected();
    return this.getClient().getAgentDashboard(this.getAgentId());
  }

  async submitHyperliquidOrder(
    input: HyperliquidSubmitOrderInput,
  ): Promise<HyperliquidOrderResult> {
    this.assertConnected();
    return this.getClient().trade.hyperliquid.submitOrder(input);
  }

  async listApprovals(opts?: {
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<ApprovalQueueEntry[]> {
    this.assertConnected();
    return this.getClient().listApprovals(opts);
  }

  async getApprovalStats(): Promise<ApprovalStats> {
    this.assertConnected();
    return this.getClient().getApprovalStats();
  }

  async invokeProviderAction(
    input: ProviderActionInvokeInput,
  ): Promise<ProviderActionInvokeResult> {
    this.assertConnected();
    const result = await this.getClient().providerActions.invoke(input);
    this.trackedProviderActionIds.add(result.id);
    return result;
  }

  async getProviderAction(actionId: string): Promise<ProviderActionStatus> {
    this.assertConnected();
    const status = await this.getClient().providerActions.get(actionId);
    this.trackedProviderActionIds.add(actionId);
    this.providerActionLastKnown.set(actionId, status);
    return status;
  }

  /**
   * Poll only action status available to this agent JWT. Human approval detail,
   * case manifests, and evidence remain on their existing human/MFA routes.
   */
  async listTrackedProviderActions(): Promise<TrackedProviderAction[]> {
    this.assertConnected();
    const results = await Promise.allSettled(
      [...this.trackedProviderActionIds].map((id) => this.getClient().providerActions.get(id)),
    );
    return results.map((result, index) => {
      const id = [...this.trackedProviderActionIds][index]!;
      if (result.status === "fulfilled") {
        this.providerActionLastKnown.set(id, result.value);
        return { polling: "ok" as const, action: result.value };
      }
      const cause = result.reason;
      return {
        polling: "error" as const,
        id,
        lastKnown: this.providerActionLastKnown.get(id),
        error: {
          message: cause instanceof Error ? cause.message : String(cause),
          httpStatus: cause instanceof StewardApiError ? cause.status : undefined,
          retryable: true as const,
        },
      };
    });
  }

  async listPendingProxyRequests(): Promise<PendingProxyRequest[]> {
    return this.proxyApprovalRequest<PendingProxyRequest[]>("/approvals/proxy");
  }

  async getPendingProxyRequest(id: string): Promise<PendingProxyRequest> {
    return this.proxyApprovalRequest<PendingProxyRequest>(
      `/approvals/proxy/${encodeURIComponent(id)}`,
    );
  }

  private async proxyApprovalRequest<T>(path: string): Promise<T> {
    this.assertConnected();
    const response = await this.getProxyClient().fetch(path);
    const payload = (await response.json()) as { ok?: boolean; data?: T; error?: string };
    if (!response.ok || !payload.ok || payload.data === undefined)
      throw new Error(payload.error ?? `Proxy approval request failed (${response.status})`);
    return payload.data;
  }

  async callGovernedApi(input: {
    url: string;
    method?: string;
    body?: unknown;
    headers?: Record<string, string>;
  }): Promise<{ held: boolean; status: number; data: unknown }> {
    this.assertConnected();
    const target = new URL(input.url);
    if (target.protocol !== "https:") throw new Error("Governed API target must use https://");
    const headers = new Headers(input.headers);
    let body: string | undefined;
    if (input.body !== undefined) {
      body = typeof input.body === "string" ? input.body : JSON.stringify(input.body);
      if (!headers.has("content-type")) headers.set("content-type", "application/json");
    }
    const response = await this.getProxyClient().fetch(
      `/proxy/${target.host}${target.pathname}${target.search}`,
      {
        method: (input.method ?? "GET").toUpperCase(),
        headers,
        body,
      },
    );
    const data = await response.json().catch(() => null);
    return {
      held:
        response.status === 202 &&
        (data as { status?: string } | null)?.status === "pending_approval",
      status: response.status,
      data,
    };
  }

  // ── Internal ────────────────────────────────────────────────────

  private getRuntimeState(runtime: IAgentRuntime): IAgentRuntime & {
    agentId?: string;
    character?: {
      name?: string;
      settings?: {
        steward?: Partial<StewardPluginConfig>;
      };
    };
  } {
    return runtime as IAgentRuntime & {
      agentId?: string;
      character?: {
        name?: string;
        settings?: {
          steward?: Partial<StewardPluginConfig>;
        };
      };
    };
  }

  private getClient(): StewardClient {
    if (!this.client) {
      throw new Error("Steward service not connected");
    }
    return this.client;
  }

  private getProxyClient(): StewardProxyClient {
    const config = this.pluginConfig;
    if (!config?.proxyUrl || !config.bearerToken) {
      throw new Error("STEWARD_PROXY_URL and STEWARD_JWT are required for proxy requests");
    }
    assertSecureApiUrl(config.proxyUrl);

    const signingRequired =
      process.env.NODE_ENV === "production" ||
      process.env.STEWARD_PROXY_REQUIRE_REQUEST_SIGNATURE === "true";
    if (signingRequired && !config.proxyRequestSigningSecret) {
      throw new Error(
        "STEWARD_PROXY_REQUEST_SIGNING_SECRET is required when proxy request signing is enforced",
      );
    }
    if (config.proxyRequestSigningSecret && !config.tenantId) {
      throw new Error("STEWARD_TENANT_ID is required to sign proxy requests");
    }

    return new StewardProxyClient({
      proxyUrl: config.proxyUrl,
      token: config.bearerToken,
      signingSecret: config.proxyRequestSigningSecret,
      tenantId: config.tenantId,
      agentId: config.agentId,
      fetch: globalThis.fetch,
    });
  }

  private getAgentId(): string {
    const agentId = this.pluginConfig?.agentId;
    if (!agentId) {
      throw new Error("Steward agent id is not configured");
    }
    return agentId;
  }

  private assertConnected(): void {
    if (!this._connected || !this.client) {
      throw new Error("Steward service not connected");
    }
  }
}

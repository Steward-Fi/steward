import { Service, type IAgentRuntime } from "@elizaos/core";
import {
  StewardClient,
  StewardApiError,
  type SignTransactionInput,
  type SignTransactionResult,
  type AgentIdentity,
  type PolicyRule,
  type GetBalanceResult,
  type GetHistoryResult,
  type SignMessageResult,
  type AgentDashboardResponse,
  type ApprovalQueueEntry,
  type ApprovalStats,
} from "@stwd/sdk";
import type { StewardPluginConfig } from "../types.js";

/**
 * Singleton service wrapping StewardClient for the ElizaOS runtime.
 *
 * Handles initialization, health checks, auto-discovery, and auto-registration.
 * Access via `runtime.getService("STEWARD")`.
 */
export class StewardService extends Service {
  static serviceType = "steward" as const;
  capabilityDescription = "Steward managed wallet — policy-enforced signing, balances, and approval flows";

  private client: StewardClient | null = null;
  private pluginConfig: StewardPluginConfig | null = null;
  private agentIdentity: AgentIdentity | null = null;
  private _connected = false;

  static async start(runtime: IAgentRuntime): Promise<StewardService> {
    const service = new StewardService(runtime);
    await service.initialize(runtime);
    return service;
  }

  async stop(): Promise<void> {
    this.client = null;
    this._connected = false;
    this.agentIdentity = null;
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
      tenantId: this.pluginConfig.tenantId,
    });

    // Probe health + fetch agent identity
    try {
      this.agentIdentity = await this.client.getAgent(this.pluginConfig.agentId);
      this._connected = true;
      console.info(`[Steward] Connected. Wallet: ${this.agentIdentity.walletAddress}`);
    } catch (err) {
      if (
        err instanceof StewardApiError &&
        err.status === 404 &&
        this.pluginConfig.autoRegister
      ) {
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
      const name = (runtime as any).character?.name ?? this.pluginConfig!.agentId;
      this.agentIdentity = await this.client!.createWallet(this.pluginConfig!.agentId, name);
      this._connected = true;
      console.info(`[Steward] Registered new wallet: ${this.agentIdentity.walletAddress}`);
    } catch (regErr) {
      const msg = regErr instanceof Error ? regErr.message : String(regErr);
      console.error(`[Steward] Failed to auto-register agent: ${msg}`);
    }
  }

  // ── Config Resolution ───────────────────────────────────────────

  private resolveConfig(runtime: IAgentRuntime): StewardPluginConfig | null {
    const settings = (runtime as any).character?.settings?.steward ?? {};
    const env = process.env;

    const apiUrl =
      settings.apiUrl ??
      env.STEWARD_API_URL ??
      "http://localhost:7860";

    return {
      apiUrl,
      apiKey: settings.apiKey ?? env.STEWARD_API_KEY,
      agentId: settings.agentId ?? env.STEWARD_AGENT_ID ?? (runtime as any).agentId ?? "default",
      tenantId: settings.tenantId ?? env.STEWARD_TENANT_ID,
      autoRegister: settings.autoRegister ?? env.STEWARD_AUTO_REGISTER !== "false",
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
    return this.client!.signTransaction(this.pluginConfig!.agentId, tx);
  }

  async signMessage(message: string): Promise<SignMessageResult> {
    this.assertConnected();
    return this.client!.signMessage(this.pluginConfig!.agentId, message);
  }

  async getBalance(chainId?: number): Promise<GetBalanceResult> {
    this.assertConnected();
    return this.client!.getBalance(this.pluginConfig!.agentId, chainId);
  }

  async getAgent(): Promise<AgentIdentity> {
    this.assertConnected();
    return this.agentIdentity!;
  }

  async getPolicies(): Promise<PolicyRule[]> {
    this.assertConnected();
    return this.client!.getPolicies(this.pluginConfig!.agentId);
  }

  async getHistory(): Promise<GetHistoryResult> {
    this.assertConnected();
    return this.client!.getHistory(this.pluginConfig!.agentId);
  }

  async getDashboard(): Promise<AgentDashboardResponse> {
    this.assertConnected();
    return this.client!.getAgentDashboard(this.pluginConfig!.agentId);
  }

  async listApprovals(opts?: { status?: string; limit?: number; offset?: number }): Promise<ApprovalQueueEntry[]> {
    this.assertConnected();
    return this.client!.listApprovals(opts);
  }

  async getApprovalStats(): Promise<ApprovalStats> {
    this.assertConnected();
    return this.client!.getApprovalStats();
  }

  // ── Internal ────────────────────────────────────────────────────

  private assertConnected(): void {
    if (!this._connected || !this.client) {
      throw new Error("Steward service not connected");
    }
  }
}

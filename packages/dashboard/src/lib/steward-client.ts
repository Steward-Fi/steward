// Inline SDK client for standalone Vercel deployment
// Mirrors @steward/sdk but doesn't require workspace resolution

export interface StewardClientConfig {
  baseUrl: string;
  apiKey?: string;
  tenantId?: string;
}

export interface AgentIdentity {
  id: string;
  tenantId: string;
  name: string;
  walletAddress: string;
  erc8004TokenId?: string;
  platformId?: string;
  createdAt: Date;
}

export interface PolicyRule {
  id: string;
  type: string;
  enabled: boolean;
  config: Record<string, unknown>;
}

export interface PolicyResult {
  policyId: string;
  type: string;
  passed: boolean;
  reason?: string;
}

export interface TxRecord {
  id: string;
  agentId: string;
  status: string;
  toAddress: string;
  value: string;
  data?: string;
  chainId: number;
  txHash?: string;
  policyResults: PolicyResult[];
  createdAt: string;
  signedAt?: string;
  confirmedAt?: string;
  // Compat with different shapes
  request?: {
    to: string;
    value: string;
    data?: string;
    chainId: number;
  };
}

interface ApiResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

export class StewardClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor(config: StewardClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.headers = {
      "Content-Type": "application/json",
      ...(config.tenantId ? { "X-Steward-Tenant": config.tenantId } : {}),
      ...(config.apiKey ? { "X-Steward-Key": config.apiKey } : {}),
    };
  }

  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: { ...this.headers, ...options?.headers },
    });
    const json: ApiResponse<T> = await res.json();
    if (!json.ok) throw new Error(json.error || `Request failed: ${res.status}`);
    return json.data as T;
  }

  async createWallet(id: string, name: string, platformId?: string): Promise<AgentIdentity> {
    return this.request<AgentIdentity>("/agents", {
      method: "POST",
      body: JSON.stringify({ id, name, platformId }),
    });
  }

  async getAgent(agentId: string): Promise<AgentIdentity> {
    return this.request<AgentIdentity>(`/agents/${agentId}`);
  }

  async listAgents(): Promise<AgentIdentity[]> {
    return this.request<AgentIdentity[]>("/agents");
  }

  async getPolicies(agentId: string): Promise<PolicyRule[]> {
    return this.request<PolicyRule[]>(`/agents/${agentId}/policies`);
  }

  async setPolicies(agentId: string, policies: PolicyRule[]): Promise<PolicyRule[]> {
    return this.request<PolicyRule[]>(`/agents/${agentId}/policies`, {
      method: "PUT",
      body: JSON.stringify(policies),
    });
  }

  async signTransaction(agentId: string, tx: { to: string; value: string; data?: string; chainId?: number }) {
    return this.request(`/vault/${agentId}/sign`, {
      method: "POST",
      body: JSON.stringify(tx),
    });
  }

  async getHistory(agentId: string): Promise<TxRecord[]> {
    return this.request<TxRecord[]>(`/vault/${agentId}/history`);
  }

  async getPending(agentId: string) {
    return this.request<any[]>(`/vault/${agentId}/pending`);
  }

  async approve(agentId: string, txId: string) {
    return this.request(`/vault/${agentId}/approve/${txId}`, { method: "POST" });
  }

  async reject(agentId: string, txId: string) {
    return this.request(`/vault/${agentId}/reject/${txId}`, { method: "POST" });
  }
}

import { StewardClient } from "@stwd/sdk";

export const API_URL = process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

export type GasSponsorshipProvider =
  | "custom_evm_paymaster"
  | "custom_bundler"
  | "solana_fee_payer"
  | "mock";

export type GasSponsorshipMode = "erc4337" | "eip7702" | "solana_fee_payer";

export type TenantGasSponsorshipConfig = {
  enabled?: boolean;
  provider?: GasSponsorshipProvider;
  mode?: GasSponsorshipMode;
  allowedChainIds?: number[];
  allowedCaip2?: string[];
  paymasterUrl?: string;
  bundlerUrl?: string;
  entryPoint?: string;
  feePayerAgentId?: string;
  maxPerTxUsd?: number;
  maxPerWalletDayUsd?: number;
  maxTenantDayUsd?: number;
  maxTenantMonthUsd?: number;
  allowClientSponsorship?: boolean;
  requireSimulation?: boolean;
  circuitBreakerEnabled?: boolean;
};

let _apiKey = "";
let _tenantId = "";
let _steward: StewardClient;

export function setCredentials(tenantId: string, apiKey: string) {
  _tenantId = tenantId;
  _apiKey = "";
  void apiKey;
  throw new Error("Dashboard browser API-key credentials are disabled; use session auth instead.");
}

export function setTenantId(tenantId: string) {
  _tenantId = tenantId;
  _steward = new StewardClient({
    baseUrl: API_URL,
    tenantId: _tenantId,
  });
}

export function setAuthToken(token: string) {
  _steward = new StewardClient({
    baseUrl: API_URL,
    bearerToken: token,
  });
}

export function clearAuthToken() {
  _steward = new StewardClient({
    baseUrl: API_URL,
    tenantId: _tenantId,
  });
}

_steward = new StewardClient({
  baseUrl: API_URL,
  tenantId: _tenantId,
});

// Proxy getter so components always get the latest client instance
export const steward = new Proxy({} as StewardClient, {
  get(_target, prop) {
    const value = (_steward as unknown as Record<string | symbol, unknown>)[prop];
    if (typeof value === "function") {
      // Rebind `this` so SDK methods can call private members on the live client.
      return (value as (...args: unknown[]) => unknown).bind(_steward);
    }
    return value;
  },
});

async function readJson<T>(res: Response, fallback: string): Promise<T> {
  const data = await res.json();
  if (!res.ok || !data.ok) throw new Error(data.error || fallback);
  return data.data as T;
}

export async function getTenantGasSponsorshipConfig(
  tenantId: string,
  authToken: string,
): Promise<TenantGasSponsorshipConfig> {
  const data = await readJson<{ gasSponsorshipConfig: TenantGasSponsorshipConfig }>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/gas-sponsorship`, {
      headers: { Authorization: `Bearer ${authToken}` },
    }),
    "Failed to load gas sponsorship config",
  );
  return data.gasSponsorshipConfig ?? {};
}

export async function updateTenantGasSponsorshipConfig(
  tenantId: string,
  authToken: string,
  gasSponsorshipConfig: TenantGasSponsorshipConfig,
): Promise<TenantGasSponsorshipConfig> {
  const data = await readJson<{ gasSponsorshipConfig: TenantGasSponsorshipConfig }>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/gas-sponsorship`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ gasSponsorshipConfig }),
    }),
    "Failed to save gas sponsorship config",
  );
  return data.gasSponsorshipConfig ?? {};
}

export { _apiKey as API_KEY, _tenantId as TENANT_ID };

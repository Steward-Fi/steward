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

export type TenantSecurityChecklistStatus = "pass" | "warning" | "fail";

export type TenantSecurityChecklistItem = {
  id: string;
  label: string;
  status: TenantSecurityChecklistStatus;
  description: string;
  remediation?: string;
};

export type TenantSecurityChecklist = {
  tenantId: string;
  generatedAt: string;
  summary: {
    pass: number;
    warning: number;
    fail: number;
  };
  items: TenantSecurityChecklistItem[];
};

export type IdempotencyMetricCounters = {
  observed: number;
  reserved: number;
  completed: number;
  replayed: number;
  conflicts: number;
  inFlightConflicts: number;
  suppressedAuthResponses: number;
  invalidKeys: number;
  storeErrors: number;
  skippedUnsafeContext: number;
  releasedOnError: number;
};

export type TenantIdempotencyMetrics = {
  tenantId: string;
  generatedAt: string;
  windowStartedAt: string;
  lastSeenAt: string | null;
  ttlMs: number;
  counters: IdempotencyMetricCounters;
};

export type TenantRequestSigningKey = {
  id: string;
  tenantId: string;
  name: string;
  secretPrefix: string;
  status: "active" | "retiring" | "revoked";
  createdAt: string;
  updatedAt: string;
  expiresAt?: string | null;
  revokedAt?: string | null;
};

export type TenantRequestSigningKeyCreateResult = {
  key: TenantRequestSigningKey;
  signingSecret: string;
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

export async function getTenantSecurityChecklist(
  tenantId: string,
  authToken: string,
): Promise<TenantSecurityChecklist> {
  return readJson<TenantSecurityChecklist>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/security-checklist`, {
      headers: { Authorization: `Bearer ${authToken}` },
    }),
    "Failed to load security checklist",
  );
}

export async function getTenantIdempotencyMetrics(
  tenantId: string,
  authToken: string,
): Promise<TenantIdempotencyMetrics> {
  return readJson<TenantIdempotencyMetrics>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/idempotency-metrics`, {
      headers: { Authorization: `Bearer ${authToken}` },
    }),
    "Failed to load idempotency metrics",
  );
}

export async function listTenantRequestSigningKeys(
  tenantId: string,
  authToken: string,
): Promise<TenantRequestSigningKey[]> {
  const data = await readJson<{ keys: TenantRequestSigningKey[] }>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/request-signing-keys`, {
      headers: { Authorization: `Bearer ${authToken}` },
    }),
    "Failed to load request signing keys",
  );
  return data.keys ?? [];
}

export async function rotateTenantRequestSigningKey(
  tenantId: string,
  authToken: string,
  name?: string,
): Promise<TenantRequestSigningKeyCreateResult> {
  return readJson<TenantRequestSigningKeyCreateResult>(
    await fetch(`${API_URL}/tenants/${encodeURIComponent(tenantId)}/request-signing-keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${authToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name }),
    }),
    "Failed to rotate request signing key",
  );
}

export async function revokeTenantRequestSigningKey(
  tenantId: string,
  authToken: string,
  keyId: string,
): Promise<TenantRequestSigningKey> {
  const data = await readJson<{ key: TenantRequestSigningKey }>(
    await fetch(
      `${API_URL}/tenants/${encodeURIComponent(
        tenantId,
      )}/request-signing-keys/${encodeURIComponent(keyId)}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${authToken}` },
      },
    ),
    "Failed to revoke request signing key",
  );
  return data.key;
}

export { _apiKey as API_KEY, _tenantId as TENANT_ID };

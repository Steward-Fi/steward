import { StewardClient } from "./steward-client";

// API URL is still public (it's the endpoint, not a secret)
export const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

// These are no longer hardcoded. They come from the auth context at runtime.
// Default empty values for SSR / initial render.
let _apiKey = "";
let _tenantId = "";

export function setCredentials(tenantId: string, apiKey: string) {
  _tenantId = tenantId;
  _apiKey = apiKey;
  // Recreate the client with new credentials
  _steward = new StewardClient({
    baseUrl: API_URL,
    apiKey: _apiKey,
    tenantId: _tenantId,
  });
}

export function setAuthToken(token: string) {
  // Recreate the client using JWT Bearer auth (passkey / email login)
  _steward = new StewardClient({
    baseUrl: API_URL,
    authToken: token,
  });
}

let _steward = new StewardClient({
  baseUrl: API_URL,
  apiKey: _apiKey,
  tenantId: _tenantId,
});

// Proxy getter so components always get the latest client
export const steward = new Proxy({} as StewardClient, {
  get(_target, prop) {
    return (_steward as unknown as Record<string | symbol, unknown>)[prop];
  },
});

export { _tenantId as TENANT_ID, _apiKey as API_KEY };

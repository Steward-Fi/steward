import { StewardClient, type StewardClientConfig } from "@stwd/sdk";

/**
 * Resolved configuration for the Steward MCP server. Mirrors the subset of
 * {@link StewardClientConfig} the server needs plus a default agent id used by
 * agent-scoped tools when the caller omits one.
 */
export interface StewardMcpConfig {
  /** Base URL of the Steward API, e.g. `https://api.steward.fi`. */
  baseUrl: string;
  /** Tenant API key. Sent as an authorization header by the SDK. */
  apiKey?: string;
  /** Agent-scoped bearer JWT. Preferred over `apiKey` when both are present. */
  bearerToken?: string;
  /** Tenant id scoping all requests. */
  tenantId?: string;
  /**
   * Default agent id applied to agent-scoped tools when the tool call omits
   * `agentId`. Optional - tools require an explicit id when this is unset.
   */
  defaultAgentId?: string;
}

/** Keys that must never be echoed back to clients or written to logs. */
const SECRET_CONFIG_KEYS = new Set<keyof StewardMcpConfig>(["apiKey", "bearerToken"]);

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Reject plaintext `http://` URLs for non-localhost hosts. Talking to a remote
 * Steward API over http would expose the API key / bearer token and any signed
 * payloads to network observers. The localhost exception keeps local dev usable.
 */
export function assertSecureBaseUrl(baseUrl: string): void {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`Invalid STEWARD_URL: ${JSON.stringify(baseUrl)} is not a valid URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Invalid STEWARD_URL protocol "${parsed.protocol}": only http(s) is supported`);
  }
  if (parsed.protocol === "http:" && !LOCAL_HOSTS.has(parsed.hostname)) {
    throw new Error(
      `Insecure STEWARD_URL "${baseUrl}": http:// is only allowed for localhost. Use https:// for remote hosts.`,
    );
  }
}

/**
 * Build a {@link StewardMcpConfig} from a record of environment variables
 * (defaults to `process.env`). Throws a clear error when required config is
 * missing or the URL is insecure.
 *
 * Recognized variables:
 * - `STEWARD_URL` / `STEWARD_BASE_URL` (required) - API base URL
 * - `STEWARD_API_KEY` - tenant API key
 * - `STEWARD_JWT` / `STEWARD_BEARER_TOKEN` - agent-scoped bearer token
 * - `STEWARD_TENANT_ID` - tenant id
 * - `STEWARD_AGENT_ID` - default agent id for agent-scoped tools
 *
 * At least one credential (`STEWARD_API_KEY` or a bearer token) must be set.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): StewardMcpConfig {
  const baseUrl = (env.STEWARD_URL ?? env.STEWARD_BASE_URL ?? "").trim();
  if (!baseUrl) {
    throw new Error(
      "Missing required STEWARD_URL (or STEWARD_BASE_URL). Set it to your Steward API base URL, e.g. https://api.steward.fi",
    );
  }
  assertSecureBaseUrl(baseUrl);

  const apiKey = env.STEWARD_API_KEY?.trim() || undefined;
  const bearerToken = (env.STEWARD_JWT ?? env.STEWARD_BEARER_TOKEN)?.trim() || undefined;
  const tenantId = env.STEWARD_TENANT_ID?.trim() || undefined;
  const defaultAgentId = env.STEWARD_AGENT_ID?.trim() || undefined;

  if (!apiKey && !bearerToken) {
    throw new Error(
      "Missing Steward credentials. Set STEWARD_API_KEY (tenant key) or STEWARD_JWT (agent bearer token).",
    );
  }

  return { baseUrl, apiKey, bearerToken, tenantId, defaultAgentId };
}

/** Construct a {@link StewardClient} from a resolved MCP config. */
export function createStewardClient(config: StewardMcpConfig): StewardClient {
  const clientConfig: StewardClientConfig = {
    baseUrl: config.baseUrl,
    apiKey: config.apiKey,
    bearerToken: config.bearerToken,
    tenantId: config.tenantId,
  };
  return new StewardClient(clientConfig);
}

/**
 * Produce a log-safe view of the config with all secret values redacted. Use
 * this anywhere config is printed (e.g. the CLI startup banner on stderr).
 */
export function redactConfig(config: StewardMcpConfig): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config) as [keyof StewardMcpConfig, unknown][]) {
    if (value === undefined) continue;
    out[key] = SECRET_CONFIG_KEYS.has(key) ? redactSecret(String(value)) : value;
  }
  return out;
}

/**
 * Mask a secret string, revealing at most the last 4 characters for
 * identification. Short secrets are fully masked.
 */
export function redactSecret(value: string): string {
  if (value.length <= 8) return "****";
  return `****${value.slice(-4)}`;
}

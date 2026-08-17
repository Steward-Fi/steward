import { describeThrown } from "@stwd/shared";
import type { StewardMcpConfig } from "./config.js";

export interface ProviderApi {
  request(path: string, init?: RequestInit): Promise<unknown>;
}

// Best-effort redaction (SEC-172): keyed fields AND free-text secret shapes.
// Coverage is deliberately conservative — over-broad patterns would redact
// legitimate tool output (tx hashes, ids) — so the first line of defense
// remains upstream errors not embedding secrets at all.
const SENSITIVE_KEY =
  /authorization|bearer|token|secret|credential|api[-_]?key|cookie|pass(?:word|phrase|wd)|private[-_]?key|jwt|signature/i;
const SECRET_TEXT =
  /(?:bearer\s+|(?:api[-_]?key|token|secret|credential|pass(?:word|phrase|wd)|private[-_]?key)["'\s:=]+)[^\s,"'}]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|\bsk-[A-Za-z0-9]{8,}|\bgh[po]_[A-Za-z0-9]{8,}|\bxox[baprs]-[A-Za-z0-9-]{8,}/gi;

export function sanitizeProviderPayload(value: unknown, depth = 0): unknown {
  if (depth > 20) return "[redacted]";
  if (typeof value === "string") return value.replace(SECRET_TEXT, "[redacted]");
  if (Array.isArray(value)) return value.map((item) => sanitizeProviderPayload(item, depth + 1));
  if (value && typeof value === "object") {
    const clean: Record<string, unknown> = {};
    for (const [key, nested] of Object.entries(value)) {
      clean[key] = SENSITIVE_KEY.test(key)
        ? "[redacted]"
        : sanitizeProviderPayload(nested, depth + 1);
    }
    return clean;
  }
  return value;
}

export class ProviderApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = "ProviderApiError";
  }
}

export function createProviderApi(config: StewardMcpConfig): ProviderApi {
  const baseUrl = config.baseUrl.replace(/\/+$/, "");
  return {
    async request(path, init = {}) {
      const headers = new Headers(init.headers);
      headers.set("Accept", "application/json");
      if (init.body !== undefined) headers.set("Content-Type", "application/json");
      if (config.bearerToken) headers.set("Authorization", `Bearer ${config.bearerToken}`);
      else if (config.apiKey) headers.set("X-Steward-Key", config.apiKey);
      if (config.tenantId) headers.set("X-Steward-Tenant", config.tenantId);

      let response: Response;
      try {
        response = await fetch(`${baseUrl}${path}`, {
          ...init,
          headers,
          signal: init.signal ?? AbortSignal.timeout(15_000),
        });
      } catch (err) {
        throw new ProviderApiError(`Provider API request failed: ${describeThrown(err)}`, 0);
      }
      let payload: unknown;
      try {
        payload = await response.json();
      } catch {
        payload = { error: "UPSTREAM_RESPONSE_INVALID" };
      }
      const clean = sanitizeProviderPayload(payload);
      if (!response.ok) {
        const message =
          clean &&
          typeof clean === "object" &&
          typeof (clean as Record<string, unknown>).error === "string"
            ? ((clean as Record<string, unknown>).error as string)
            : `Provider API request failed with HTTP ${response.status}`;
        throw new ProviderApiError(message, response.status, clean);
      }
      return clean;
    },
  };
}

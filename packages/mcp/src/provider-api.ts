import { describeThrown, isSensitiveCredentialKey } from "@stwd/shared";
import type { StewardMcpConfig } from "./config.js";

export interface ProviderApi {
  request(path: string, init?: RequestInit): Promise<unknown>;
}

// Best-effort redaction (SEC-172): keyed fields AND free-text secret shapes.
// Coverage is deliberately conservative — over-broad patterns would redact
// legitimate tool output (tx hashes, ids) — so the first line of defense
// remains upstream errors not embedding secrets at all.
function isSensitiveProviderKey(key: string): boolean {
  // Use the repository-wide classifier so this MCP boundary cannot drift
  // behind newly recognized credential carrier names. `passwd` and
  // signatures are retained as MCP-specific conservative additions.
  return isSensitiveCredentialKey(key) || /passwd|signature/i.test(key);
}
const SECRET_TEXT =
  /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----|(?:bearer\s+|(?:auth(?:orization)?|token|secret|credential|api[-_]?key|cookie(?:[-_]?header)?|pass(?:word|phrase|wd)|private[-_]?key|jwt|signature|client[-_]?secret|access[-_]?key(?:[-_]?id)?|secret[-_]?access[-_]?key|session[-_]?(?:id|cookie)|signing[-_]?key|encryption[-_]?key|mnemonic|seed[-_]?phrase|recovery[-_]?phrase|pat)(?:\s*["']?\s*[:=]\s*["']?|\s+))[^\s,"'}]+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|\bsk-[A-Za-z0-9_-]{8,}|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[po]_[A-Za-z0-9]{8,}|\bxox[baprs]-[A-Za-z0-9-]{8,}/gi;

export function sanitizeProviderPayload(
  value: unknown,
  depth = 0,
  ancestors = new Set<object>(),
): unknown {
  if (depth > 20) return "[redacted]";
  if (typeof value === "string") return value.replace(SECRET_TEXT, "[redacted]");
  if (value && typeof value === "object") {
    // Untrusted provider values must not execute accessors during a scrub, and
    // cycles fail closed instead of being traversed repeatedly to the limit.
    if (ancestors.has(value)) return "[redacted]";
    ancestors.add(value);
    try {
      if (Array.isArray(value)) {
        return value.map((item) => sanitizeProviderPayload(item, depth + 1, ancestors));
      }
      const clean: Record<string, unknown> = {};
      for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
        if (!descriptor.enumerable) continue;
        clean[key] =
          isSensitiveProviderKey(key) || !("value" in descriptor)
            ? "[redacted]"
            : sanitizeProviderPayload(descriptor.value, depth + 1, ancestors);
      }
      return clean;
    } finally {
      ancestors.delete(value);
    }
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

/**
 * Proxy configuration — named aliases and defaults.
 *
 * Aliases let agents use short names instead of full hostnames:
 *   /openai/v1/chat/completions → api.openai.com/v1/chat/completions
 *
 * Per-tenant aliases will be configurable via DB in a future release.
 */

export const DEFAULT_ALIASES: Record<string, string> = {
  openai: "api.openai.com",
  anthropic: "api.anthropic.com",
  birdeye: "public-api.birdeye.so",
  coingecko: "api.coingecko.com",
  helius: "api.helius.xyz",
  github: "api.github.com",
  x: "api.x.com",
};

/** Default port for the proxy server */
export function positiveIntegerEnv(name: string, fallback: number, maximum?: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0 || (maximum !== undefined && value > maximum)) {
    throw new Error(
      `${name} must be a positive integer${maximum ? ` no greater than ${maximum}` : ""}`,
    );
  }
  return value;
}

export const PROXY_PORT = positiveIntegerEnv("STEWARD_PROXY_PORT", 8080, 65535);

/** Required JWT scope for proxy access */
export const PROXY_SCOPE = "api:proxy";

/**
 * SEC-175: the proxy fails closed by default — request signing, Redis-backed
 * rate limiting, and the shared replay store are REQUIRED regardless of
 * NODE_ENV. The soft development posture (unsigned requests, permissive
 * in-process fallbacks) now needs this explicit opt-in, so a deployment that
 * merely forgets to set NODE_ENV=production no longer silently gets it.
 * Local dev compose sets STEWARD_PROXY_DEV_MODE=true.
 */
export function isProxyDevMode(): boolean {
  return process.env.NODE_ENV !== "production" && process.env.STEWARD_PROXY_DEV_MODE === "true";
}

export function configuredProxyCorsOrigins(): string[] {
  const values = (process.env.STEWARD_PROXY_CORS_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return values.map((value) => {
    if (value === "*") throw new Error("STEWARD_PROXY_CORS_ORIGINS must not contain '*'");
    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error(`Invalid STEWARD_PROXY_CORS_ORIGINS origin: ${JSON.stringify(value)}`);
    }
    if (
      (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
      parsed.username ||
      parsed.password ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash ||
      parsed.origin !== value
    ) {
      throw new Error(
        `STEWARD_PROXY_CORS_ORIGINS entries must be canonical HTTP(S) origins: ${JSON.stringify(value)}`,
      );
    }
    return parsed.origin;
  });
}

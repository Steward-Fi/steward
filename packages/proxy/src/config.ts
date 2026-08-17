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

/** Parse a bounded integer setting at module load so malformed resource limits fail closed. */
export function boundedPositiveIntegerEnv(name: string, fallback: number, maximum: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

/** Default port for the proxy server */
export const PROXY_PORT = boundedPositiveIntegerEnv("STEWARD_PROXY_PORT", 8080, 65_535);

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
  return process.env.STEWARD_PROXY_DEV_MODE === "true";
}

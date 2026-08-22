import { runtimeEnvironmentSnapshot, runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
/**
 * Redis middleware — initializes the Redis client and exposes
 * rate-limiting + spend-tracking helpers on the Hono context.
 *
 * When Redis is not configured, the middleware is a no-op and the helpers
 * return documented local-development defaults. If Redis is configured and a
 * money-path/rate-limit helper cannot read it, the helper fails closed.
 */

import {
  checkRateLimit,
  checkSpendLimit,
  disconnectRedis,
  getRedis,
  type IoredisLike,
  type RateLimitResult,
  recordSpend,
  type SpendPeriod,
  type SpendRecordOptions,
} from "@stwd/redis";
import { redactedThrownDiagnostics } from "@stwd/shared";

// ─── Redis availability flag ─────────────────────────────────────────────────

const redisClients = new Map<string, IoredisLike>();

function redisAuthorityFingerprint(): string {
  const environment = runtimeEnvironmentSnapshot();
  return JSON.stringify([
    environment.REDIS_DRIVER ?? "ioredis",
    environment.REDIS_URL ?? "",
    environment.KV_REST_API_URL ?? environment.UPSTASH_REDIS_REST_URL ?? "",
    environment.KV_REST_API_TOKEN ?? environment.UPSTASH_REDIS_REST_TOKEN ?? "",
    environment.NODE_ENV ?? "",
    environment.STEWARD_RUNTIME ?? "",
    environment.STEWARD_ALLOW_INSECURE_REDIS ?? "",
  ]);
}

/**
 * Try to connect to Redis on startup. If it fails, route-level helpers decide
 * whether to use local-development defaults or fail closed based on whether
 * Redis was configured for this deployment.
 */
export async function initRedis(_env?: Record<string, unknown>): Promise<boolean> {
  const fingerprint = redisAuthorityFingerprint();
  if (redisClients.has(fingerprint)) return true;

  const driver = runtimeEnvironmentValue("REDIS_DRIVER")?.trim().toLowerCase() || "ioredis";
  const hasIoredisUrl = Boolean(runtimeEnvironmentValue("REDIS_URL"));
  const hasUpstashConfig = Boolean(
    (runtimeEnvironmentValue("KV_REST_API_URL") ||
      runtimeEnvironmentValue("UPSTASH_REDIS_REST_URL")) &&
      (runtimeEnvironmentValue("KV_REST_API_TOKEN") ||
        runtimeEnvironmentValue("UPSTASH_REDIS_REST_TOKEN")),
  );

  if (driver === "upstash" ? !hasUpstashConfig : !hasIoredisUrl) {
    const expected = driver === "upstash" ? "KV_REST_API_URL/KV_REST_API_TOKEN" : "REDIS_URL";
    console.log(`[steward:redis] ${expected} not set — Redis enforcement disabled`);
    return false;
  }

  try {
    const redisClient = getRedis();
    // Ping to verify the connection
    await redisClient?.ping();
    redisClients.set(fingerprint, redisClient);
    console.log("[steward:redis] Redis connected — rate limiting and spend tracking enabled");
    return true;
  } catch (err) {
    console.warn(
      "[steward:redis] Failed to connect — Redis enforcement disabled",
      redactedThrownDiagnostics(err),
    );
    redisClients.delete(fingerprint);
    return false;
  }
}

export function isRedisAvailable(): boolean {
  return redisClients.has(redisAuthorityFingerprint());
}

export function isRedisConfigured(): boolean {
  const driver = runtimeEnvironmentValue("REDIS_DRIVER")?.trim().toLowerCase() || "ioredis";
  if (driver === "upstash") {
    return Boolean(
      (runtimeEnvironmentValue("KV_REST_API_URL") ||
        runtimeEnvironmentValue("UPSTASH_REDIS_REST_URL")) &&
        (runtimeEnvironmentValue("KV_REST_API_TOKEN") ||
          runtimeEnvironmentValue("UPSTASH_REDIS_REST_TOKEN")),
    );
  }
  return Boolean(runtimeEnvironmentValue("REDIS_URL"));
}

/**
 * Return the active Redis client (real ioredis or upstash adapter), or null
 * if Redis is not available. Call isRedisAvailable() first to check.
 */
export function getRedisClient(): IoredisLike | null {
  return redisClients.get(redisAuthorityFingerprint()) ?? null;
}

export async function shutdownRedis(): Promise<void> {
  if (redisClients.size > 0) {
    await disconnectRedis();
    redisClients.clear();
  }
}

// ─── Rate-limit helpers (safe wrappers) ──────────────────────────────────────

const PERMISSIVE_RATE_LIMIT: RateLimitResult = {
  allowed: true,
  remaining: Infinity,
  resetMs: 0,
};

/**
 * Check rate limit for an agent's vault signing requests.
 *
 * Key format: ratelimit:vault:{agentId}:{windowMs}
 */
export async function checkAgentRateLimit(
  agentId: string,
  windowMs: number,
  maxRequests: number,
): Promise<RateLimitResult> {
  // Redis not available: only skip enforcement when Redis was never configured
  // (documented dev path). If Redis IS configured (production), an unavailable
  // backend must fail CLOSED — mirroring checkAgentSpendLimit (SEC-016).
  if (!isRedisAvailable()) {
    if (!isRedisConfigured()) return PERMISSIVE_RATE_LIMIT;
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }

  try {
    const key = `ratelimit:vault:${agentId}:${windowMs}`;
    return await checkRateLimit(key, windowMs, maxRequests);
  } catch (err) {
    console.error(
      "[steward:redis] Rate limit check failed, denying sensitive request",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }
}

/**
 * Check rate limit for proxy requests.
 *
 * Key format: ratelimit:proxy:{agentId}:{host}:{windowMs}
 */
export async function checkProxyRateLimit(
  agentId: string,
  host: string,
  windowMs: number,
  maxRequests: number,
): Promise<RateLimitResult> {
  // Same fail-closed posture as checkAgentRateLimit (SEC-016): permissive only
  // when Redis was never configured; a configured-but-down backend denies.
  if (!isRedisAvailable()) {
    if (!isRedisConfigured()) return PERMISSIVE_RATE_LIMIT;
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }

  try {
    const key = `ratelimit:proxy:${agentId}:${host}:${windowMs}`;
    return await checkRateLimit(key, windowMs, maxRequests);
  } catch (err) {
    console.error(
      "[steward:redis] Proxy rate limit check failed, denying request",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }
}

// ─── Spend-tracking helpers (safe wrappers) ───────────────────────────────────

/**
 * Check if an agent's spending would exceed their limit.
 */
export async function checkAgentSpendLimit(
  agentId: string,
  limitUsd: number,
  period: SpendPeriod,
): Promise<{ allowed: boolean; spent: number; remaining: number }> {
  // Redis not available: only skip enforcement when Redis was never configured
  // (documented dev path). If Redis IS configured (production), an unavailable
  // backend must fail CLOSED rather than silently allow unlimited spend.
  if (!isRedisAvailable()) {
    if (!isRedisConfigured()) return { allowed: true, spent: 0, remaining: limitUsd };
    return { allowed: false, spent: 0, remaining: 0 };
  }

  try {
    return await checkSpendLimit(agentId, limitUsd, period);
  } catch (err) {
    // Configured backend threw: fail CLOSED — we cannot prove the spend is within limit.
    console.error(
      "[steward:redis] Spend limit check failed, denying request (fail-closed)",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, spent: 0, remaining: 0 };
  }
}

/**
 * Record a spend event after a successful transaction/request.
 */
export async function recordAgentSpend(
  agentId: string,
  tenantId: string,
  costUsd: number,
  host: string,
  options: SpendRecordOptions & { throwOnError?: boolean } = {},
): Promise<void> {
  if (!isRedisAvailable()) {
    if (options.throwOnError && isRedisConfigured()) {
      throw new Error("Configured Redis spend backend is unavailable");
    }
    return;
  }
  if (costUsd <= 0) return;

  try {
    await recordSpend(agentId, tenantId, costUsd, host, options);
  } catch (err) {
    if (options.throwOnError) throw err;
    console.error("[steward:redis] Failed to record spend", redactedThrownDiagnostics(err));
  }
}

// Re-export cost estimator for proxy use
export { estimateCost } from "@stwd/redis";

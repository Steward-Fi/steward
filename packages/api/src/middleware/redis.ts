/**
 * Redis middleware — initializes the Redis client and exposes
 * rate-limiting + spend-tracking helpers on the Hono context.
 *
 * When Redis is not configured, the middleware is a no-op. Helpers return
 * documented defaults only in explicit non-production postures; production
 * money-path enforcement fails closed when durable state is absent or down.
 */

import {
  checkRateLimit,
  disconnectRedis,
  getRedis,
  type IoredisLike,
  type RateLimitResult,
  recordSpend,
  reserveSpend,
  type SpendRecordOptions,
  type SpendReservation,
  settleReservedSpend,
} from "@stwd/redis";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

// ─── Redis availability flag ─────────────────────────────────────────────────

let redisAvailable = false;
let redisClient: IoredisLike | null = null;

export type AgentSpendReservation =
  | { source: "redis"; agentId: string; tenantId: string; reservation: SpendReservation }
  | { source: "memory"; key: string; units: number };

const localAdapterReservations = new Map<string, number>();

function adapterMemoryFallbackAllowed(): boolean {
  const environment = runtimeEnvironmentValue("NODE_ENV");
  return (
    runtimeEnvironmentValue("STEWARD_RUNTIME") !== "workers" &&
    (environment === "development" || environment === "test") &&
    runtimeEnvironmentValue("STEWARD_ALLOW_MEMORY_ADAPTER_SPEND") === "true"
  );
}

function adapterMemoryKey(agentId: string): string {
  return `${agentId}:${new Date().toISOString().slice(0, 10)}`;
}

function toSpendUnits(value: number): number {
  if (!Number.isFinite(value) || value <= 0) throw new Error("invalid adapter spend amount");
  const units = Math.ceil(value * 10_000);
  if (!Number.isSafeInteger(units)) throw new Error("adapter spend amount is too large");
  return units;
}

/** Test-only reset for the explicitly acknowledged process-local fallback. */
export function __resetAdapterMemorySpendForTests(): void {
  localAdapterReservations.clear();
}

/**
 * Try to connect to Redis on startup. If it fails, route-level helpers decide
 * whether to use local-development defaults or fail closed based on whether
 * Redis was configured for this deployment.
 */
export async function initRedis(env?: Record<string, unknown>): Promise<boolean> {
  if (redisAvailable && redisClient) return true;

  if (env) {
    for (const [key, value] of Object.entries(env)) {
      if (typeof value === "string") process.env[key] = value;
    }
  }

  const driver = process.env.REDIS_DRIVER?.trim().toLowerCase() || "ioredis";
  const hasIoredisUrl = Boolean(process.env.REDIS_URL);
  const hasUpstashConfig = Boolean(
    (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL) &&
      (process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN),
  );

  if (driver === "upstash" ? !hasUpstashConfig : !hasIoredisUrl) {
    const expected = driver === "upstash" ? "KV_REST_API_URL/KV_REST_API_TOKEN" : "REDIS_URL";
    console.log(`[steward:redis] ${expected} not set — Redis enforcement disabled`);
    return false;
  }

  try {
    redisClient = getRedis();
    // Ping to verify the connection
    await redisClient?.ping();
    redisAvailable = true;
    console.log("[steward:redis] Redis connected — rate limiting and spend tracking enabled");
    return true;
  } catch (err) {
    console.warn(
      "[steward:redis] Failed to connect — Redis enforcement disabled",
      redactedThrownDiagnostics(err),
    );
    redisAvailable = false;
    return false;
  }
}

export function isRedisAvailable(): boolean {
  return redisAvailable;
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
  return redisAvailable ? redisClient : null;
}

export async function shutdownRedis(): Promise<void> {
  if (redisAvailable) {
    await disconnectRedis();
    redisAvailable = false;
    redisClient = null;
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
  // backend must fail CLOSED — mirroring adapter spend reservations (SEC-016).
  if (!redisAvailable) {
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
  if (!redisAvailable) {
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
 * Cheap preflight used before an adapter/provider is invoked. This is not the
 * monetary admission decision; reserveAgentSpendLimit performs that atomically.
 */
export function isAgentSpendReservationAvailable(): boolean {
  if (isRedisConfigured()) return redisAvailable;
  return adapterMemoryFallbackAllowed();
}

/**
 * Atomically reserve an adapter intent against settled + already-reserved daily
 * spend. Successful reservations remain authoritative after the response so a
 * concurrent process or restarted API cannot issue another intent past the cap.
 */
export async function reserveAgentSpendLimit(
  agentId: string,
  tenantId: string,
  amountUsd: number,
  limitUsd: number,
): Promise<
  { allowed: true; reservation: AgentSpendReservation } | { allowed: false; reason: string }
> {
  let amountUnits: number;
  let limitUnits: number;
  try {
    amountUnits = toSpendUnits(amountUsd);
    limitUnits = toSpendUnits(limitUsd);
  } catch {
    return { allowed: false, reason: "adapter spend policy is invalid" };
  }

  if (!isRedisConfigured()) {
    if (!adapterMemoryFallbackAllowed()) {
      return { allowed: false, reason: "durable adapter spend enforcement is unavailable" };
    }
    const key = adapterMemoryKey(agentId);
    const current = localAdapterReservations.get(key) ?? 0;
    if (amountUnits > limitUnits - current) {
      return { allowed: false, reason: "adapter daily spend cap would be exceeded" };
    }
    localAdapterReservations.set(key, current + amountUnits);
    return { allowed: true, reservation: { source: "memory", key, units: amountUnits } };
  }

  if (!redisAvailable) {
    return { allowed: false, reason: "durable adapter spend enforcement is unavailable" };
  }

  try {
    const reservation = await reserveSpend(agentId, tenantId, amountUsd, { day: limitUsd });
    return {
      allowed: true,
      reservation: { source: "redis", agentId, tenantId, reservation },
    };
  } catch (err) {
    console.error(
      "[steward:redis] Adapter spend reservation failed, denying request",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, reason: "adapter daily spend cap or durable enforcement denied" };
  }
}

/** Release a reservation only when no intent was handed to the caller. */
export async function releaseAgentSpendReservation(
  held: AgentSpendReservation | undefined,
): Promise<void> {
  if (!held) return;
  if (held.source === "memory") {
    const current = localAdapterReservations.get(held.key) ?? 0;
    const after = Math.max(0, current - held.units);
    if (after === 0) localAdapterReservations.delete(held.key);
    else localAdapterReservations.set(held.key, after);
    return;
  }
  try {
    await settleReservedSpend(
      held.agentId,
      held.tenantId,
      held.reservation.reservedUsd,
      0,
      "adapter-intent",
      held.reservation.periods,
      held.reservation.buckets,
    );
  } catch (err) {
    // A failed release intentionally leaves the reservation in place. That is
    // fail-closed and prevents a provider failure from freeing uncertain budget.
    console.error(
      "[steward:redis] Adapter spend reservation release failed; hold retained",
      redactedThrownDiagnostics(err),
    );
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
  if (!redisAvailable) {
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

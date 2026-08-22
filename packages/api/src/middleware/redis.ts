/**
 * Redis middleware — initializes the Redis client and exposes
 * rate-limiting + spend-tracking helpers on the Hono context.
 *
 * When Redis is not configured, the middleware is a no-op. Helpers return
 * documented defaults only in explicit non-production postures; production
 * money-path enforcement fails closed when durable state is absent or down.
 */

import { createHash } from "node:crypto";
import {
  checkRateLimit,
  checkSpendLimit,
  createRedisClient,
  type IoredisLike,
  type RateLimitResult,
  recordSpend,
  reserveDailySpendIdempotently,
  type SpendPeriod,
  type SpendRecordOptions,
  setRedisClientResolverForRuntime,
} from "@stwd/redis";
import { redactedThrownDiagnostics } from "@stwd/shared";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";

// ─── Redis availability flag ─────────────────────────────────────────────────

type RedisBinding = Readonly<{
  driver: "ioredis" | "upstash";
  redisUrl?: string;
  restUrl?: string;
  restToken?: string;
  nodeEnv?: string;
  runtime?: string;
  allowInsecure?: string;
}>;

const redisClients = new Map<string, IoredisLike>();
const redisInitializations = new Map<string, Promise<boolean>>();
const MAX_REDIS_BINDING_GENERATIONS = 8;
const MAX_MEMORY_ADAPTER_BUCKETS = 1_000;
const MAX_MEMORY_ADAPTER_RESERVATIONS_PER_BUCKET = 1_000;
type MemoryAdapterBucket = { units: number; markers: Map<string, string> };
const memoryAdapterBuckets = new Map<string, MemoryAdapterBucket>();

function valueFrom(env: Record<string, unknown> | undefined, name: string): string | undefined {
  if (env) return typeof env[name] === "string" ? (env[name] as string) : undefined;
  return runtimeEnvironmentValue(name);
}

function redisBinding(env?: Record<string, unknown>): RedisBinding | null {
  const driver =
    valueFrom(env, "REDIS_DRIVER")?.trim().toLowerCase() === "upstash" ? "upstash" : "ioredis";
  const nodeEnv = valueFrom(env, "NODE_ENV");
  // STEWARD_RUNTIME is injected into the immutable ALS snapshot by worker.ts;
  // it is intentionally not a real Worker binding. Fall back only for this
  // synthetic posture field, never for URLs/tokens omitted by a new binding.
  const explicitRuntime = env?.STEWARD_RUNTIME;
  const runtime =
    typeof explicitRuntime === "string"
      ? explicitRuntime
      : runtimeEnvironmentValue("STEWARD_RUNTIME");
  const allowInsecure = valueFrom(env, "STEWARD_ALLOW_INSECURE_REDIS");
  if (driver === "upstash") {
    const restUrl = valueFrom(env, "KV_REST_API_URL") || valueFrom(env, "UPSTASH_REDIS_REST_URL");
    const restToken =
      valueFrom(env, "KV_REST_API_TOKEN") || valueFrom(env, "UPSTASH_REDIS_REST_TOKEN");
    return restUrl && restToken
      ? { driver, restUrl, restToken, nodeEnv, runtime, allowInsecure }
      : null;
  }
  const redisUrl = valueFrom(env, "REDIS_URL");
  return redisUrl ? { driver, redisUrl, nodeEnv, runtime, allowInsecure } : null;
}

function redisBindingKey(binding: RedisBinding): string {
  return createHash("sha256").update(JSON.stringify(binding)).digest("hex");
}

function redisClientEnvironment(binding: RedisBinding): Record<string, string | undefined> {
  return binding.driver === "upstash"
    ? {
        REDIS_DRIVER: "upstash",
        KV_REST_API_URL: binding.restUrl,
        KV_REST_API_TOKEN: binding.restToken,
        NODE_ENV: binding.nodeEnv,
        STEWARD_RUNTIME: binding.runtime,
        STEWARD_ALLOW_INSECURE_REDIS: binding.allowInsecure,
      }
    : {
        REDIS_DRIVER: "ioredis",
        REDIS_URL: binding.redisUrl,
        NODE_ENV: binding.nodeEnv,
        STEWARD_RUNTIME: binding.runtime,
        STEWARD_ALLOW_INSECURE_REDIS: binding.allowInsecure,
      };
}

function reserveMemoryAdapterSpend(input: {
  agentId: string;
  tenantId: string;
  amountUsd: number;
  limitUsd: number;
  reservationId: string;
  requestDigest: string;
}): { allowed: boolean; replayed: boolean; conflict?: boolean; remainingUsd: number } {
  const amountUnits = Math.ceil(input.amountUsd * 10_000);
  const limitUnits = Math.ceil(input.limitUsd * 10_000);
  if (
    !Number.isSafeInteger(amountUnits) ||
    !Number.isSafeInteger(limitUnits) ||
    amountUnits <= 0 ||
    limitUnits <= 0
  ) {
    return { allowed: false, replayed: false, remainingUsd: 0 };
  }
  const day = new Date().toISOString().slice(0, 10);
  const key = `${day}:${input.tenantId}:${input.agentId}`;
  let bucket = memoryAdapterBuckets.get(key);
  if (!bucket) {
    if (memoryAdapterBuckets.size >= MAX_MEMORY_ADAPTER_BUCKETS) {
      for (const candidate of memoryAdapterBuckets.keys()) {
        if (!candidate.startsWith(`${day}:`)) memoryAdapterBuckets.delete(candidate);
      }
      if (memoryAdapterBuckets.size >= MAX_MEMORY_ADAPTER_BUCKETS) {
        return { allowed: false, replayed: false, remainingUsd: 0 };
      }
    }
    bucket = { units: 0, markers: new Map() };
    memoryAdapterBuckets.set(key, bucket);
  }
  const prior = bucket.markers.get(input.reservationId);
  if (prior !== undefined) {
    return prior === input.requestDigest
      ? {
          allowed: true,
          replayed: true,
          remainingUsd: Math.max(0, (limitUnits - bucket.units) / 10_000),
        }
      : { allowed: false, replayed: false, conflict: true, remainingUsd: 0 };
  }
  if (
    bucket.markers.size >= MAX_MEMORY_ADAPTER_RESERVATIONS_PER_BUCKET ||
    amountUnits > limitUnits - bucket.units
  ) {
    return {
      allowed: false,
      replayed: false,
      remainingUsd: Math.max(0, (limitUnits - bucket.units) / 10_000),
    };
  }
  bucket.units += amountUnits;
  bucket.markers.set(input.reservationId, input.requestDigest);
  return {
    allowed: true,
    replayed: false,
    remainingUsd: Math.max(0, (limitUnits - bucket.units) / 10_000),
  };
}

/**
 * Try to connect to Redis on startup. If it fails, route-level helpers decide
 * whether to use local-development defaults or fail closed based on whether
 * Redis was configured for this deployment.
 */
export async function initRedis(env?: Record<string, unknown>): Promise<boolean> {
  const binding = redisBinding(env);
  if (!binding) {
    const expected =
      valueFrom(env, "REDIS_DRIVER")?.trim().toLowerCase() === "upstash"
        ? "KV_REST_API_URL/KV_REST_API_TOKEN"
        : "REDIS_URL";
    console.log(`[steward:redis] ${expected} not set — Redis enforcement disabled`);
    return false;
  }
  const key = redisBindingKey(binding);
  if (redisClients.has(key)) return true;
  const pending = redisInitializations.get(key);
  if (pending) return pending;
  if (redisClients.size + redisInitializations.size >= MAX_REDIS_BINDING_GENERATIONS) {
    console.warn("[steward:redis] Redis binding generation limit reached; refusing new client");
    return false;
  }
  const initialization = (async () => {
    let client: IoredisLike | null = null;
    try {
      client = createRedisClient(redisClientEnvironment(binding));
      await client.ping();
      redisClients.set(key, client);
      console.log("[steward:redis] Redis connected — rate limiting and spend tracking enabled");
      return true;
    } catch (err) {
      if (client && "quit" in client && typeof client.quit === "function") {
        await client.quit().catch(() => undefined);
      }
      console.warn(
        "[steward:redis] Failed to connect — Redis enforcement disabled",
        redactedThrownDiagnostics(err),
      );
      return false;
    } finally {
      redisInitializations.delete(key);
    }
  })();
  redisInitializations.set(key, initialization);
  return initialization;
}

export function isRedisAvailable(): boolean {
  return getRedisClient() !== null;
}

export function isRedisConfigured(): boolean {
  return redisBinding() !== null;
}

/**
 * Return the active Redis client (real ioredis or upstash adapter), or null
 * if Redis is not available. Call isRedisAvailable() first to check.
 */
export function getRedisClient(): IoredisLike | null {
  const binding = redisBinding();
  return binding ? (redisClients.get(redisBindingKey(binding)) ?? null) : null;
}

// Package helpers that have not yet grown an explicit client parameter must
// still inherit immutable request authority, never the process singleton.
setRedisClientResolverForRuntime(() => getRedisClient());

export async function shutdownRedis(): Promise<void> {
  const clients = [...redisClients.values()];
  redisClients.clear();
  redisInitializations.clear();
  memoryAdapterBuckets.clear();
  await Promise.all(
    clients.map(async (client) => {
      if ("quit" in client && typeof client.quit === "function") {
        await client.quit().catch(() => undefined);
      }
    }),
  );
}

// ─── Rate-limit helpers (safe wrappers) ──────────────────────────────────────

const PERMISSIVE_RATE_LIMIT: RateLimitResult = {
  allowed: true,
  remaining: Infinity,
  resetMs: 0,
};

function permitsUnconfiguredMemoryPosture(): boolean {
  const nodeEnv = runtimeEnvironmentValue("NODE_ENV");
  return (
    runtimeEnvironmentValue("STEWARD_RUNTIME") !== "workers" &&
    (nodeEnv === "development" || nodeEnv === "test")
  );
}

/** True when any mounted money-path limiter must have shared durable state. */
export function redisEnforcementRequiresDurability(): boolean {
  return !permitsUnconfiguredMemoryPosture();
}

/**
 * Check rate limit for an agent's vault signing requests.
 *
 * Key format: ratelimit:vault:{agentId}:{windowMs}:{maxRequests}
 */
export async function checkAgentRateLimit(
  agentId: string,
  windowMs: number,
  maxRequests: number,
): Promise<RateLimitResult> {
  // Redis not available: only skip enforcement when Redis was never configured
  // (documented dev path). If Redis IS configured (production), an unavailable
  // backend must fail CLOSED — mirroring checkAgentSpendLimit (SEC-016).
  const client = getRedisClient();
  if (!client) {
    if (!isRedisConfigured() && permitsUnconfiguredMemoryPosture()) return PERMISSIVE_RATE_LIMIT;
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }

  try {
    const key = `ratelimit:vault:${agentId}:${windowMs}:${maxRequests}`;
    return await checkRateLimit(key, windowMs, maxRequests, client);
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
 * Key format: ratelimit:proxy:{agentId}:{host}:{windowMs}:{maxRequests}
 */
export async function checkProxyRateLimit(
  agentId: string,
  host: string,
  windowMs: number,
  maxRequests: number,
): Promise<RateLimitResult> {
  // Same fail-closed posture as checkAgentRateLimit (SEC-016): permissive only
  // when Redis was never configured; a configured-but-down backend denies.
  const client = getRedisClient();
  if (!client) {
    if (!isRedisConfigured() && permitsUnconfiguredMemoryPosture()) return PERMISSIVE_RATE_LIMIT;
    return { allowed: false, remaining: 0, resetMs: 60_000 };
  }

  try {
    const key = `ratelimit:proxy:${agentId}:${host}:${windowMs}:${maxRequests}`;
    return await checkRateLimit(key, windowMs, maxRequests, client);
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
  // Resolve authority from the immutable request snapshot before consulting
  // process-global connection state. A Worker request without Redis bindings
  // must never inherit a client initialized by a previous request.
  if (!isRedisConfigured()) {
    if (permitsUnconfiguredMemoryPosture()) {
      return { allowed: true, spent: 0, remaining: limitUsd };
    }
    return { allowed: false, spent: 0, remaining: 0 };
  }

  // The current request expects durable enforcement, but the configured client
  // was absent or failed to initialize. Deny rather than assume zero spend.
  const client = getRedisClient();
  if (!client) return { allowed: false, spent: 0, remaining: 0 };

  try {
    return await checkSpendLimit(agentId, limitUsd, period, client);
  } catch (err) {
    // Configured backend threw: fail CLOSED — we cannot prove the spend is within limit.
    console.error(
      "[steward:redis] Spend limit check failed, denying request (fail-closed)",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, spent: 0, remaining: 0 };
  }
}

export async function reserveAgentDailySpend(input: {
  agentId: string;
  tenantId: string;
  amountUsd: number;
  limitUsd: number;
  reservationId: string;
  requestDigest: string;
}): Promise<{ allowed: boolean; replayed: boolean; conflict?: boolean; remainingUsd: number }> {
  const client = getRedisClient();
  if (!client) {
    if (!isRedisConfigured() && permitsUnconfiguredMemoryPosture()) {
      // Explicit development/test uses the same cap/idempotency semantics in a
      // bounded process-local store; unknown/staging/Workers never reach it.
      return reserveMemoryAdapterSpend(input);
    }
    return { allowed: false, replayed: false, remainingUsd: 0 };
  }
  try {
    return await reserveDailySpendIdempotently(
      input.agentId,
      input.tenantId,
      input.amountUsd,
      input.limitUsd,
      input.reservationId,
      input.requestDigest,
      client,
    );
  } catch (err) {
    console.error(
      "[steward:redis] Spend reservation failed, denying request (fail-closed)",
      redactedThrownDiagnostics(err),
    );
    return { allowed: false, replayed: false, remainingUsd: 0 };
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
  const client = getRedisClient();
  if (!client) {
    if (options.throwOnError && (isRedisConfigured() || !permitsUnconfiguredMemoryPosture())) {
      throw new Error("Configured Redis spend backend is unavailable");
    }
    return;
  }
  if (costUsd <= 0) return;

  try {
    await recordSpend(agentId, tenantId, costUsd, host, options, client);
  } catch (err) {
    if (options.throwOnError) throw err;
    console.error("[steward:redis] Failed to record spend", redactedThrownDiagnostics(err));
  }
}

// Re-export cost estimator for proxy use
export { estimateCost } from "@stwd/redis";

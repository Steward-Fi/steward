/**
 * Redis-backed rate limiting and spend tracking for the proxy gateway.
 *
 * Checks per-agent rate limits before forwarding requests and records
 * API costs after receiving responses (using the cost estimator).
 */

import { getDb, policies } from "@stwd/db";
import {
  checkRateLimit,
  checkSpendLimit,
  disconnectRedis,
  estimateCost,
  getPricingTable,
  getRedis,
  isKnownHost,
  type RateLimitResult,
  recordSpend,
  reserveSpend,
  type SpendPeriod,
  type SpendReservation,
  settleReservedSpend,
} from "@stwd/redis";
import { and, eq } from "drizzle-orm";

// ─── State ───────────────────────────────────────────────────────────────────

let redisAvailable = false;

/**
 * Initialize Redis for the proxy. Production enforcement fails closed unless
 * an explicit soft-fail override is configured for compatibility.
 */
export async function initProxyRedis(): Promise<boolean> {
  const url = process.env.REDIS_URL;
  if (!url) {
    redisAvailable = false;
    console.log("[proxy:redis] REDIS_URL not set — Redis enforcement disabled");
    return false;
  }

  try {
    const client = getRedis();
    await client.ping();
    redisAvailable = true;
    console.log("[proxy:redis] Redis connected — rate limiting and spend tracking enabled");
    return true;
  } catch (err) {
    redisAvailable = false;
    console.warn("[proxy:redis] Failed to connect:", (err as Error).message);
    return false;
  }
}

export function isProxyRedisAvailable(): boolean {
  return redisAvailable;
}

export async function shutdownProxyRedis(): Promise<void> {
  if (redisAvailable) {
    await disconnectRedis();
    redisAvailable = false;
  }
}

// ─── Default rate limits for proxy (per-agent per-host) ──────────────────────

const DEFAULT_PROXY_RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const DEFAULT_PROXY_RATE_LIMIT_MAX = 60; // 60 requests/minute per agent per host

const PERMISSIVE: RateLimitResult = {
  allowed: true,
  remaining: Infinity,
  resetMs: 0,
};

function isRedisRequired(): boolean {
  return (
    process.env.REDIS_REQUIRED === "true" ||
    (process.env.NODE_ENV === "production" &&
      process.env.STEWARD_ALLOW_PROXY_REDIS_SOFT_FAIL !== "true")
  );
}

/**
 * Check rate limit for a proxy request.
 * Uses a per-agent, per-host sliding window.
 */
export async function checkProxyRateLimit(
  agentId: string,
  host: string,
  windowMs: number = DEFAULT_PROXY_RATE_LIMIT_WINDOW_MS,
  maxRequests: number = DEFAULT_PROXY_RATE_LIMIT_MAX,
): Promise<RateLimitResult> {
  if (!redisAvailable) {
    if (isRedisRequired()) {
      return {
        allowed: false,
        remaining: 0,
        resetMs: windowMs,
      };
    }
    return PERMISSIVE;
  }

  try {
    const key = `ratelimit:proxy:${agentId}:${host}:${windowMs}`;
    return await checkRateLimit(key, windowMs, maxRequests);
  } catch (err) {
    console.error("[proxy:redis] Rate limit check failed:", (err as Error).message);
    if (isRedisRequired()) {
      return {
        allowed: false,
        remaining: 0,
        resetMs: windowMs,
      };
    }
    return PERMISSIVE;
  }
}

/**
 * Estimate and record spend for a proxied API call.
 *
 * Should be called after receiving the upstream response.
 * Only tracks costs for known LLM hosts (OpenAI, Anthropic).
 *
 * @param agentId - The agent making the request
 * @param tenantId - The agent's tenant
 * @param host - The target API host
 * @param requestBody - The parsed request body (for model detection)
 * @param responseBody - The parsed response body (for token usage)
 */
export async function trackProxySpend(
  agentId: string,
  tenantId: string,
  host: string,
  requestBody: any,
  responseBody: any,
  reservation?: SpendReservation,
): Promise<number> {
  if (!redisAvailable) return 0;
  if (!isKnownHost(host)) return 0;

  try {
    const cost = estimateCost(host, requestBody, responseBody);
    if (reservation && reservation.reservedUsd > 0) {
      await settleReservedSpend(
        agentId,
        tenantId,
        reservation.reservedUsd,
        cost > 0 ? cost : reservation.reservedUsd,
        host,
        reservation.periods,
        reservation.buckets,
      );
    } else if (cost > 0) {
      await recordSpend(agentId, tenantId, cost, host);
    }
    return cost;
  } catch (err) {
    console.error("[proxy:redis] Spend tracking failed:", (err as Error).message);
    return 0;
  }
}

function findPricing(model: string): { input: number; output: number } | null {
  const table = getPricingTable();
  if (table[model]) return table[model]!;
  for (const key of Object.keys(table)) {
    if (model.startsWith(key)) return table[key]!;
  }
  return null;
}

function finitePositiveInteger(value: unknown): number | null {
  if (value === undefined || value === null || value === "") return null;
  const n = Number(value);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

function containsUnsupportedMeteredInput(value: unknown): boolean {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => containsUnsupportedMeteredInput(item));

  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey === "image_url" ||
      lowerKey === "input_image" ||
      lowerKey === "input_audio" ||
      lowerKey === "file_id"
    ) {
      return true;
    }
    if (
      lowerKey === "media_type" &&
      typeof child === "string" &&
      /^(image|audio|video)\//i.test(child)
    ) {
      return true;
    }
    if (containsUnsupportedMeteredInput(child)) return true;
  }

  return false;
}

/**
 * Conservative upper-bound estimate for a spend-limited LLM request.
 *
 * This intentionally requires a max token cap. Without one, the proxy cannot
 * reserve a bounded amount before forwarding the request.
 */
export function estimateProxyLlmReservationUsd(host: string, requestBody: any): number | null {
  if (!isKnownHost(host)) return null;
  if (containsUnsupportedMeteredInput(requestBody)) return null;
  const model = typeof requestBody?.model === "string" ? requestBody.model : "";
  if (!model) return null;
  const pricing = findPricing(model);
  if (!pricing) return null;

  const maxOutputTokens =
    finitePositiveInteger(requestBody?.max_tokens) ??
    finitePositiveInteger(requestBody?.max_completion_tokens);
  if (maxOutputTokens === null) return null;
  const choices = finitePositiveInteger(requestBody?.n) ?? 1;
  if (choices !== 1) return null;

  const serialized = JSON.stringify(requestBody ?? {});
  const estimatedInputTokens = new TextEncoder().encode(serialized).byteLength;
  const cost =
    (estimatedInputTokens / 1000) * pricing.input + (maxOutputTokens / 1000) * pricing.output;
  return Math.ceil(cost * 1_000_000) / 1_000_000;
}

interface ProxySpendLimits {
  perRequest?: number;
  day?: number;
  week?: number;
  month?: number;
}

export interface ProxySpendLimitResult {
  allowed: boolean;
  /** False when no enabled spend-limit policy with USD API budget is configured. */
  configured: boolean;
  period?: SpendPeriod;
  limit?: number;
  spent: number;
  remaining: number;
  reason?: string;
}

export interface ProxySpendReservationResult {
  allowed: boolean;
  configured: boolean;
  reservation?: SpendReservation;
  reserveUsd: number;
  reason?: string;
}

const NO_SPEND_POLICY: ProxySpendLimitResult = {
  allowed: true,
  configured: false,
  spent: 0,
  remaining: Infinity,
};

function toPositiveNumber(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

export function extractProxySpendLimits(config: Record<string, unknown>): ProxySpendLimits {
  return {
    perRequest: toPositiveNumber(
      config.maxPerTxUsd ??
        config.maxPerRequestUsd ??
        config.proxyPerRequestLimitUsd ??
        config.apiPerRequestLimitUsd,
    ),
    day: toPositiveNumber(
      config.dailyLimitUsd ??
        config.maxPerDayUsd ??
        config.maxDailyUsd ??
        config.proxyDailyLimitUsd ??
        config.apiDailyLimitUsd,
    ),
    week: toPositiveNumber(
      config.weeklyLimitUsd ??
        config.maxPerWeekUsd ??
        config.maxWeeklyUsd ??
        config.proxyWeeklyLimitUsd ??
        config.apiWeeklyLimitUsd,
    ),
    month: toPositiveNumber(
      config.monthlyLimitUsd ??
        config.maxPerMonthUsd ??
        config.maxMonthlyUsd ??
        config.proxyMonthlyLimitUsd ??
        config.apiMonthlyLimitUsd,
    ),
  };
}

function hasCumulativeProxySpendLimits(limits: ProxySpendLimits): boolean {
  return limits.day !== undefined || limits.week !== undefined || limits.month !== undefined;
}

async function getConfiguredProxySpendLimits(agentId: string): Promise<ProxySpendLimits | null> {
  const db = getDb();
  const rows = await db
    .select({ config: policies.config })
    .from(policies)
    .where(
      and(
        eq(policies.agentId, agentId),
        eq(policies.type, "spending-limit"),
        eq(policies.enabled, true),
      ),
    );

  const merged: ProxySpendLimits = {};
  for (const row of rows) {
    const limits = extractProxySpendLimits(row.config as Record<string, unknown>);
    if (limits.perRequest !== undefined) {
      merged.perRequest = Math.min(merged.perRequest ?? Infinity, limits.perRequest);
    }
    if (limits.day !== undefined) merged.day = Math.min(merged.day ?? Infinity, limits.day);
    if (limits.week !== undefined) merged.week = Math.min(merged.week ?? Infinity, limits.week);
    if (limits.month !== undefined) merged.month = Math.min(merged.month ?? Infinity, limits.month);
  }

  return merged.perRequest !== undefined ||
    merged.day !== undefined ||
    merged.week !== undefined ||
    merged.month !== undefined
    ? merged
    : null;
}

/**
 * Check if an agent has exceeded their proxy API spend budget.
 *
 * Looks up enabled spending-limit policies for the agent and enforces USD API
 * budgets when present. On-chain wei policies are ignored for proxy API spend.
 *
 * Backward-compatible helper form: checkProxySpendLimit(agentId, dailyLimitUsd).
 */
export async function checkProxySpendLimit(
  agentId: string,
  tenantIdOrDailyLimit?: string | number,
  host?: string,
): Promise<ProxySpendLimitResult> {
  let limits: ProxySpendLimits | null;
  if (typeof tenantIdOrDailyLimit === "number") {
    limits = tenantIdOrDailyLimit > 0 ? { day: tenantIdOrDailyLimit } : null;
  } else {
    limits = await getConfiguredProxySpendLimits(agentId);
  }

  if (!limits) return NO_SPEND_POLICY;
  if (!hasCumulativeProxySpendLimits(limits)) {
    return {
      allowed: true,
      configured: true,
      limit: limits.perRequest ?? 0,
      spent: 0,
      remaining: limits.perRequest ?? Infinity,
    };
  }

  const firstLimit = limits.perRequest ?? limits.day ?? limits.week ?? limits.month ?? 0;
  const firstPeriod =
    limits.day !== undefined ? "day" : limits.week !== undefined ? "week" : "month";
  if (!redisAvailable) {
    const message = `[proxy:redis] Redis unavailable while checking spend limit for agent=${agentId}${host ? ` host=${host}` : ""}`;
    if (isRedisRequired()) {
      console.error(`${message}; REDIS_REQUIRED=true, failing closed`);
      return {
        allowed: false,
        configured: true,
        period: firstPeriod,
        limit: firstLimit,
        spent: 0,
        remaining: 0,
        reason: "Redis unavailable; spend-limit enforcement is required",
      };
    }

    console.error(`${message}; spend limits are configured, failing closed`);
    return {
      allowed: false,
      configured: true,
      period: firstPeriod,
      limit: firstLimit,
      spent: 0,
      remaining: 0,
      reason: "Redis unavailable; spend-limit enforcement is required",
    };
  }

  try {
    let lastAllowed: ProxySpendLimitResult | null = null;
    for (const period of ["day", "week", "month"] as const) {
      const limit = limits[period];
      if (limit === undefined) continue;
      const result = await checkSpendLimit(agentId, limit, period);
      lastAllowed = {
        allowed: true,
        configured: true,
        period,
        limit,
        spent: result.spent,
        remaining: result.remaining,
      };
      if (!result.allowed) {
        return {
          allowed: false,
          configured: true,
          period,
          limit,
          spent: result.spent,
          remaining: result.remaining,
          reason: `${period === "day" ? "Daily" : period === "week" ? "Weekly" : "Monthly"} proxy spend limit exceeded for ${host ?? "host"}: spent $${result.spent.toFixed(4)} of $${limit.toFixed(4)}`,
        };
      }
    }

    return (
      lastAllowed ?? {
        allowed: true,
        configured: true,
        limit: firstLimit,
        spent: 0,
        remaining: firstLimit,
      }
    );
  } catch (err) {
    console.error("[proxy:redis] Spend limit check failed:", (err as Error).message);
    if (isRedisRequired()) {
      return {
        allowed: false,
        configured: true,
        period: firstPeriod,
        limit: firstLimit,
        spent: 0,
        remaining: 0,
        reason: "Redis spend-limit check failed; REDIS_REQUIRED=true",
      };
    }

    return {
      allowed: false,
      configured: true,
      period: firstPeriod,
      limit: firstLimit,
      spent: 0,
      remaining: 0,
      reason: "Redis spend-limit check failed; spend-limit enforcement is required",
    };
  }
}

/**
 * Reserve spend for an in-flight proxy request. This prevents concurrent LLM
 * calls from all passing a preflight check against the same remaining budget.
 */
export async function reserveProxySpendLimit(
  agentId: string,
  tenantId: string,
  host: string,
  reserveUsd: number,
): Promise<ProxySpendReservationResult> {
  const limits = await getConfiguredProxySpendLimits(agentId);
  if (!limits) return { allowed: true, configured: false, reserveUsd };

  if (limits.perRequest !== undefined && reserveUsd > limits.perRequest) {
    return {
      allowed: false,
      configured: true,
      reserveUsd,
      reason: `Proxy per-request spend limit exceeded for ${host}: requested $${reserveUsd.toFixed(4)} of $${limits.perRequest.toFixed(4)}`,
    };
  }

  if (!hasCumulativeProxySpendLimits(limits)) {
    return { allowed: true, configured: true, reserveUsd };
  }

  if (!redisAvailable) {
    return {
      allowed: false,
      configured: true,
      reserveUsd,
      reason: "Redis unavailable; spend-limit enforcement is required",
    };
  }

  try {
    const reservation = await reserveSpend(agentId, tenantId, reserveUsd, limits);
    return { allowed: true, configured: true, reserveUsd, reservation };
  } catch (err) {
    const reason =
      err instanceof Error
        ? err.message
        : `Proxy spend reservation exceeded for ${host}: requested $${reserveUsd.toFixed(4)}`;
    return { allowed: false, configured: true, reserveUsd, reason };
  }
}

/**
 * Redis-backed rate limiting and spend tracking for the proxy gateway.
 *
 * Checks per-agent rate limits before forwarding requests and records
 * API costs after receiving responses (using the cost estimator).
 */

import {
  checkRateLimit,
  checkSpendLimit,
  disconnectRedis,
  estimateCost,
  getRedis,
  isKnownHost,
  type RateLimitResult,
  recordSpend,
  type SpendPeriod,
} from "@stwd/redis";
import { getDb, policies } from "@stwd/db";
import { and, eq } from "drizzle-orm";

// ─── State ───────────────────────────────────────────────────────────────────

let redisAvailable = false;

/**
 * Initialize Redis for the proxy. Non-blocking — proxy works without Redis.
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
    console.log(
      "[proxy:redis] Redis connected — rate limiting and spend tracking enabled",
    );
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
  return process.env.REDIS_REQUIRED === "true";
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
  if (!redisAvailable) return PERMISSIVE;

  try {
    const key = `ratelimit:proxy:${agentId}:${host}:${windowMs}`;
    return await checkRateLimit(key, windowMs, maxRequests);
  } catch (err) {
    console.error(
      "[proxy:redis] Rate limit check failed:",
      (err as Error).message,
    );
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
): Promise<number> {
  if (!redisAvailable) return 0;
  if (!isKnownHost(host)) return 0;

  try {
    const cost = estimateCost(host, requestBody, responseBody);
    if (cost > 0) {
      await recordSpend(agentId, tenantId, cost, host);
    }
    return cost;
  } catch (err) {
    console.error(
      "[proxy:redis] Spend tracking failed:",
      (err as Error).message,
    );
    return 0;
  }
}

interface ProxySpendLimits {
  day?: number;
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

function extractProxySpendLimits(
  config: Record<string, unknown>,
): ProxySpendLimits {
  return {
    day: toPositiveNumber(
      config.dailyLimitUsd ??
        config.maxPerDayUsd ??
        config.maxDailyUsd ??
        config.proxyDailyLimitUsd ??
        config.apiDailyLimitUsd,
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

async function getConfiguredProxySpendLimits(
  agentId: string,
): Promise<ProxySpendLimits | null> {
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
    const limits = extractProxySpendLimits(
      row.config as Record<string, unknown>,
    );
    if (limits.day !== undefined)
      merged.day = Math.min(merged.day ?? Infinity, limits.day);
    if (limits.month !== undefined)
      merged.month = Math.min(merged.month ?? Infinity, limits.month);
  }

  return merged.day !== undefined || merged.month !== undefined ? merged : null;
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

  const firstLimit = limits.day ?? limits.month ?? 0;
  if (!redisAvailable) {
    const message = `[proxy:redis] Redis unavailable while checking spend limit for agent=${agentId}${host ? ` host=${host}` : ""}`;
    if (isRedisRequired()) {
      console.error(`${message}; REDIS_REQUIRED=true, failing closed`);
      return {
        allowed: false,
        configured: true,
        period: limits.day !== undefined ? "day" : "month",
        limit: firstLimit,
        spent: 0,
        remaining: 0,
        reason: "Redis unavailable; spend-limit enforcement is required",
      };
    }

    console.warn(`${message}; REDIS_REQUIRED=false, allowing request`);
    return {
      allowed: true,
      configured: true,
      limit: firstLimit,
      spent: 0,
      remaining: firstLimit,
    };
  }

  try {
    let lastAllowed: ProxySpendLimitResult | null = null;
    for (const period of ["day", "month"] as const) {
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
          reason: `${period === "day" ? "Daily" : "Monthly"} proxy spend limit exceeded for ${host ?? "host"}: spent $${result.spent.toFixed(4)} of $${limit.toFixed(4)}`,
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
    console.error(
      "[proxy:redis] Spend limit check failed:",
      (err as Error).message,
    );
    if (isRedisRequired()) {
      return {
        allowed: false,
        configured: true,
        period: limits.day !== undefined ? "day" : "month",
        limit: firstLimit,
        spent: 0,
        remaining: 0,
        reason: "Redis spend-limit check failed; REDIS_REQUIRED=true",
      };
    }

    console.warn(
      "[proxy:redis] REDIS_REQUIRED=false, allowing request after spend limit check failure",
    );
    return {
      allowed: true,
      configured: true,
      limit: firstLimit,
      spent: 0,
      remaining: firstLimit,
    };
  }
}

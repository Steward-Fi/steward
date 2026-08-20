/**
 * Per-agent rate limiting for capability invoke/OpenAI-adapter and manifest
 * issuance. Redis remains the preferred sliding-window backend. When Redis was
 * never configured, production uses a plugin-owned Postgres bucket whose row
 * lock is the cross-replica reservation boundary. Process memory is available
 * only in explicit development/test posture.
 */

import { checkRateLimit } from "@stwd/redis";
import { sql } from "drizzle-orm";
import type { StewardAppContext } from "./context";

/** invoke + OpenAI-adapter calls: 60 per agent per minute. */
export const CAPABILITY_INVOKE_RATE_LIMIT = { windowMs: 60_000, maxRequests: 60 } as const;
/** manifest issue/renew: 30 per agent per minute (renewal is minute-scale by design). */
export const CAPABILITY_ISSUE_RATE_LIMIT = { windowMs: 60_000, maxRequests: 30 } as const;

const RATE_LIMITS = {
  invoke: CAPABILITY_INVOKE_RATE_LIMIT,
  issue: CAPABILITY_ISSUE_RATE_LIMIT,
} as const;

export type CapabilityRateSurface = keyof typeof RATE_LIMITS;

const memoryBuckets = new Map<string, { reservations: number[] }>();

export interface CapabilityRateResult {
  allowed: boolean;
  resetMs: number;
}

type CapabilityRateContext = Pick<StewardAppContext, "db" | "getRedisClient"> &
  Partial<Pick<StewardAppContext, "isRedisConfigured" | "withCapabilityTenantDatabase">>;

function rowsFromExecute<T>(result: unknown): T[] {
  return (
    Array.isArray(result) ? result : ((result as { rows?: unknown[] } | null)?.rows ?? [])
  ) as T[];
}

function redisConfiguredFromEnvironment(): boolean {
  const driver = process.env.REDIS_DRIVER?.trim().toLowerCase() || "ioredis";
  if (driver === "upstash") {
    return Boolean(
      (process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL) &&
        (process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN),
    );
  }
  return Boolean(process.env.REDIS_URL);
}

function explicitMemoryPosture(): boolean {
  return process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";
}

function reserveMemory(key: string, windowMs: number, maxRequests: number): CapabilityRateResult {
  const now = Date.now();
  const threshold = now - windowMs;
  const reservations = (memoryBuckets.get(key)?.reservations ?? []).filter(
    (reservedAt) => reservedAt > threshold,
  );
  if (reservations.length >= maxRequests) {
    return { allowed: false, resetMs: Math.max(1, reservations[0]! + windowMs - now) };
  }
  reservations.push(now);
  memoryBuckets.set(key, { reservations });
  return { allowed: true, resetMs: Math.max(1, reservations[0]! + windowMs - now) };
}

async function reservePostgres(
  ctx: Pick<StewardAppContext, "db">,
  key: { tenantId: string; agentId: string; surface: CapabilityRateSurface },
  windowMs: number,
  maxRequests: number,
): Promise<CapabilityRateResult> {
  // One statement is the complete reservation boundary. ON CONFLICT locks the
  // identity row, and its WHERE clause evaluates only after the prior writer
  // commits. This works both on a direct Postgres connection and inside an
  // already-open tenant/RLS transaction; it does not depend on nested
  // transaction support from a particular Drizzle driver.
  const [result] = rowsFromExecute<{ allowed: boolean; reset_ms: number | string }>(
    await ctx.db.execute(sql`
      WITH clock AS MATERIALIZED (
        SELECT clock_timestamp() AS now
      ), attempted AS (
        INSERT INTO public.capability_rate_limit_buckets (
          tenant_id,
          agent_id,
          surface,
          reservations,
          updated_at
        )
        SELECT
          ${key.tenantId},
          ${key.agentId},
          ${key.surface},
          ARRAY[clock.now]::timestamptz[],
          clock.now
        FROM clock
        ON CONFLICT (tenant_id, agent_id, surface) DO UPDATE
        SET
          reservations = ARRAY(
            SELECT reserved_at
            FROM (
              SELECT reserved_at
              FROM unnest(capability_rate_limit_buckets.reservations) AS reserved_at
              WHERE reserved_at >
                (SELECT now FROM clock) - (${windowMs}::double precision * interval '1 millisecond')
              UNION ALL
              SELECT now FROM clock
            ) AS live_reservations
            ORDER BY reserved_at
          ),
          updated_at = (SELECT now FROM clock)
        WHERE (
          SELECT count(*)
          FROM unnest(capability_rate_limit_buckets.reservations) AS reserved_at
          WHERE reserved_at >
            (SELECT now FROM clock) - (${windowMs}::double precision * interval '1 millisecond')
        ) < ${maxRequests}
        RETURNING reservations
      ), state AS (
        SELECT true AS allowed, reservations
        FROM attempted
        UNION ALL
        SELECT false AS allowed, bucket.reservations
        FROM public.capability_rate_limit_buckets AS bucket
        WHERE bucket.tenant_id = ${key.tenantId}
          AND bucket.agent_id = ${key.agentId}
          AND bucket.surface = ${key.surface}
          AND NOT EXISTS (SELECT 1 FROM attempted)
      )
      SELECT
        state.allowed,
        greatest(
          1,
          extract(epoch FROM (
            (SELECT min(reserved_at) FROM unnest(state.reservations) AS reserved_at)
              + (${windowMs}::double precision * interval '1 millisecond')
              - clock.now
          )) * 1000
        )::bigint AS reset_ms
      FROM state
      CROSS JOIN clock
    `),
  );
  const resetMs = Number(result?.reset_ms);
  if (!result || !Number.isFinite(resetMs)) {
    throw new Error("capability rate-limit reservation unavailable");
  }
  return { allowed: result.allowed, resetMs };
}

/**
 * Atomically reserve one request before any invocation/audit/upstream work.
 * Configured Redis errors deny. Redis-absent production reserves in Postgres.
 * Only explicit NODE_ENV=test/development may use process memory.
 */
export async function enforceCapabilityRateLimit(
  ctx: CapabilityRateContext,
  surface: CapabilityRateSurface,
  tenantId: string,
  agentId: string,
): Promise<CapabilityRateResult> {
  const { windowMs, maxRequests } = RATE_LIMITS[surface];
  const key = `ratelimit:capability:${surface}:${tenantId}:${agentId}:${windowMs}`;

  if (ctx.getRedisClient()) {
    try {
      const result = await checkRateLimit(key, windowMs, maxRequests);
      return { allowed: result.allowed, resetMs: result.resetMs };
    } catch {
      return { allowed: false, resetMs: windowMs };
    }
  }

  // A configured backend that failed startup must never be reclassified as
  // "Redis absent" and silently fall through to Postgres or process memory.
  if ((ctx.isRedisConfigured?.() ?? redisConfiguredFromEnvironment()) === true) {
    return { allowed: false, resetMs: windowMs };
  }

  if (explicitMemoryPosture()) return reserveMemory(key, windowMs, maxRequests);

  try {
    if (!ctx.withCapabilityTenantDatabase) {
      throw new Error("tenant-bound capability database is unavailable");
    }
    return await ctx.withCapabilityTenantDatabase(tenantId, (tenantDb) =>
      reservePostgres({ db: tenantDb }, { tenantId, agentId, surface }, windowMs, maxRequests),
    );
  } catch {
    // Missing migration, database outage, lock/statement timeout, or malformed
    // persisted state all deny. The route cannot write an invocation row after
    // this result because it returns before dispatch.
    return { allowed: false, resetMs: windowMs };
  }
}

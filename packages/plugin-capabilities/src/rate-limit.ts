/**
 * Per-agent rate limiting for capability invoke/OpenAI-adapter and manifest
 * issuance. Bun prefers Redis and uses a plugin-owned Postgres bucket when
 * Redis was never configured. Workers always use that request-owned Postgres
 * boundary so overlapping binding generations cannot share isolate authority.
 * Process memory is available only in explicit non-Worker development/test
 * posture.
 */

import { checkRateLimit } from "@stwd/redis";
import { runtimeEnvironmentValue } from "@stwd/shared/runtime-env";
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

function workersRuntime(): boolean {
  return (
    runtimeEnvironmentValue("STEWARD_RUNTIME") === "workers" ||
    (typeof navigator !== "undefined" && navigator.userAgent === "Cloudflare-Workers")
  );
}

function explicitMemoryPosture(): boolean {
  const nodeEnvironment = runtimeEnvironmentValue("NODE_ENV");
  return !workersRuntime() && (nodeEnvironment === "development" || nodeEnvironment === "test");
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
 * Configured Redis errors deny on Bun. Redis-absent production and every Worker
 * invocation reserve in Postgres. Only explicit non-Worker
 * NODE_ENV=test/development may use process memory.
 */
export async function enforceCapabilityRateLimit(
  ctx: CapabilityRateContext,
  surface: CapabilityRateSurface,
  tenantId: string,
  agentId: string,
): Promise<CapabilityRateResult> {
  const { windowMs, maxRequests } = RATE_LIMITS[surface];
  const key = `ratelimit:capability:${surface}:${tenantId}:${agentId}:${windowMs}`;

  // A Worker invocation always has a request-owned transactional database but
  // the legacy Redis bridge remains isolate-global until the general Redis
  // authority lane lands. Use the tenant-RLS Postgres bucket on Workers so an
  // overlapping binding rotation/removal can never borrow another request's
  // URL, credential, client, or reservation namespace.
  if (!workersRuntime()) {
    const redisClient = ctx.getRedisClient();
    if (redisClient) {
      try {
        const result = await checkRateLimit(key, windowMs, maxRequests, redisClient);
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
  }

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

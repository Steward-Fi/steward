/**
 * rate-limit.ts — per-agent rate limiting for the agent-facing capability
 * surface (invoke / OpenAI adapter / manifest issuance). Trade orders have
 * `enforceOrderRateLimit`; the capability routes had NO throttle beyond the
 * optional operator-configured `maxCallsPerHour` policy rule, so an agent
 * could spam invocations (a DB write per attempt + upstream calls with
 * credential injection). This mirrors the trade-order limiter's shape: a
 * Redis sliding window when the core reports Redis available, a per-process
 * memory bucket otherwise (the documented local-dev posture), and FAIL CLOSED
 * (deny) when the configured Redis path errors.
 */

import { checkRateLimit } from "@stwd/redis";
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

/** Process-local fallback buckets (mirrors the trade route's memory limiter). */
const memoryBuckets = new Map<string, { count: number; resetAt: number }>();

export interface CapabilityRateResult {
  allowed: boolean;
  resetMs: number;
}

/**
 * Check-and-increment the per-agent limit for a capability surface. Call BEFORE
 * any DB/upstream work so a flooded agent is turned away cheaply (and the 429
 * path does NOT write an invocation row — that write is the very vector being
 * throttled).
 */
export async function enforceCapabilityRateLimit(
  ctx: Pick<StewardAppContext, "getRedisClient">,
  surface: CapabilityRateSurface,
  agentId: string,
): Promise<CapabilityRateResult> {
  const { windowMs, maxRequests } = RATE_LIMITS[surface];
  const key = `ratelimit:capability:${surface}:${agentId}:${windowMs}`;

  if (ctx.getRedisClient()) {
    try {
      const result = await checkRateLimit(key, windowMs, maxRequests);
      return { allowed: result.allowed, resetMs: result.resetMs };
    } catch {
      // Fail CLOSED: Redis was configured but errored — deny rather than let a
      // flood through unthrottled.
      return { allowed: false, resetMs: windowMs };
    }
  }

  const now = Date.now();
  const current = memoryBuckets.get(key);
  if (!current || current.resetAt <= now) {
    memoryBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, resetMs: windowMs };
  }
  if (current.count >= maxRequests) return { allowed: false, resetMs: current.resetAt - now };
  current.count += 1;
  return { allowed: true, resetMs: current.resetAt - now };
}

/**
 * Sliding window rate limiter using Redis sorted sets.
 *
 * Uses MULTI/EXEC for atomic check-and-increment.
 * Keys auto-expire after the window passes.
 *
 * Key format: ratelimit:{key}
 * (Caller provides the full key, e.g. ratelimit:{agentId}:{host}:{window})
 */

import { randomUUID } from "node:crypto";
import { getRedis } from "./client.js";

// KEYS[1]=zset  ARGV: windowMs, maxRequests, member, ttlMs
// Prune the window, count, and add the member only if strictly under the
// limit (count < max → the Nth request is admitted, N+1 rejected). Done in one
// script so concurrent requests cannot collectively pass the ceiling. Redis
// TIME is the authority for every replica: an application host with a skewed
// clock cannot expire another replica's still-live reservations.
const RATE_LIMIT_LUA = `
local cleanup = ARGV[5] == '1'
local ok, result = pcall(function()
local redisTime = redis.call('TIME')
local now = (tonumber(redisTime[1]) * 1000) + math.floor(tonumber(redisTime[2]) / 1000)
local windowMs = tonumber(ARGV[1])
local windowStart = now - windowMs
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, windowStart)
local count = redis.call('ZCARD', KEYS[1])
local allowed = 0
if count < tonumber(ARGV[2]) then
  redis.call('ZADD', KEYS[1], now, ARGV[3])
  allowed = 1
  count = count + 1
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local oldestScore = now
if oldest[2] ~= nil then oldestScore = oldest[2] end
local resetMs = math.max(0, tonumber(oldestScore) + windowMs - now)
return {allowed, count, oldestScore, now, resetMs}
end)
if cleanup then redis.call('DEL', KEYS[1]) end
if not ok then return redis.error_reply(tostring(result)) end
return result
`;

const RATE_LIMIT_STATUS_LUA = `
local redisTime = redis.call('TIME')
local now = (tonumber(redisTime[1]) * 1000) + math.floor(tonumber(redisTime[2]) / 1000)
local windowMs = tonumber(ARGV[1])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - windowMs)
local count = redis.call('ZCARD', KEYS[1])
local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
local oldestScore = now
if oldest[2] ~= nil then oldestScore = oldest[2] end
local resetMs = math.max(0, tonumber(oldestScore) + windowMs - now)
return {count, oldestScore, now, resetMs}
`;

export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Remaining requests in the current window */
  remaining: number;
  /** Milliseconds until the window resets (oldest entry expires) */
  resetMs: number;
}

function validateRateLimitInput(key: string, windowMs: number, maxRequests: number): void {
  if (key.length === 0 || key.length > 512) {
    throw new RangeError("rate limit key must contain between 1 and 512 characters");
  }
  if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
    throw new RangeError("rate limit windowMs must be a positive safe integer");
  }
  if (!Number.isSafeInteger(maxRequests) || maxRequests <= 0) {
    throw new RangeError("rate limit maxRequests must be a positive safe integer");
  }
}

/**
 * Bind the durable bucket to the complete policy generation. Callers often
 * include the window in their logical key, but historically omitted the cap.
 * Reusing that bucket after a limit rotation lets the new policy inherit the
 * old generation's reservations (or, when loosening and later tightening,
 * reinterpret them). Keep the caller-facing key stable while fencing the
 * physical Redis key by both numeric policy inputs.
 */
export function rateLimitBucketKey(key: string, windowMs: number, maxRequests: number): string {
  return `${key}:policy:${windowMs}:${maxRequests}`;
}

/**
 * Check and increment a sliding window rate limit.
 *
 * Uses a sorted set where:
 * - Score = Redis server timestamp (ms)
 * - Member = unique request ID
 *
 * The window slides: we remove all entries older than (now - windowMs),
 * then count remaining entries to determine if under the limit.
 *
 * @param key - Rate limit key (e.g. "ratelimit:agent-123:api.openai.com:60000")
 * @param windowMs - Window size in milliseconds
 * @param maxRequests - Maximum requests allowed in the window
 */
export async function checkRateLimit(
  key: string,
  windowMs: number,
  maxRequests: number,
  client?: ReturnType<typeof getRedis>,
): Promise<RateLimitResult> {
  return executeRateLimit(key, windowMs, maxRequests, client ?? getRedis(), false);
}

/** Exercise the exact production rate-limit script but atomically remove the
 * isolated bucket before EVAL returns. This is safe under caller deadlines:
 * Redis may finish the script late, but it cannot publish a lingering probe
 * reservation after the timeout path has completed. */
export async function exerciseRateLimitReadiness(
  key: string,
  windowMs: number,
  maxRequests: number,
  client: ReturnType<typeof getRedis>,
): Promise<RateLimitResult> {
  return executeRateLimit(key, windowMs, maxRequests, client, true);
}

async function executeRateLimit(
  key: string,
  windowMs: number,
  maxRequests: number,
  redis: ReturnType<typeof getRedis>,
  cleanup: boolean,
): Promise<RateLimitResult> {
  validateRateLimitInput(key, windowMs, maxRequests);

  // Redis supplies the timestamp inside the script. The UUID only distinguishes
  // concurrent reservations that share the same server millisecond.
  const member = randomUUID();

  const res = (await redis.eval(
    RATE_LIMIT_LUA,
    1,
    rateLimitBucketKey(key, windowMs, maxRequests),
    String(windowMs),
    String(maxRequests),
    member,
    String(windowMs + 1000), // TTL = window + 1s buffer
    cleanup ? "1" : "0",
  )) as [number, number, string, number, number];
  const [allowed, count, _oldestScore, _serverNow, resetMs] = res;

  if (allowed !== 1) {
    return { allowed: false, remaining: 0, resetMs };
  }

  return {
    allowed: true,
    remaining: Math.max(0, maxRequests - count),
    resetMs,
  };
}

/**
 * Get current rate limit status without incrementing.
 *
 * ADVISORY ONLY: `allowed` (count < maxRequests) mirrors the atomic gate's
 * admit condition but does not itself reserve a slot — enforcement is
 * checkRateLimit. Use this for display, not as the gate.
 */
export async function getRateLimitStatus(
  key: string,
  windowMs: number,
  maxRequests: number,
): Promise<RateLimitResult> {
  validateRateLimitInput(key, windowMs, maxRequests);
  const redis = getRedis();
  // Although advisory, status performs expiry cleanup. Keep that mutation on
  // the same Redis clock as enforcement so a skewed observer cannot prune live
  // reservations and weaken the gate.
  const [count, _oldestScore, _serverNow, resetMs] = (await redis.eval(
    RATE_LIMIT_STATUS_LUA,
    1,
    rateLimitBucketKey(key, windowMs, maxRequests),
    String(windowMs),
  )) as [number, string, number, number];

  return {
    allowed: count < maxRequests,
    remaining: Math.max(0, maxRequests - count),
    resetMs,
  };
}

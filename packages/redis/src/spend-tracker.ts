/**
 * Per-agent spend tracking with time-bucketed Redis keys.
 *
 * Key format: spend:{agentId}:{period}:{dateKey}
 * Values stored as USD cents (integer) to avoid floating point issues.
 *
 * TTLs:
 *   day   → 2 days   (172800s)
 *   week  → 8 days   (691200s)
 *   month → 32 days  (2764800s)
 */

import { getRedis } from "./client.js";

export type SpendPeriod = "day" | "week" | "month";
type SpendLimitMap = Partial<Record<SpendPeriod, number>>;

export interface SpendLimitSnapshot {
  allowed: boolean;
  spent: number;
  reserved: number;
  effectiveSpent: number;
  remaining: number;
}

export interface SpendReservation {
  reservedUsd: number;
  periods: SpendPeriod[];
  buckets: Array<{ period: SpendPeriod; dateKey: string; key: string }>;
}

export interface IdempotentSpendReservationResult {
  allowed: boolean;
  replayed: boolean;
  conflict?: boolean;
  remainingUsd: number;
}

export interface SpendRecordOptions {
  /** Stable identity used by recovery writers to make the increment idempotent. */
  eventId?: string;
  /** Authoritative event time; retries must not move spend into a later bucket. */
  occurredAt?: Date | number;
}

const TTL_SECONDS: Record<SpendPeriod, number> = {
  day: 172800, // 2 days
  week: 691200, // 8 days
  month: 2764800, // 32 days
};
const MAX_IDEMPOTENT_RESERVATIONS_PER_BUCKET = 10_000;

// ARGV: reserveUnits, limitUnits, tenantId, ttlSeconds
// Returns {ok, settled, reservedAfter}. Increments `reserved` only when the
// effective spend stays within the limit — atomic so concurrent reserves
// cannot collectively exceed the cap.
const RESERVE_SPEND_LUA = `
local reserve = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local settled = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved') or '0')
if (settled + reserved + reserve) > limit then
  return {0, settled, reserved}
end
local after = redis.call('HINCRBY', KEYS[1], 'reserved', reserve)
redis.call('HSET', KEYS[1], 'tenantId', ARGV[3])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
return {1, settled, after}
`;

// KEYS[1]=daily spend bucket. ARGV: reserveUnits, limitUnits, tenantId,
// bucketTtl, opaque issuance marker field, requestDigest, maxHashFields.
// The marker and budget increment commit in one script, so overlapping retries
// cannot double-reserve and distinct requests cannot race past the daily cap.
const RESERVE_IDEMPOTENT_SPEND_LUA = `
local prior = redis.call('HGET', KEYS[1], ARGV[5])
if prior then
  if prior == ARGV[6] then
    local settled = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
    local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved') or '0')
    return {1, 1, settled, reserved}
  end
  return {0, -1, 0, 0}
end
local reserve = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local settled = tonumber(redis.call('HGET', KEYS[1], 'total') or '0')
local reserved = tonumber(redis.call('HGET', KEYS[1], 'reserved') or '0')
if (settled + reserved + reserve) > limit then
  return {0, 0, settled, reserved}
end
if redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[7]) then
  return {0, 0, settled, reserved}
end
local after = redis.call('HINCRBY', KEYS[1], 'reserved', reserve)
redis.call('HSET', KEYS[1], 'tenantId', ARGV[3])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[4]))
redis.call('HSET', KEYS[1], ARGV[5], ARGV[6])
return {1, 0, settled, after}
`;

// ARGV: releaseUnits. Returns reservedAfter.
// Decrement `reserved` but FLOOR AT ZERO: a double-settle (caller bug) must
// not drive the field negative — a negative `reserved` would subtract from
// the effective spend in checkSpendLimit/reserveSpend and silently free
// budget (fail-open). SEC-168. Atomic so a concurrent reserve cannot observe
// a transient negative either.
const SETTLE_RESERVED_LUA = `
local release = tonumber(ARGV[1])
local current = tonumber(redis.call('HGET', KEYS[1], 'reserved') or '0')
local after = math.max(0, current - release)
redis.call('HSET', KEYS[1], 'reserved', after)
return after
`;

// KEYS[1]=idempotency marker, KEYS[2..4]=day/week/month buckets.
// ARGV[1]=units ARGV[2]=host ARGV[3]=tenantId ARGV[4..6]=bucket TTLs.
const RECORD_IDEMPOTENT_SPEND_LUA = `
if redis.call('SET', KEYS[1], '1', 'NX', 'EX', tonumber(ARGV[6])) == false then
  return 0
end
for i = 2, 4 do
  redis.call('HINCRBY', KEYS[i], 'total', tonumber(ARGV[1]))
  redis.call('HINCRBY', KEYS[i], 'host:' .. ARGV[2], tonumber(ARGV[1]))
  redis.call('HSET', KEYS[i], 'tenantId', ARGV[3])
  redis.call('EXPIRE', KEYS[i], tonumber(ARGV[i + 2]))
end
return 1
`;

/**
 * Get the date key for a given period.
 * - day:   "2026-03-27"
 * - week:  "2026-W13" (ISO week number)
 * - month: "2026-03"
 */
function getDateKey(period: SpendPeriod, date: Date = new Date()): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  const d = String(date.getUTCDate()).padStart(2, "0");

  switch (period) {
    case "day":
      return `${y}-${m}-${d}`;
    case "week": {
      const { isoYear, isoWeek: weekNum } = isoWeek(date);
      return `${isoYear}-W${String(weekNum).padStart(2, "0")}`;
    }
    case "month":
      return `${y}-${m}`;
  }
}

function spendKey(agentId: string, period: SpendPeriod, dateKey: string): string {
  return `spend:${agentId}:${period}:${dateKey}`;
}

/**
 * ISO-8601 week number + ISO week-year (Thursday-based). Days near a year
 * boundary may belong to the previous/next ISO week-year, so we return both.
 */
export function isoWeek(date: Date): { isoYear: number; isoWeek: number } {
  // Shift to the Thursday of the current ISO week (Mon=0..Sun=6).
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNum = (d.getUTCDay() + 6) % 7;
  d.setUTCDate(d.getUTCDate() - dayNum + 3);
  const isoYear = d.getUTCFullYear();
  const firstThursday = new Date(Date.UTC(isoYear, 0, 4));
  const firstThursdayDayNum = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - firstThursdayDayNum + 3);
  const week = 1 + Math.round((d.getTime() - firstThursday.getTime()) / (7 * 86400000));
  return { isoYear, isoWeek: week };
}

function toSpendUnits(costUsd: number): number {
  // A sign/parse error upstream must not silently floor to a free spend.
  if (!Number.isFinite(costUsd) || costUsd < 0) {
    throw new Error(`invalid spend amount: ${costUsd}`);
  }
  if (costUsd === 0) return 0;
  return Math.ceil(costUsd * 10000); // store as 0.01 cent precision, rounded up for enforcement
}

function fromSpendUnits(units: number): number {
  return units / 10000;
}

async function rollbackReservedSpend(
  tenantId: string,
  reserveUnits: number,
  buckets: SpendReservation["buckets"],
): Promise<void> {
  if (reserveUnits <= 0 || buckets.length === 0) return;
  const redis = getRedis();
  const pipeline = redis.multi();

  for (const { period, key } of buckets) {
    pipeline.hincrby(key, "reserved", -reserveUnits);
    pipeline.hset(key, "tenantId", tenantId);
    pipeline.expire(key, TTL_SECONDS[period]);
  }

  await pipeline.exec();
}

/**
 * Record a spend event. Increments the spend counter for all periods
 * (day, week, month) atomically.
 *
 * Also stores per-host breakdown as hash fields.
 *
 * @param agentId - The agent's ID
 * @param tenantId - The tenant's ID (stored in hash for querying)
 * @param costUsd - Cost in USD (e.g. 0.03 for 3 cents)
 * @param host - The API host (e.g. "api.openai.com")
 */
export async function recordSpend(
  agentId: string,
  tenantId: string,
  costUsd: number,
  host: string,
  options: SpendRecordOptions = {},
  client?: ReturnType<typeof getRedis>,
): Promise<void> {
  const costCents = toSpendUnits(costUsd); // throws on negative/NaN; 0 → no-op below
  if (costCents <= 0) return;

  const redis = client ?? getRedis();
  const now =
    options.occurredAt instanceof Date
      ? new Date(options.occurredAt.getTime())
      : new Date(options.occurredAt ?? Date.now());
  if (Number.isNaN(now.getTime())) throw new Error("invalid spend event timestamp");

  if (options.eventId) {
    const bucketKeys = (["day", "week", "month"] as SpendPeriod[]).map((period) =>
      spendKey(agentId, period, getDateKey(period, now)),
    );
    await redis.eval(
      RECORD_IDEMPOTENT_SPEND_LUA,
      4,
      `spend:${agentId}:event:${options.eventId}`,
      ...bucketKeys,
      String(costCents),
      host,
      tenantId,
      String(TTL_SECONDS.day),
      String(TTL_SECONDS.week),
      String(TTL_SECONDS.month),
    );
    return;
  }

  const pipeline = redis.multi();

  for (const period of ["day", "week", "month"] as SpendPeriod[]) {
    const dateKey = getDateKey(period, now);
    const key = spendKey(agentId, period, dateKey);

    // Increment total spend
    pipeline.hincrby(key, "total", costCents);
    // Increment per-host spend
    pipeline.hincrby(key, `host:${host}`, costCents);
    // Store tenant ID (idempotent)
    pipeline.hset(key, "tenantId", tenantId);
    // Set TTL (only if not already set — NX equivalent via expire)
    pipeline.expire(key, TTL_SECONDS[period]);
  }

  await pipeline.exec();
}

/**
 * Reserve in-flight spend before a request leaves the proxy.
 *
 * The reservation is kept separate from settled spend but checkSpendLimit counts
 * both fields. Each period is incremented first and rolled back if the effective
 * spend crosses that period's configured limit.
 */
export async function reserveSpend(
  agentId: string,
  tenantId: string,
  reserveUsd: number,
  limits: SpendLimitMap,
  client?: ReturnType<typeof getRedis>,
): Promise<SpendReservation> {
  const reserveUnits = toSpendUnits(reserveUsd);
  if (reserveUnits <= 0) return { reservedUsd: 0, periods: [], buckets: [] };

  const redis = client ?? getRedis();
  const now = new Date();
  const periods = (["day", "week", "month"] as SpendPeriod[]).filter(
    (period) => limits[period] !== undefined,
  );
  const reservedPeriods: SpendPeriod[] = [];
  const reservedBuckets: SpendReservation["buckets"] = [];

  for (const period of periods) {
    const limit = limits[period];
    if (limit === undefined) continue;
    const dateKey = getDateKey(period, now);
    const key = spendKey(agentId, period, dateKey);
    const limitUnits = toSpendUnits(limit);

    // Atomic per-bucket gate: read total+reserved, only bump `reserved` if the
    // result stays within the limit. A separate hincrby + hget would let
    // concurrent requests race past the cap (TOCTOU).
    const res = (await redis.eval(
      RESERVE_SPEND_LUA,
      1,
      key,
      String(reserveUnits),
      String(limitUnits),
      tenantId,
      String(TTL_SECONDS[period]),
    )) as [number, number, number];
    const [ok, settled] = res;

    if (ok === 1) {
      reservedPeriods.push(period);
      reservedBuckets.push({ period, dateKey, key });
      continue;
    }

    if (reservedBuckets.length > 0) {
      await rollbackReservedSpend(tenantId, reserveUnits, reservedBuckets);
    }
    throw new Error(
      `${period} spend reservation would exceed limit: requested $${reserveUsd.toFixed(4)} with $${fromSpendUnits(Math.max(0, limitUnits - settled)).toFixed(4)} available`,
    );
  }

  return {
    reservedUsd: fromSpendUnits(reserveUnits),
    periods: reservedPeriods,
    buckets: reservedBuckets,
  };
}

/**
 * Atomic, idempotent daily reservation for unsigned fund-moving issuance.
 * This intentionally uses a separate potential-spend bucket from settled
 * execution spend: issuing an artifact reserves its full notional for the day,
 * while a later vault execution records actual spend without double-counting
 * the issuance reservation in the general spend ledger.
 */
export async function reserveDailySpendIdempotently(
  agentId: string,
  tenantId: string,
  reserveUsd: number,
  limitUsd: number,
  reservationId: string,
  requestDigest: string,
  client?: ReturnType<typeof getRedis>,
): Promise<IdempotentSpendReservationResult> {
  const reserveUnits = toSpendUnits(reserveUsd);
  const limitUnits = toSpendUnits(limitUsd);
  if (reserveUnits <= 0 || limitUnits <= 0) {
    throw new Error("spend reservation and limit must be positive");
  }
  if (!/^[a-f0-9]{64}$/.test(reservationId) || !/^[a-f0-9]{64}$/.test(requestDigest)) {
    throw new Error("spend reservation identities must be SHA-256 hex digests");
  }
  const redis = client ?? getRedis();
  const dateKey = getDateKey("day");
  const bucket = `spend:${tenantId}:${agentId}:adapter-issuance:day:${dateKey}`;
  const markerField = `issuance:${reservationId}`;
  const result = (await redis.eval(
    RESERVE_IDEMPOTENT_SPEND_LUA,
    1,
    bucket,
    String(reserveUnits),
    String(limitUnits),
    tenantId,
    String(TTL_SECONDS.day),
    markerField,
    requestDigest,
    String(MAX_IDEMPOTENT_RESERVATIONS_PER_BUCKET),
  )) as [number, number, number, number];
  const [allowed, replay, settled, reserved] = result.map(Number);
  return {
    allowed: allowed === 1,
    replayed: replay === 1,
    ...(replay === -1 ? { conflict: true } : {}),
    remainingUsd: Math.max(0, limitUsd - fromSpendUnits(settled + reserved)),
  };
}

/**
 * Settle an earlier reservation after the upstream response is known.
 *
 * If actual spend cannot be calculated, callers should pass the reserved amount
 * to avoid turning parsing failures into free budget bypasses.
 */
export async function settleReservedSpend(
  agentId: string,
  tenantId: string,
  reservedUsd: number,
  actualUsd: number,
  host: string,
  periods: SpendPeriod[],
  buckets?: SpendReservation["buckets"],
): Promise<void> {
  const reservedUnits = toSpendUnits(reservedUsd);
  const actualUnits = Math.max(0, toSpendUnits(actualUsd));
  const settlementBuckets =
    buckets && buckets.length > 0
      ? buckets
      : periods.map((period) => {
          const dateKey = getDateKey(period);
          return { period, dateKey, key: spendKey(agentId, period, dateKey) };
        });
  if (reservedUnits <= 0 || settlementBuckets.length === 0) {
    if (actualUnits > 0) await recordSpend(agentId, tenantId, actualUsd, host);
    return;
  }

  const redis = getRedis();
  const pipeline = redis.multi();

  for (const { period, key } of settlementBuckets) {
    // SEC-168: clamped Lua decrement — never let `reserved` go negative.
    pipeline.eval(SETTLE_RESERVED_LUA, 1, key, String(reservedUnits));
    if (actualUnits > 0) {
      pipeline.hincrby(key, "total", actualUnits);
      pipeline.hincrby(key, `host:${host}`, actualUnits);
    }
    pipeline.hset(key, "tenantId", tenantId);
    pipeline.expire(key, TTL_SECONDS[period]);
  }

  await pipeline.exec();
}

/**
 * Get total spend for an agent in a given period.
 *
 * @returns Spend in USD
 */
export async function getSpend(agentId: string, period: SpendPeriod, date?: Date): Promise<number> {
  const redis = getRedis();
  const dateKey = getDateKey(period, date || new Date());
  const key = spendKey(agentId, period, dateKey);

  const totalCents = await redis.hget(key, "total");
  if (!totalCents) return 0;

  return fromSpendUnits(Number(totalCents)); // convert back to USD
}

/**
 * Check if an agent is within their spend limit.
 *
 * ADVISORY ONLY: this is a status read with no pending amount, so `allowed`
 * means "budget not yet fully consumed". The real enforcement is the atomic
 * gate in reserveSpend — never admit a request on this alone.
 *
 * @returns Whether the agent can spend more, how much they've spent, and remaining budget
 */
export async function checkSpendLimit(
  agentId: string,
  limitUsd: number,
  period: SpendPeriod,
  client?: ReturnType<typeof getRedis>,
): Promise<SpendLimitSnapshot> {
  const redis = client ?? getRedis();
  const dateKey = getDateKey(period);
  const key = spendKey(agentId, period, dateKey);
  const [totalRaw, reservedRaw] = await Promise.all([
    redis.hget(key, "total"),
    redis.hget(key, "reserved"),
  ]);
  const spent = fromSpendUnits(Number(totalRaw ?? "0"));
  const reserved = fromSpendUnits(Number(reservedRaw ?? "0"));
  const effectiveSpent = spent + reserved;
  const remaining = Math.max(0, limitUsd - effectiveSpent);

  return {
    allowed: effectiveSpent < limitUsd,
    spent,
    reserved,
    effectiveSpent,
    remaining,
  };
}

/**
 * Get per-host spend breakdown for an agent in a given period.
 */
export async function getSpendByHost(
  agentId: string,
  period: SpendPeriod,
  date?: Date,
): Promise<Record<string, number>> {
  const redis = getRedis();
  const dateKey = getDateKey(period, date || new Date());
  const key = spendKey(agentId, period, dateKey);

  const all = await redis.hgetall(key);
  const result: Record<string, number> = {};

  for (const [field, value] of Object.entries(all)) {
    if (field.startsWith("host:")) {
      result[field.slice(5)] = Number(value) / 10000;
    }
  }

  return result;
}

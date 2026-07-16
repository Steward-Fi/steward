/**
 * Cumulative (aggregate) spend tracker with CONFIGURABLE trailing windows and
 * ATOMIC single-winner reservations - backs the policy-engine `cumulativeSpend`
 * capability-intent constraint (#206, Privy aggregate-limit parity).
 *
 * WHY A NEW TRACKER (vs spend-tracker.ts / aggregation-tracker.ts)
 * ---------------------------------------------------------------
 *   - `spend-tracker.ts` is atomic (Lua reserve-under-limit) but only supports
 *     FIXED calendar periods (day/week/month), not an arbitrary ISO-8601 window,
 *     and it scopes per-agent only.
 *   - `aggregation-tracker.ts` supports rolling windows but is READ-THEN-CHECK
 *     (record AFTER settle; the evaluator reads a snapshot). Two concurrent
 *     invokes can both read the same prior sum and both pass - unacceptable for a
 *     hard money cap (#206 req 4).
 * This tracker combines both: a sorted-set rolling window (any windowSeconds) +
 * a single Lua script that prunes, sums, checks `sum + amount <= max`, and only
 * then appends the reservation - so concurrent reservers can never collectively
 * cross the cap (TOCTOU-free).
 *
 * SCOPES (mirror the cumulativeSpend `aggregateOver`):
 *   - "operation": per (agent, operationKey)  key discriminator = operationKey
 *   - "agent":     per agent                    key discriminator = ""
 *   - "grant":     per grant                     key discriminator = grantId
 *
 * MONEY MATH: integer minor units only (micros/cents - the caller's convention,
 * matching the policy `max`). No floats, no FX. A currency is part of the key so
 * two currencies never share a window.
 *
 * WINDOW BOUNDARY (matches the policy evaluator + aggregation-tracker): a window
 * of S seconds at time `now` covers the HALF-OPEN interval `(now - S*1000, now]`.
 * An entry exactly S seconds old has aged out and is excluded; an entry at `now`
 * is included.
 *
 * RESERVATION LIFECYCLE + HONEST SEMANTICS:
 *   1. reserveCumulativeSpend(...) atomically admits (or rejects) an invoke and
 *      returns a reservationId. The reserved amount is IMMEDIATELY part of the
 *      window sum, so a concurrent invoke sees it.
 *   2. On a KNOWN-SUCCESS outcome, settleCumulativeSpend(...) keeps the entry
 *      (it stays counted for the rest of the window) - a no-op mark, present for
 *      symmetry + auditability.
 *   3. On a KNOWN-FAILURE outcome, releaseCumulativeSpend(...) removes the entry
 *      so the budget is reclaimed.
 *   4. On outcome_unknown (a crash/timeout after admission, or a settle we can't
 *      confirm), the reservation is DELIBERATELY LEFT IN PLACE and ages out
 *      naturally at the window edge. This is fail-CLOSED for a money cap: an
 *      unknown outcome must never free budget it may have actually spent. The
 *      honest cost is a possible transient over-count for one window if the
 *      action in fact never spent - acceptable for a guardrail (deny-side error
 *      is safe; allow-side error is not).
 *
 * PER-PROCESS CAVEAT: correctness under concurrency is guaranteed by the atomic
 * Redis script, so it holds across processes sharing one Redis. It does NOT
 * claim exactly-once settlement across a crash (see outcome_unknown semantics).
 */

import { getRedis } from "./client.js";

export type CumulativeSpendScope = "operation" | "agent" | "grant";

/** Max window we retain reservation entries for (30d - matches other trackers). */
const MAX_WINDOW_SECONDS = 2592000;
const RETENTION_MS = MAX_WINDOW_SECONDS * 1000;

export interface CumulativeSpendKeyParts {
  agentId: string;
  scope: CumulativeSpendScope;
  /** operationKey for "operation" scope, grantId for "grant" scope, "" for "agent". */
  scopeKey: string;
  /** currency/asset tag - part of the key so currencies never share a window. */
  currency: string;
  /** trailing window length in seconds - part of the key so two rules with the
   *  SAME scope/currency but DIFFERENT windows get INDEPENDENT buckets (no shared
   *  double-count of the same invoke across distinct caps; codex P2). */
  windowSeconds: number;
  /** the cap in minor units - part of the key so two rules with the same
   *  scope/currency/window but different maxes are independent buckets too. */
  max: number;
}

export interface ReserveCumulativeSpendInput extends CumulativeSpendKeyParts {
  /** this invoke's spend, integer minor units. */
  amount: number;
  /** evaluation time in ms; injectable for tests. */
  now?: number;
}

export interface ReserveCumulativeSpendResult {
  /** true when admitted (sum + amount <= max), false when it would breach. */
  ok: boolean;
  /** the trailing-window sum BEFORE this invoke (integer minor units). */
  priorSum: number;
  /** opaque id to settle/release this reservation; only set when ok. */
  reservationId?: string;
}

/** Read-only trailing-window sum snapshot (advisory; enforcement is reserve). */
export interface CumulativeSpendSnapshot {
  /** committed+reserved sum over the trailing window, integer minor units. */
  sum: number;
}

function cumKey(parts: CumulativeSpendKeyParts): string {
  // scopeKey/currency are operator/adapter-derived tags; encode to keep the key
  // delimiter-safe (no ':' collisions merging two buckets). windowSeconds+max are
  // part of the identity so distinct caps never share a ZSET (codex P2).
  const enc = (s: string) => encodeURIComponent(s);
  return `cumspend:${enc(parts.agentId)}:${parts.scope}:${enc(parts.scopeKey)}:${enc(
    parts.currency,
  )}:${parts.windowSeconds}:${parts.max}`;
}

// ATOMIC reserve-under-limit over a rolling window.
//   KEYS[1] = bucket key
//   ARGV: now, windowStartExclusive, retentionCutoff, amount, max, ttlMs, member
// Prune aged-out + retention-expired members, sum the survivors' amounts, and
// only ZADD the new reservation if (sum + amount) <= max. Returns {ok, priorSum}.
// The sum is parsed from the "|amount|" segment of each member. Because prune +
// sum + conditional-add happen in ONE script, two concurrent reservers cannot
// both pass when their combined sum would exceed max.
const RESERVE_LUA = `
local now = tonumber(ARGV[1])
local windowStart = tonumber(ARGV[2])
local retentionCutoff = tonumber(ARGV[3])
local amount = tonumber(ARGV[4])
local maxv = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])
local member = ARGV[7]
-- prune retention-expired first (bounds the set), then read the live window.
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, retentionCutoff)
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. windowStart, now)
local sum = 0
for i = 1, #members do
  local m = members[i]
  -- member format: "{ts}:{seq}|{amount}|{state}"
  local firstBar = string.find(m, '|', 1, true)
  if firstBar then
    local rest = string.sub(m, firstBar + 1)
    local secondBar = string.find(rest, '|', 1, true)
    local amtStr = secondBar and string.sub(rest, 1, secondBar - 1) or rest
    local amt = tonumber(amtStr)
    if amt == nil then
      -- corrupt member -> fail closed (signal caller with a sentinel).
      return {-1, 0}
    end
    sum = sum + amt
  else
    return {-1, 0}
  end
end
if (sum + amount) > maxv then
  return {0, sum}
end
redis.call('ZADD', KEYS[1], now, member)
redis.call('PEXPIRE', KEYS[1], ttl)
return {1, sum}
`;

// Read-only window sum (advisory). Prune retention-expired, sum the live window.
const SUM_LUA = `
local now = tonumber(ARGV[1])
local windowStart = tonumber(ARGV[2])
local retentionCutoff = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, retentionCutoff)
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. windowStart, now)
local sum = 0
for i = 1, #members do
  local m = members[i]
  local firstBar = string.find(m, '|', 1, true)
  if firstBar then
    local rest = string.sub(m, firstBar + 1)
    local secondBar = string.find(rest, '|', 1, true)
    local amtStr = secondBar and string.sub(rest, 1, secondBar - 1) or rest
    local amt = tonumber(amtStr)
    if amt == nil then return {-1} end
    sum = sum + amt
  else
    return {-1}
  end
end
return {sum}
`;

function isNonNegInt(v: number): boolean {
  return typeof v === "number" && Number.isFinite(v) && Number.isInteger(v) && v >= 0;
}

let seq = 0;
function nextSeq(): string {
  seq = (seq + 1) % 1_000_000;
  return `${seq}.${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * Atomically reserve this invoke's spend against the trailing-window cap. When
 * `ok` is false the caller MUST deny (the cap would be breached). When `ok` is
 * true the reservation is already part of the window sum for any concurrent
 * invoke, and the caller must later settle (success) or release (failure).
 *
 * Fail-closed inputs: a non-integer/negative amount/max or a non-positive window
 * throws (a bad spend must never silently become free budget). A corrupt member
 * in the bucket throws (never sum past garbage).
 */
export async function reserveCumulativeSpend(
  input: ReserveCumulativeSpendInput,
): Promise<ReserveCumulativeSpendResult> {
  if (!isNonNegInt(input.amount))
    throw new Error(`invalid cumulative spend amount: ${input.amount}`);
  if (!isNonNegInt(input.max)) throw new Error(`invalid cumulative spend max: ${input.max}`);
  if (
    typeof input.windowSeconds !== "number" ||
    !Number.isSafeInteger(input.windowSeconds) ||
    input.windowSeconds <= 0 ||
    // Over-retention windows cannot be enforced (older entries are pruned), so we
    // REJECT rather than silently clamp - a money cap must never be quietly
    // weakened to a shorter effective window (codex P1). The policy layer already
    // rejects these at config time; this is the defense-in-depth floor.
    input.windowSeconds > MAX_WINDOW_SECONDS
  ) {
    throw new Error(`invalid cumulative spend window: ${input.windowSeconds}`);
  }
  if (typeof input.agentId !== "string" || input.agentId.length === 0) {
    throw new Error("cumulative spend reserve requires agentId");
  }
  if (typeof input.currency !== "string" || input.currency.length === 0) {
    throw new Error("cumulative spend reserve requires currency");
  }

  const now = input.now ?? Date.now();
  // windowSeconds is guaranteed <= MAX_WINDOW_SECONDS by the guard above.
  const windowStart = now - input.windowSeconds * 1000;
  const retentionCutoff = now - RETENTION_MS;
  const reservationId = `${now}:${nextSeq()}`;
  const member = `${reservationId}|${input.amount}|reserved`;
  const key = cumKey(input);

  const redis = getRedis();
  const res = (await redis.eval(
    RESERVE_LUA,
    1,
    key,
    String(now),
    String(windowStart),
    String(retentionCutoff),
    String(input.amount),
    String(input.max),
    String(RETENTION_MS),
    member,
  )) as [number, number];

  const [ok, sum] = res;
  if (ok === -1) {
    // Corrupt member in the window -> fail closed.
    throw new Error("cumulative spend bucket contained a corrupt member");
  }
  if (ok === 1) {
    return { ok: true, priorSum: sum, reservationId };
  }
  return { ok: false, priorSum: sum };
}

/**
 * Settle a successful reservation. The entry stays counted for the rest of the
 * window (it represents real spend), so this is a no-op mark today, kept for a
 * symmetric lifecycle + future per-state auditing. Never frees budget.
 */
export async function settleCumulativeSpend(_input: {
  keyParts: CumulativeSpendKeyParts;
  reservationId: string;
}): Promise<void> {
  // Intentionally a no-op: a settled reservation must remain in the window sum.
  return;
}

/**
 * Release a reservation on a KNOWN-FAILURE outcome, reclaiming its budget. Safe
 * to call at most once per reservationId; a second call is a no-op (ZREM of an
 * absent member). NEVER call this on outcome_unknown - an unconfirmed action may
 * have really spent, and freeing its budget would be an allow-side error.
 */
export async function releaseCumulativeSpend(input: {
  keyParts: CumulativeSpendKeyParts;
  reservationId: string;
  amount: number;
}): Promise<void> {
  if (!isNonNegInt(input.amount)) return;
  const key = cumKey(input.keyParts);
  const member = `${input.reservationId}|${input.amount}|reserved`;
  const redis = getRedis();
  await redis.zrem(key, member);
}

/**
 * Advisory read of the trailing-window sum (committed + reserved). Enforcement
 * MUST use reserveCumulativeSpend (atomic); this is for the policy context's
 * prior-sum signal and for observability. Returns null on any I/O/parse failure
 * so the caller fails closed (deny).
 */
export async function getCumulativeSpendSum(
  input: CumulativeSpendKeyParts & { now?: number },
): Promise<CumulativeSpendSnapshot | null> {
  if (
    typeof input.windowSeconds !== "number" ||
    !Number.isSafeInteger(input.windowSeconds) ||
    input.windowSeconds <= 0 ||
    input.windowSeconds > MAX_WINDOW_SECONDS
  ) {
    return null;
  }
  const now = input.now ?? Date.now();
  const windowStart = now - input.windowSeconds * 1000;
  const retentionCutoff = now - RETENTION_MS;
  const key = cumKey(input);
  try {
    const redis = getRedis();
    const res = (await redis.eval(
      SUM_LUA,
      1,
      key,
      String(now),
      String(windowStart),
      String(retentionCutoff),
    )) as [number];
    const [sum] = res;
    if (sum < 0) return null; // corrupt member -> fail closed
    return { sum };
  } catch {
    return null;
  }
}

export { cumKey as cumulativeSpendKeyForTest };

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
 * a single Lua script that prunes, sums, checks EACH cap's `sum + amount <= max`
 * over its own window, and only then appends the reservation - so concurrent
 * reservers can never collectively cross any cap (TOCTOU-free).
 *
 * STREAM KEY vs CAP THRESHOLDS (codex P1 fix)
 * -------------------------------------------
 * The Redis ZSET (the "spend stream") is keyed ONLY by the spend-stream identity
 * `(agentId, scope, scopeKey, currency)` - NOT by the cap's window/max. Editing a
 * cap (lowering a 24h limit, changing a window) MUST re-evaluate against the SAME
 * accumulated history, never a fresh empty bucket. Cap thresholds are supplied as
 * check parameters per reserve, not baked into the key.
 *
 * MULTIPLE CAPS ON ONE STREAM (codex P2 fix)
 * ------------------------------------------
 * A single invoke that is governed by several caps on the same stream (e.g. a 1h
 * AND a 24h cap, or two rules) is reserved ONCE: the atomic script checks ALL
 * supplied (window, max) pairs against the shared stream and only adds the entry
 * if EVERY cap holds. The invoke is therefore counted exactly once, never
 * double-counted across caps, and no cap can be crossed by a concurrent burst.
 *
 * SCOPES (mirror the cumulativeSpend `aggregateOver`):
 *   - "operation": per (agent, operationKey)  scopeKey = operationKey
 *   - "agent":     per agent                    scopeKey = ""
 *   - "grant":     per grant                     scopeKey = grantId
 *
 * MONEY MATH: integer minor units only (micros/cents - the caller's convention,
 * matching the policy `max`). No floats, no FX. Currency is part of the stream
 * key so two currencies never share a window.
 *
 * WINDOW BOUNDARY (matches the policy evaluator + aggregation-tracker): a window
 * of S seconds at time `now` covers the HALF-OPEN interval `(now - S*1000, now]`.
 * An entry exactly S seconds old has aged out and is excluded; an entry at `now`
 * is included.
 *
 * RESERVATION LIFECYCLE + HONEST SEMANTICS:
 *   1. reserveCumulativeSpend(...) atomically admits (or rejects) an invoke and
 *      returns a reservationId. The reserved amount is IMMEDIATELY part of the
 *      stream, so a concurrent invoke sees it.
 *   2. On a KNOWN-SUCCESS outcome, settleCumulativeSpend(...) keeps the entry.
 *   3. On a KNOWN-FAILURE outcome, releaseCumulativeSpend(...) removes the entry
 *      so the budget is reclaimed.
 *   4. On outcome_unknown, the reservation is LEFT in place and ages out at the
 *      window edge - fail-CLOSED for a money cap (never free maybe-spent budget).
 *
 * PER-PROCESS CAVEAT: correctness under concurrency is guaranteed by the atomic
 * Redis script, so it holds across processes sharing one Redis. It does NOT
 * claim exactly-once settlement across a crash (see outcome_unknown semantics).
 */

import { randomUUID } from "node:crypto";
import { getRedis } from "./client.js";

export type CumulativeSpendScope = "operation" | "agent" | "grant";

/** Reserved currency tag for the #206 windowed invoke-count stream (never a real
 *  asset), so a count stream can never collide with a spend stream. */
const WINDOWED_INVOKE_CURRENCY = "__calls__";

/** Max window we retain reservation entries for (30d - matches other trackers). */
const MAX_WINDOW_SECONDS = 2592000;
const RETENTION_MS = MAX_WINDOW_SECONDS * 1000;

/** The spend-stream identity. Editing a cap does NOT change this key, so history
 *  persists across cap edits (codex P1). */
export interface CumulativeSpendStream {
  /** Tenant namespace. New governed callers MUST supply it; omitted only for
   * legacy streams that predate tenant-bound keys. */
  tenantId?: string;
  agentId: string;
  scope: CumulativeSpendScope;
  /** operationKey for "operation" scope, grantId for "grant" scope, "" for "agent". */
  scopeKey: string;
  /** currency/asset tag - part of the key so currencies never share a stream. */
  currency: string;
}

/** A single trailing-window cap to enforce against a stream. */
export interface CumulativeSpendCap {
  /** trailing window length in seconds (resolved from the ISO-8601 duration). */
  windowSeconds: number;
  /** the cap, integer minor units (micros/cents). */
  max: number;
}

export interface ReserveCumulativeSpendInput {
  stream: CumulativeSpendStream;
  /** every cap governing this invoke on this stream; ALL are checked atomically. */
  caps: CumulativeSpendCap[];
  /** this invoke's spend, integer minor units. */
  amount: number;
  /** evaluation time in ms; injectable for tests. */
  now?: number;
  /** Optional caller-stable identity. This makes a durable workflow retry the
   * same reservation instead of double-debiting after a process death between
   * Redis admission and its database commit. Must be opaque and delimiter-safe. */
  reservationId?: string;
}

export interface ReserveCumulativeSpendResult {
  /** true when admitted (every cap holds), false when any cap would breach. */
  ok: boolean;
  /** the trailing-window sums BEFORE this invoke, one per input cap (same order).
   *  Feeds the policy composer's per-cap prior-sum signal. */
  priorSums: number[];
  /** opaque id to settle/release this reservation; only set when ok. */
  reservationId?: string;
}

/** Read-only trailing-window sum snapshot (advisory; enforcement is reserve). */
export interface CumulativeSpendSnapshot {
  /** committed+reserved sum over the trailing window, integer minor units. */
  sum: number;
}

function streamKey(s: CumulativeSpendStream): string {
  // scopeKey/currency are operator/adapter-derived tags; encode to keep the key
  // delimiter-safe. Deliberately NO window/max in the key (codex P1): the stream
  // identity is the spend history, not the current cap threshold.
  const enc = (v: string) => encodeURIComponent(v);
  if (s.tenantId) {
    // The hash tag keeps every stream for one tenant+agent in the same Redis
    // Cluster slot, permitting an atomic multi-stream Lua reservation.
    return `cumspend:v2:{${enc(`${s.tenantId}|${s.agentId}`)}}:${s.scope}:${enc(s.scopeKey)}:${enc(s.currency)}`;
  }
  // Preserve the exact legacy namespace for already-deployed callers. New
  // governed flows always pass tenantId and therefore use v2 above.
  return `cumspend:${enc(s.agentId)}:${s.scope}:${enc(s.scopeKey)}:${enc(s.currency)}`;
}

export interface CumulativeSpendBatchGroup {
  stream: CumulativeSpendStream & { tenantId: string };
  caps: CumulativeSpendCap[];
  amount: number;
  reservationId: string;
}

export interface CumulativeSpendBatchResult {
  ok: boolean;
  priorSums: number[][];
  reservationIds?: string[];
}

// Atomically checks every cap on every applicable stream, and only writes when
// ALL streams admit. This prevents provisional holds on one stream from causing
// a concurrent false exhaustion/freeze when another stream later denies.
const RESERVE_BATCH_LUA = `
local now = tonumber(ARGV[1])
local retentionCutoff = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local nGroups = tonumber(ARGV[4])
local cursor = 5
local out = {1}
local outCursor = 2
local parsed = {}
for g = 1, nGroups do
  local amount = tonumber(ARGV[cursor]); cursor = cursor + 1
  local member = ARGV[cursor]; cursor = cursor + 1
  local memberBar = string.find(member, '|', 1, true)
  local reservationId = string.sub(member, 1, memberBar - 1)
  local nCaps = tonumber(ARGV[cursor]); cursor = cursor + 1
  redis.call('ZREMRANGEBYSCORE', KEYS[g], 0, retentionCutoff)
  parsed[g] = {amount=amount, member=member, reservationId=reservationId}
  for c = 1, nCaps do
    local windowStart = tonumber(ARGV[cursor]); cursor = cursor + 1
    local maxv = tonumber(ARGV[cursor]); cursor = cursor + 1
    local members = redis.call('ZRANGEBYSCORE', KEYS[g], '(' .. windowStart, now)
    local sum = 0
    for i = 1, #members do
      local m = members[i]
      local firstBar = string.find(m, '|', 1, true)
      if not firstBar then return {-1} end
      if string.sub(m, 1, firstBar - 1) ~= reservationId then
        local rest = string.sub(m, firstBar + 1)
        local secondBar = string.find(rest, '|', 1, true)
        local amtStr = secondBar and string.sub(rest, 1, secondBar - 1) or rest
        local amt = tonumber(amtStr)
        if amt == nil then return {-1} end
        sum = sum + amt
      end
    end
    out[outCursor] = sum; outCursor = outCursor + 1
    if (sum + amount) > maxv then out[1] = 0 end
  end
end
for g = 1, nGroups do
  local p = parsed[g]
  -- Remove any pre-crash member with this reservation identity, including an
  -- older amount. This makes a changed retry replace rather than double-debit.
  local live = redis.call('ZRANGEBYSCORE', KEYS[g], retentionCutoff, now)
  for i = 1, #live do
    local bar = string.find(live[i], '|', 1, true)
    if bar and string.sub(live[i], 1, bar - 1) == p.reservationId then
      redis.call('ZREM', KEYS[g], live[i])
    end
  end
  if out[1] == 1 then
    -- A retry adopts the orphan at the current admission time. Keeping the
    -- pre-crash score could make a freshly committed action age out early.
    redis.call('ZADD', KEYS[g], now, p.member)
    redis.call('PEXPIRE', KEYS[g], ttl)
  end
end
return out
`;

// ATOMIC multi-cap reserve over a rolling stream.
//   KEYS[1] = stream key
//   ARGV[1]=now ARGV[2]=retentionCutoff ARGV[3]=amount ARGV[4]=ttlMs
//   ARGV[5]=member ARGV[6]=nCaps then nCaps pairs of (windowStartExclusive, max)
// Prune retention-expired, then for EACH cap compute the sum over its window and
// verify sum+amount <= max. Only if ALL caps hold, ZADD the entry ONCE. Returns
// {ok, priorSum_1, priorSum_2, ...}. ok=-1 => corrupt member (fail closed).
const RESERVE_LUA = `
local now = tonumber(ARGV[1])
local retentionCutoff = tonumber(ARGV[2])
local amount = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local member = ARGV[5]
local memberBar = string.find(member, '|', 1, true)
local reservationId = string.sub(member, 1, memberBar - 1)
local nCaps = tonumber(ARGV[6])
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, retentionCutoff)
local out = {1}
local base = 6
for c = 1, nCaps do
  local windowStart = tonumber(ARGV[base + (c-1)*2 + 1])
  local maxv = tonumber(ARGV[base + (c-1)*2 + 2])
  local members = redis.call('ZRANGEBYSCORE', KEYS[1], '(' .. windowStart, now)
  local sum = 0
  for i = 1, #members do
    local m = members[i]
    local firstBar = string.find(m, '|', 1, true)
    if firstBar then
      -- A retry may carry a newly canonicalized amount. Exclude any member with
      -- the same reservation identity, not only the byte-identical member.
      if string.sub(m, 1, firstBar - 1) ~= reservationId then
        local rest = string.sub(m, firstBar + 1)
        local secondBar = string.find(rest, '|', 1, true)
        local amtStr = secondBar and string.sub(rest, 1, secondBar - 1) or rest
        local amt = tonumber(amtStr)
        if amt == nil then return {-1} end
        sum = sum + amt
      end
    else
      return {-1}
    end
  end
  out[c + 1] = sum
  if (sum + amount) > maxv then
    out[1] = 0
  end
end
local live = redis.call('ZRANGEBYSCORE', KEYS[1], retentionCutoff, now)
for i = 1, #live do
  local bar = string.find(live[i], '|', 1, true)
  if bar and string.sub(live[i], 1, bar - 1) == reservationId then
    redis.call('ZREM', KEYS[1], live[i])
  end
end
if out[1] == 1 then
  -- Refresh an adopted orphan to the authoritative retry time.
  redis.call('ZADD', KEYS[1], now, member)
  redis.call('PEXPIRE', KEYS[1], ttl)
end
return out
`;

// ATOMIC all-or-nothing reserve over several independently-keyed streams.
// Every stream is inspected before any member is added, so a rejection never
// needs compensating writes and concurrent callers cannot observe a partial
// multi-dimensional budget reservation.
//
// KEYS = one key per entry
// ARGV[1]=now ARGV[2]=retentionCutoff ARGV[3]=ttlMs ARGV[4]=nEntries
// then, for each entry: amount, member, nCaps, nCaps*(windowStart,max)
const RESERVE_BATCH_LUA = `
local now = tonumber(ARGV[1])
local retentionCutoff = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local nEntries = tonumber(ARGV[4])
local cursor = 5
local admitted = 1
local out = {1}
local members = {}

for e = 1, nEntries do
  local amount = tonumber(ARGV[cursor])
  local member = ARGV[cursor + 1]
  local nCaps = tonumber(ARGV[cursor + 2])
  cursor = cursor + 3
  members[e] = member
  redis.call('ZREMRANGEBYSCORE', KEYS[e], 0, retentionCutoff)
  for c = 1, nCaps do
    local windowStart = tonumber(ARGV[cursor])
    local maxv = tonumber(ARGV[cursor + 1])
    cursor = cursor + 2
    local live = redis.call('ZRANGEBYSCORE', KEYS[e], '(' .. windowStart, now)
    local sum = 0
    for i = 1, #live do
      local m = live[i]
      if m ~= member then
        local firstBar = string.find(m, '|', 1, true)
        if not firstBar then return {-1} end
        local rest = string.sub(m, firstBar + 1)
        local secondBar = string.find(rest, '|', 1, true)
        local amtStr = secondBar and string.sub(rest, 1, secondBar - 1) or rest
        local amt = tonumber(amtStr)
        if amt == nil then return {-1} end
        sum = sum + amt
      end
    end
    out[#out + 1] = sum
    if (sum + amount) > maxv then admitted = 0 end
  end
end

out[1] = admitted
cursor = 5
for e = 1, nEntries do
  local amount = tonumber(ARGV[cursor])
  local member = ARGV[cursor + 1]
  local nCaps = tonumber(ARGV[cursor + 2])
  cursor = cursor + 3 + nCaps * 2
  local existing = redis.call('ZSCORE', KEYS[e], member)
  if admitted == 1 and not existing then
    redis.call('ZADD', KEYS[e], now, member)
    redis.call('PEXPIRE', KEYS[e], ttl)
  elseif admitted == 0 and existing then
    redis.call('ZREM', KEYS[e], member)
  end
end
return out
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
  // Redis Lua numbers are IEEE-754 doubles. Values above MAX_SAFE_INTEGER may
  // stringify/round differently between JS and Lua, which would make a durable
  // reservation impossible to identify and release exactly. Reject them before
  // touching Redis.
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
}

function isValidWindow(w: number): boolean {
  return typeof w === "number" && Number.isSafeInteger(w) && w > 0 && w <= MAX_WINDOW_SECONDS;
}

function nextSeq(): string {
  // A process-local counter can repeat after a restart, and Math.random is not
  // an appropriate uniqueness source for money-accounting reservations. A UUID
  // prevents an existing ZSET member from being overwritten and under-counted.
  return randomUUID();
}

/**
 * Atomically reserve this invoke's spend against EVERY cap on the stream. When
 * `ok` is false the caller MUST deny (some cap would breach). When `ok` is true
 * the reservation is already part of the window sums for any concurrent invoke,
 * and the caller must later settle (success) or release (failure).
 *
 * The invoke is added to the stream EXACTLY ONCE (never double-counted across
 * caps). `priorSums[i]` is the trailing-window sum for `caps[i]` BEFORE this
 * invoke - fed to the policy composer so its per-cap check agrees.
 *
 * Fail-closed inputs: a non-integer/negative amount/max, an empty caps list, or
 * an out-of-range window throws (a bad spend must never become free budget). A
 * corrupt member in the stream throws (never sum past garbage).
 */
export async function reserveCumulativeSpend(
  input: ReserveCumulativeSpendInput,
): Promise<ReserveCumulativeSpendResult> {
  if (!isNonNegInt(input.amount))
    throw new Error(`invalid cumulative spend amount: ${input.amount}`);
  if (!Array.isArray(input.caps) || input.caps.length === 0)
    throw new Error("cumulative spend reserve requires at least one cap");
  for (const cap of input.caps) {
    if (!isNonNegInt(cap.max)) throw new Error(`invalid cumulative spend max: ${cap.max}`);
    if (!isValidWindow(cap.windowSeconds))
      throw new Error(`invalid cumulative spend window: ${cap.windowSeconds}`);
  }
  const { stream } = input;
  if (typeof stream.agentId !== "string" || stream.agentId.length === 0)
    throw new Error("cumulative spend reserve requires agentId");
  if (typeof stream.currency !== "string" || stream.currency.length === 0)
    throw new Error("cumulative spend reserve requires currency");

  const now = input.now ?? Date.now();
  const retentionCutoff = now - RETENTION_MS;
  if (
    input.reservationId !== undefined &&
    (input.reservationId.length === 0 ||
      input.reservationId.length > 200 ||
      input.reservationId.includes("|"))
  ) {
    throw new Error("invalid cumulative spend reservationId");
  }
  const reservationId = input.reservationId ?? `${now}:${nextSeq()}`;
  const member = `${reservationId}|${input.amount}|reserved`;
  const key = streamKey(stream);

  const capArgs: string[] = [];
  for (const cap of input.caps) {
    capArgs.push(String(now - cap.windowSeconds * 1000)); // windowStart (exclusive)
    capArgs.push(String(cap.max));
  }

  const redis = getRedis();
  const res = (await redis.eval(
    RESERVE_LUA,
    1,
    key,
    String(now),
    String(retentionCutoff),
    String(input.amount),
    String(RETENTION_MS),
    member,
    String(input.caps.length),
    ...capArgs,
  )) as number[];

  if (res[0] === -1) {
    throw new Error("cumulative spend stream contained a corrupt member");
  }
  const priorSums = res.slice(1);
  if (res[0] === 1) {
    return { ok: true, priorSums, reservationId };
  }
  return { ok: false, priorSums };
}

export async function reserveCumulativeSpendBatch(input: {
  groups: CumulativeSpendBatchGroup[];
  now?: number;
}): Promise<CumulativeSpendBatchResult> {
  if (!Array.isArray(input.groups) || input.groups.length === 0)
    throw new Error("cumulative spend batch requires at least one group");
  const now = input.now ?? Date.now();
  const keys: string[] = [];
  const args: string[] = [
    String(now),
    String(now - RETENTION_MS),
    String(RETENTION_MS),
    String(input.groups.length),
  ];
  for (const group of input.groups) {
    if (!group.stream.tenantId) throw new Error("batch stream requires tenantId");
    if (!isNonNegInt(group.amount)) throw new Error("invalid cumulative spend batch amount");
    if (!group.caps.length) throw new Error("batch group requires caps");
    if (
      !group.reservationId ||
      group.reservationId.length > 180 ||
      group.reservationId.includes("|")
    )
      throw new Error("invalid cumulative spend batch reservationId");
    for (const cap of group.caps) {
      if (!isNonNegInt(cap.max) || !isValidWindow(cap.windowSeconds))
        throw new Error("invalid cumulative spend batch cap");
    }
    keys.push(streamKey(group.stream));
    const member = `${group.reservationId}|${group.amount}|reserved`;
    args.push(String(group.amount), member, String(group.caps.length));
    for (const cap of group.caps) {
      args.push(String(now - cap.windowSeconds * 1000), String(cap.max));
    }
  }
  const redis = getRedis();
  const raw = (await redis.eval(RESERVE_BATCH_LUA, keys.length, ...keys, ...args)) as number[];
  if (raw[0] === -1) throw new Error("cumulative spend stream contained a corrupt member");
  let cursor = 1;
  const priorSums = input.groups.map((group) => {
    const values = raw.slice(cursor, cursor + group.caps.length);
    cursor += group.caps.length;
    return values;
  });
  return raw[0] === 1
    ? { ok: true, priorSums, reservationIds: input.groups.map((g) => g.reservationId) }
    : { ok: false, priorSums };
}

/**
 * Settle a successful reservation. The entry stays counted for the rest of the
 * window (it represents real spend), so this is a no-op mark today, kept for a
 * symmetric lifecycle + future per-state auditing. Never frees budget.
 */
export async function settleCumulativeSpend(_input: {
  stream: CumulativeSpendStream;
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
  stream: CumulativeSpendStream;
  reservationId: string;
  amount: number;
}): Promise<void> {
  if (!isNonNegInt(input.amount)) return;
  const key = streamKey(input.stream);
  const member = `${input.reservationId}|${input.amount}|reserved`;
  const redis = getRedis();
  await redis.zrem(key, member);
}

/**
 * Advisory read of the trailing-window sum (committed + reserved) for a single
 * cap window. Enforcement MUST use reserveCumulativeSpend (atomic); this is for
 * observability + the windowed-count read. Returns null on any I/O/parse failure
 * so the caller fails closed (deny).
 */
export async function getCumulativeSpendSum(
  input: CumulativeSpendStream & { windowSeconds: number; now?: number },
): Promise<CumulativeSpendSnapshot | null> {
  if (!isValidWindow(input.windowSeconds)) return null;
  const now = input.now ?? Date.now();
  const windowStart = now - input.windowSeconds * 1000;
  const retentionCutoff = now - RETENTION_MS;
  const key = streamKey(input);
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

/**
 * #206 configurable count cap (maxCalls + callWindow): ATOMICALLY reserve ONE
 * invoke against EVERY count window governing the operation. The invoke is added
 * to the operation-level `__calls__` stream EXACTLY ONCE (amount=1), and each
 * cap's window is checked atomically - so combining an hourly AND a daily cap
 * never double-counts a single invoke (codex P2), and concurrent invokes cannot
 * collectively exceed any cap (single-winner). Returns ok=false when ANY cap is
 * at its limit, plus the per-cap prior counts (same order as `caps`). Returns
 * { ok:false } on a Redis error (fail closed).
 */
export async function reserveWindowedInvoke(input: {
  tenantId?: string;
  agentId: string;
  operationKey: string;
  caps: CumulativeSpendCap[];
  now?: number;
  reservationId?: string;
}): Promise<{ ok: boolean; priorCounts: number[]; reservationId?: string }> {
  if (
    !Array.isArray(input.caps) ||
    input.caps.length === 0 ||
    input.caps.some((c) => !isValidWindow(c.windowSeconds) || !isNonNegInt(c.max))
  ) {
    return { ok: false, priorCounts: [] };
  }
  try {
    const res = await reserveCumulativeSpend({
      stream: {
        ...(input.tenantId ? { tenantId: input.tenantId } : {}),
        agentId: input.agentId,
        scope: "operation",
        scopeKey: input.operationKey,
        currency: WINDOWED_INVOKE_CURRENCY,
      },
      caps: input.caps,
      amount: 1,
      now: input.now,
      reservationId: input.reservationId,
    });
    return {
      ok: res.ok,
      priorCounts: res.priorSums,
      ...(res.reservationId !== undefined ? { reservationId: res.reservationId } : {}),
    };
  } catch {
    return { ok: false, priorCounts: [] };
  }
}

/**
 * Release a windowed-invoke reservation slot (KNOWN-FAILURE outcome only).
 */
export async function releaseWindowedInvoke(input: {
  tenantId?: string;
  agentId: string;
  operationKey: string;
  reservationId: string;
}): Promise<void> {
  await releaseCumulativeSpend({
    stream: {
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
      agentId: input.agentId,
      scope: "operation",
      scopeKey: input.operationKey,
      currency: WINDOWED_INVOKE_CURRENCY,
    },
    reservationId: input.reservationId,
    amount: 1,
  });
}

/**
 * Advisory read of the trailing-window invoke count for observability/tests.
 * Enforcement is reserveWindowedInvoke (atomic). Returns null on failure.
 */
export async function getWindowedInvokeCount(input: {
  tenantId?: string;
  agentId: string;
  operationKey: string;
  windowSeconds: number;
  now?: number;
}): Promise<number | null> {
  const snap = await getCumulativeSpendSum({
    ...(input.tenantId ? { tenantId: input.tenantId } : {}),
    agentId: input.agentId,
    scope: "operation",
    scopeKey: input.operationKey,
    currency: WINDOWED_INVOKE_CURRENCY,
    windowSeconds: input.windowSeconds,
    now: input.now,
  });
  return snap === null ? null : snap.sum;
}

export { streamKey as cumulativeSpendStreamKeyForTest };

/**
 * Durable, multi-replica idempotency for fund-moving trading routes.
 *
 * Callers first `check()` for an existing result, then invoke the returned
 * `claim()` immediately before the first externally mutating operation. The
 * claim is an atomic Redis SET PX NX (or a synchronous in-memory insertion),
 * so only one replica may execute. The owner replaces or releases its claim
 * with token-checked Lua CAS operations.
 */

import { createHash } from "node:crypto";
import type { IoredisLike } from "@stwd/redis";
import { redactedThrownDiagnostics } from "@stwd/shared";

export interface IdempotencyRecord {
  status: number;
  body: unknown;
}

export interface IdempotencyCheck<TRecord extends IdempotencyRecord> {
  conflict?: boolean;
  inProgress?: boolean;
  record?: TRecord;
  claim?: () => Promise<IdempotencyCheck<TRecord>>;
  store?: (record: TRecord) => Promise<void>;
  release?: () => Promise<void>;
}

const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MEMORY_ENTRIES = 1_000;

type PendingValue = { state: "pending"; bodyHash: string; claimToken: string };
type CompletedValue<TRecord> = {
  state: "completed";
  bodyHash: string;
  record: TRecord;
};

const COMPLETE_IF_OWNER = `
local current = redis.call("GET", KEYS[1])
if not current then return 0 end
local ok, decoded = pcall(cjson.decode, current)
if not ok or decoded["state"] ~= "pending" or decoded["claimToken"] ~= ARGV[1] then
  return 0
end
redis.call("SET", KEYS[1], ARGV[2], "PX", ARGV[3])
return 1
`;

const DELETE_IF_OWNER = `
local current = redis.call("GET", KEYS[1])
if not current then return 0 end
local ok, decoded = pcall(cjson.decode, current)
if not ok or decoded["state"] ~= "pending" or decoded["claimToken"] ~= ARGV[1] then
  return 0
end
return redis.call("DEL", KEYS[1])
`;

export class DurableIdempotencyStore<TRecord extends IdempotencyRecord> {
  private readonly memory = new Map<
    string,
    {
      bodyHash: string;
      state: "pending" | "completed";
      claimToken?: string;
      record?: TRecord;
      expiresAt: number;
    }
  >();

  constructor(
    private readonly options: {
      namespace: string;
      getRedisClient: () => IoredisLike | null;
    },
  ) {}

  private storageKey(scope: string, key: string): string {
    // Length-prefix before hashing so ambiguous tuples ("a:b", "c") and
    // ("a", "b:c") cannot alias. Hashing also keeps attacker-controlled
    // idempotency keys opaque and bounded in Redis and memory.
    return createHash("sha256")
      .update(`${scope.length}:${scope}${key.length}:${key}`, "utf8")
      .digest("hex");
  }

  private redisKey(scope: string, key: string): string {
    return `idempotency:${this.options.namespace}:${this.storageKey(scope, key)}`;
  }

  private sweepMemory(now: number): void {
    // Evict expired entries only. Live records protect in-flight fund movements
    // from replay, so capacity saturation must fail closed rather than discard
    // an active claim.
    for (const [entryKey, entry] of this.memory) {
      if (entry.expiresAt <= now) this.memory.delete(entryKey);
    }
  }

  private parseExisting(raw: string): PendingValue | CompletedValue<TRecord> {
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      throw new Error("Malformed durable idempotency record");
    }
    if (!value || typeof value !== "object") {
      throw new Error("Malformed durable idempotency record");
    }
    const candidate = value as Record<string, unknown>;
    // Records written by the earlier SEC-043 implementation remain replayable.
    if (typeof candidate.bodyHash === "string" && candidate.record && !candidate.state) {
      return {
        state: "completed",
        bodyHash: candidate.bodyHash,
        record: candidate.record as TRecord,
      };
    }
    if (
      candidate.state === "pending" &&
      typeof candidate.bodyHash === "string" &&
      typeof candidate.claimToken === "string"
    ) {
      return candidate as PendingValue;
    }
    if (
      candidate.state === "completed" &&
      typeof candidate.bodyHash === "string" &&
      candidate.record
    ) {
      return candidate as CompletedValue<TRecord>;
    }
    throw new Error("Malformed durable idempotency record");
  }

  private outcome(
    existing: PendingValue | CompletedValue<TRecord>,
    bodyHash: string,
  ): IdempotencyCheck<TRecord> {
    if (existing.bodyHash !== bodyHash) return { conflict: true };
    if (existing.state === "pending") return { inProgress: true };
    return { record: existing.record };
  }

  private ownerHandles(
    redis: IoredisLike,
    redisKey: string,
    bodyHash: string,
    claimToken: string,
  ): IdempotencyCheck<TRecord> {
    return {
      store: async (record) => {
        const completed: CompletedValue<TRecord> = { state: "completed", bodyHash, record };
        try {
          const replaced = await redis.eval(
            COMPLETE_IF_OWNER,
            1,
            redisKey,
            claimToken,
            JSON.stringify(completed),
            IDEMPOTENCY_TTL_MS,
          );
          if (Number(replaced) !== 1) {
            console.error("[idempotency] outcome was not persisted: claim ownership was lost");
          }
        } catch (err) {
          // The pending marker remains fail-closed, preventing a duplicate retry.
          console.error(
            "[idempotency] failed to persist outcome; claim remains pending",
            redactedThrownDiagnostics(err),
          );
        }
      },
      release: async () => {
        try {
          await redis.eval(DELETE_IF_OWNER, 1, redisKey, claimToken);
        } catch (err) {
          // A failed release leaves the claim pending, which is inconvenient
          // but safe: a later request must not execute while ownership is unknown.
          console.error(
            "[idempotency] failed to release pre-execution claim",
            redactedThrownDiagnostics(err),
          );
        }
      },
    };
  }

  private async claimRedis(
    redis: IoredisLike,
    redisKey: string,
    bodyHash: string,
  ): Promise<IdempotencyCheck<TRecord>> {
    const claimToken = crypto.randomUUID();
    const pending: PendingValue = { state: "pending", bodyHash, claimToken };
    const serialized = JSON.stringify(pending);
    const claimed = await redis.set(redisKey, serialized, "PX", IDEMPOTENCY_TTL_MS, "NX");
    if (claimed) return this.ownerHandles(redis, redisKey, bodyHash, claimToken);
    const raw = await redis.get(redisKey);
    // An expiry exactly between SET NX and GET is safe to retry once.
    if (raw === null) {
      const retry = await redis.set(redisKey, serialized, "PX", IDEMPOTENCY_TTL_MS, "NX");
      if (retry) return this.ownerHandles(redis, redisKey, bodyHash, claimToken);
      const raced = await redis.get(redisKey);
      if (raced === null) throw new Error("Unable to establish durable idempotency claim");
      return this.outcome(this.parseExisting(raced), bodyHash);
    }
    return this.outcome(this.parseExisting(raw), bodyHash);
  }

  async check(
    scope: string,
    key: string | undefined,
    bodyHash: string,
  ): Promise<IdempotencyCheck<TRecord>> {
    if (!key) return {};
    const now = Date.now();
    const redis = this.options.getRedisClient();
    if (redis) {
      const redisKey = this.redisKey(scope, key);
      const raw = await redis.get(redisKey);
      if (raw !== null) return this.outcome(this.parseExisting(raw), bodyHash);
      return { claim: () => this.claimRedis(redis, redisKey, bodyHash) };
    }

    if (
      (process.env.NODE_ENV === "production" ||
        process.env.STEWARD_RUNTIME === "workers" ||
        process.env.CF_PAGES === "1") &&
      process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY !== "true"
    ) {
      throw new Error(
        "Trading idempotency requires Redis in production; set STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY=true only for an explicitly single-instance deployment",
      );
    }

    const mapKey = this.storageKey(scope, key);
    const existing = this.memory.get(mapKey);
    if (existing && existing.expiresAt > now) {
      if (existing.bodyHash !== bodyHash) return { conflict: true };
      if (existing.state === "pending") return { inProgress: true };
      return { record: existing.record } as IdempotencyCheck<TRecord>;
    }
    return {
      claim: async () => {
        const claimNow = Date.now();
        const raced = this.memory.get(mapKey);
        if (raced && raced.expiresAt > claimNow) {
          if (raced.bodyHash !== bodyHash) return { conflict: true };
          if (raced.state === "pending") return { inProgress: true };
          return { record: raced.record } as IdempotencyCheck<TRecord>;
        }
        this.sweepMemory(claimNow);
        if (this.memory.size >= MAX_MEMORY_ENTRIES) {
          // Full of LIVE records: shedding an existing entry would silently
          // drop replay protection for an in-flight fund movement, and
          // admitting the new key anyway would let a flood grow the map
          // without bound. Fail closed — refuse the new claim.
          throw new Error(
            "Trading idempotency memory fallback is saturated with live records; refusing a new claim — configure Redis or retry after existing records expire",
          );
        }
        const claimToken = crypto.randomUUID();
        this.memory.set(mapKey, {
          bodyHash,
          state: "pending",
          claimToken,
          expiresAt: claimNow + IDEMPOTENCY_TTL_MS,
        });
        return {
          store: async (record) => {
            const current = this.memory.get(mapKey);
            if (current?.state !== "pending" || current.claimToken !== claimToken) return;
            this.memory.set(mapKey, {
              bodyHash,
              state: "completed",
              record,
              expiresAt: Date.now() + IDEMPOTENCY_TTL_MS,
            });
          },
          release: async () => {
            const current = this.memory.get(mapKey);
            if (current?.state === "pending" && current.claimToken === claimToken) {
              this.memory.delete(mapKey);
            }
          },
        };
      },
    };
  }
}

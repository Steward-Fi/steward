/**
 * Durable, multi-replica idempotency for fund-moving trading routes.
 *
 * Callers first `check()` for an existing result, then invoke the returned
 * `claim()` immediately before the first externally mutating operation. The
 * claim is an atomic Redis SET PX NX (or a synchronous in-memory insertion),
 * so only one replica may execute. The owner replaces or releases its claim
 * with token-checked Lua CAS operations.
 */

import type { IoredisLike } from "@stwd/redis";

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

  private redisKey(scope: string, key: string): string {
    return `idempotency:${this.options.namespace}:${scope}:${key}`;
  }

  private sweepMemory(now: number): void {
    for (const [entryKey, entry] of this.memory) {
      if (entry.expiresAt <= now || this.memory.size >= MAX_MEMORY_ENTRIES) {
        this.memory.delete(entryKey);
      }
      if (this.memory.size < MAX_MEMORY_ENTRIES) break;
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
          console.error("[idempotency] failed to persist outcome; claim remains pending:", err);
        }
      },
      release: async () => {
        try {
          await redis.eval(DELETE_IF_OWNER, 1, redisKey, claimToken);
        } catch (err) {
          // A failed release leaves the claim pending, which is inconvenient
          // but safe: a later request must not execute while ownership is unknown.
          console.error("[idempotency] failed to release pre-execution claim:", err);
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

    const mapKey = `${scope}:${key}`;
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

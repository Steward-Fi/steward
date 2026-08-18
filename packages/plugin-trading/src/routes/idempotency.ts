/**
 * Durable, claim-before-execute idempotency for fund-moving trading routes.
 *
 * A lookup is intentionally separate from `reserve()`: callers can replay a
 * completed response before consulting mutable session/venue state, then do
 * all safe validation and policy work before atomically claiming the key at
 * the last pre-execution boundary. Once claimed, the processing marker stays
 * for the full 24-hour window. A concurrent request, process restart, crash,
 * or failed completion write therefore fails closed instead of re-executing.
 */

import type { IoredisLike } from "@stwd/redis";
import { createHash } from "node:crypto";

export interface IdempotencyRecord {
  status: number;
  body: unknown;
}

export interface IdempotencyCheck<TRecord extends IdempotencyRecord> {
  conflict?: boolean;
  pending?: boolean;
  record?: TRecord;
  store?: (record: TRecord) => Promise<void>;
}

type StoredEntry<TRecord extends IdempotencyRecord> =
  | {
      bodyHash: string;
      state: "processing";
      claimId: string;
      claimedAt: number;
    }
  | {
      bodyHash: string;
      state: "completed";
      record: TRecord;
    };

const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MEMORY_ENTRIES = 1_000;

// Complete only the processing record created by this claimant. A stale owner
// must never overwrite a newer claim after its TTL has elapsed.
const COMPLETE_IF_OWNER_LUA = `
local current = redis.call("GET", KEYS[1])
if current ~= ARGV[1] then
  return 0
end
redis.call("SET", KEYS[1], ARGV[2], "PX", ARGV[3])
return 1
`;

export class DurableIdempotencyStore<TRecord extends IdempotencyRecord> {
  private readonly memory = new Map<string, { entry: StoredEntry<TRecord>; expiresAt: number }>();

  constructor(
    private readonly options: {
      /** Key prefix segment, e.g. "trade:hl" or "trade:operator". */
      namespace: string;
      getRedisClient: () => IoredisLike | null;
    },
  ) {}

  private storageKey(scope: string, key: string): string {
    const material = `${scope.length}:${scope}${key.length}:${key}`;
    return createHash("sha256").update(material).digest("hex");
  }

  private redisKey(scope: string, key: string): string {
    return `idempotency:${this.options.namespace}:${this.storageKey(scope, key)}`;
  }

  private memoryKey(scope: string, key: string): string {
    return this.storageKey(scope, key);
  }

  private assertMemoryFallbackAllowed(): void {
    if (
      process.env.NODE_ENV === "production" &&
      process.env.STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY !== "true"
    ) {
      throw new Error(
        "Durable Redis idempotency is required for production trading routes. " +
          "Configure Redis or explicitly acknowledge a single-instance deployment with " +
          "STEWARD_ALLOW_MEMORY_TRADING_IDEMPOTENCY=true.",
      );
    }
  }

  private sweepMemory(now: number): void {
    for (const [entryKey, entry] of this.memory) {
      if (entry.expiresAt <= now || this.memory.size >= MAX_MEMORY_ENTRIES) {
        this.memory.delete(entryKey);
      }
      if (this.memory.size < MAX_MEMORY_ENTRIES) break;
    }
  }

  private parseStored(raw: string): StoredEntry<TRecord> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error("Durable idempotency record is malformed");
    }
    if (!parsed || typeof parsed !== "object") {
      throw new Error("Durable idempotency record is malformed");
    }
    const value = parsed as Record<string, unknown>;
    if (typeof value.bodyHash !== "string") {
      throw new Error("Durable idempotency record is malformed");
    }
    if (
      value.state === "processing" &&
      typeof value.claimId === "string" &&
      typeof value.claimedAt === "number" &&
      Number.isFinite(value.claimedAt)
    ) {
      return value as StoredEntry<TRecord>;
    }
    if (value.state === "completed" && value.record && typeof value.record === "object") {
      const record = value.record as Record<string, unknown>;
      if (typeof record.status === "number" && Object.hasOwn(record, "body")) {
        return value as StoredEntry<TRecord>;
      }
    }
    throw new Error("Durable idempotency record is malformed");
  }

  private resultForExisting(
    entry: StoredEntry<TRecord>,
    bodyHash: string,
  ): IdempotencyCheck<TRecord> {
    if (entry.bodyHash !== bodyHash) return { conflict: true };
    if (entry.state === "processing") return { pending: true };
    return { record: entry.record };
  }

  /** Read an existing claim/outcome without claiming an absent key. */
  async check(
    scope: string,
    key: string | undefined,
    bodyHash: string,
  ): Promise<IdempotencyCheck<TRecord>> {
    if (!key) return {};
    const redis = this.options.getRedisClient();
    if (redis) {
      // Redis errors and malformed records both fail closed. Neither condition
      // can prove that a prior movement did not occur.
      const raw = await redis.get(this.redisKey(scope, key));
      return raw === null ? {} : this.resultForExisting(this.parseStored(raw), bodyHash);
    }
    this.assertMemoryFallbackAllowed();

    const now = Date.now();
    const mapKey = this.memoryKey(scope, key);
    const existing = this.memory.get(mapKey);
    if (!existing) return {};
    if (existing.expiresAt <= now) {
      this.memory.delete(mapKey);
      return {};
    }
    return this.resultForExisting(existing.entry, bodyHash);
  }

  /** Atomically claim an absent key immediately before an external side effect. */
  async reserve(
    scope: string,
    key: string | undefined,
    bodyHash: string,
  ): Promise<IdempotencyCheck<TRecord>> {
    if (!key) return {};
    const now = Date.now();
    const claim: StoredEntry<TRecord> = {
      bodyHash,
      state: "processing",
      claimId: crypto.randomUUID(),
      claimedAt: now,
    };
    const claimPayload = JSON.stringify(claim);
    const redis = this.options.getRedisClient();
    if (redis) {
      const redisKey = this.redisKey(scope, key);
      const reserved = await redis.set(redisKey, claimPayload, "PX", IDEMPOTENCY_TTL_MS, "NX");
      if (!reserved) {
        // SET NX and GET are separate operations. If the key expires between
        // them, retry the atomic reservation once; otherwise absence is
        // ambiguous and must fail closed.
        const raw = await redis.get(redisKey);
        if (raw === null) {
          const retried = await redis.set(redisKey, claimPayload, "PX", IDEMPOTENCY_TTL_MS, "NX");
          if (!retried) {
            const raced = await redis.get(redisKey);
            if (raced === null) throw new Error("Durable idempotency reservation is ambiguous");
            return this.resultForExisting(this.parseStored(raced), bodyHash);
          }
        } else {
          return this.resultForExisting(this.parseStored(raw), bodyHash);
        }
      }

      return {
        store: async (record) => {
          const completedPayload = JSON.stringify({
            bodyHash,
            state: "completed",
            record,
          } satisfies StoredEntry<TRecord>);
          try {
            const completed = await redis.eval(
              COMPLETE_IF_OWNER_LUA,
              1,
              redisKey,
              claimPayload,
              completedPayload,
              IDEMPOTENCY_TTL_MS,
            );
            if (Number(completed) !== 1) {
              console.error(
                "[idempotency] outcome was not persisted because claim ownership changed; retries remain fail-closed",
              );
            }
          } catch (err) {
            // The durable processing marker was written before execution and
            // remains in place. Return the real movement outcome, but keep all
            // retries fail-closed rather than risk a duplicate.
            console.error(
              "[idempotency] failed to complete the outcome record; retries remain fail-closed:",
              err,
            );
          }
        },
      };
    }
    this.assertMemoryFallbackAllowed();

    // Single-process fallback. JavaScript executes this check-and-set without
    // an await, so concurrent requests cannot both claim the same key.
    const mapKey = this.memoryKey(scope, key);
    const existing = this.memory.get(mapKey);
    if (existing && existing.expiresAt > now) {
      return this.resultForExisting(existing.entry, bodyHash);
    }
    if (existing) this.memory.delete(mapKey);
    this.sweepMemory(now);
    this.memory.set(mapKey, { entry: claim, expiresAt: now + IDEMPOTENCY_TTL_MS });
    return {
      store: async (record) => {
        const current = this.memory.get(mapKey);
        if (
          !current ||
          current.entry.state !== "processing" ||
          current.entry.claimId !== claim.claimId
        ) {
          return;
        }
        this.memory.set(mapKey, {
          entry: { bodyHash, state: "completed", record },
          expiresAt: Date.now() + IDEMPOTENCY_TTL_MS,
        });
      },
    };
  }
}

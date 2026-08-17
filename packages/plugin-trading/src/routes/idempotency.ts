/**
 * idempotency.ts — durable idempotency backing for the trade + operator routes
 * (SEC-043).
 *
 * Wave-2 bounded the process-local maps (1_000 entries + expired-sweep) and
 * stored ambiguous-outcome 502 envelopes, but the maps were still per-process:
 * a restart or a second replica silently lost dedup, so a retried
 * withdraw/order could double-execute a fund movement.
 *
 * This store keeps the wave-2 semantics and adds a Redis-backed record when a
 * client is available (production always has one — durable stores are asserted
 * at startup), keyed `idempotency:<namespace>:<scope>:<key>` with the same 24h
 * TTL. Without Redis it falls back to the bounded process-local map (dev /
 * single-replica), exactly like the routes' rate limiters.
 *
 * Semantics (unchanged from wave-2):
 *   - same key + same body      -> replay the stored outcome (no re-execution)
 *   - same key + DIFFERENT body -> conflict (the routes answer 409)
 *   - missing/expired           -> fresh; `store` records the final outcome
 *                                  (success OR ambiguous 502) so retries replay
 *
 * Failure posture:
 *   - a Redis error on CHECK fails CLOSED (throws): executing without the
 *     dedup record risks a double fund-movement; the caller's retry replays
 *     once Redis recovers.
 *   - a Redis error on STORE is logged and swallowed: the movement already
 *     executed, so the caller must still see the real outcome. A later retry
 *     may re-execute — the same accepted residual as a crash between venue
 *     execution and persistence.
 *
 * Known residual (pre-existing, unchanged): two requests with the same key
 * in-flight CONCURRENTLY can both pass the check before either stores. This
 * store closes the sequential-retry / restart / multi-replica gaps the audit
 * flagged; claim-before-execute hardening is separate work.
 */

import type { IoredisLike } from "@stwd/redis";

export interface IdempotencyRecord {
  status: number;
  body: unknown;
}

export interface IdempotencyCheck<TRecord extends IdempotencyRecord> {
  conflict?: boolean;
  record?: TRecord;
  store?: (record: TRecord) => Promise<void>;
}

const IDEMPOTENCY_TTL_MS = 24 * 60 * 60 * 1000;
const MAX_MEMORY_ENTRIES = 1_000;

export class DurableIdempotencyStore<TRecord extends IdempotencyRecord> {
  private readonly memory = new Map<
    string,
    { bodyHash: string; record: TRecord; expiresAt: number }
  >();

  constructor(
    private readonly options: {
      /** Key prefix segment, e.g. "trade" or "trade:operator". */
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

  /**
   * Look up `key` within `scope`. `bodyHash` is the caller-computed canonical
   * body fingerprint; a mismatch on an existing entry is a conflict.
   */
  async check(
    scope: string,
    key: string | undefined,
    bodyHash: string,
  ): Promise<IdempotencyCheck<TRecord>> {
    if (!key) return {};
    const now = Date.now();
    const redis = this.options.getRedisClient();
    if (redis) {
      // Fail CLOSED on a Redis error (see the module doc).
      const raw = await redis.get(this.redisKey(scope, key));
      if (raw !== null) {
        let existing: { bodyHash?: unknown; record?: unknown } | null = null;
        try {
          existing = JSON.parse(raw) as { bodyHash?: unknown; record?: unknown };
        } catch {
          existing = null;
        }
        if (typeof existing?.bodyHash === "string" && existing.record) {
          if (existing.bodyHash !== bodyHash) return { conflict: true };
          return { record: existing.record as TRecord };
        }
        // An unparsable entry cannot vouch for a prior execution — treat as
        // absent and let store() overwrite it below.
      }
      return {
        store: async (record) => {
          const payload = JSON.stringify({ bodyHash, record });
          await redis
            .set(this.redisKey(scope, key), payload, "PX", IDEMPOTENCY_TTL_MS)
            .catch((err) => {
              // The movement already executed; losing the record means a later
              // retry re-executes. Log loudly — nothing safer remains.
              console.error(
                "[idempotency] failed to persist the outcome record; a retry may re-execute:",
                err,
              );
            });
        },
      };
    }

    // Process-local fallback (dev / single-replica): bounded + swept, mirroring
    // the wave-2 maps.
    const mapKey = `${scope}:${key}`;
    const existing = this.memory.get(mapKey);
    if (existing && existing.expiresAt > now) {
      if (existing.bodyHash !== bodyHash) return { conflict: true };
      return { record: existing.record };
    }
    return {
      store: async (record) => {
        this.sweepMemory(now);
        this.memory.set(mapKey, { bodyHash, record, expiresAt: now + IDEMPOTENCY_TTL_MS });
      },
    };
  }
}

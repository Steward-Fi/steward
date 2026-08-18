import { createHash, randomUUID } from "node:crypto";
import type { IoredisLike } from "@stwd/redis";

export type TradeVenue = "hyperliquid" | "polymarket";

export interface TradeIdempotencyEnvelope {
  status: 200 | 202 | 400 | 403 | 409 | 502 | 503;
  body: unknown;
  headers?: Record<string, string>;
}

export interface TradeIdempotencyRequest {
  tenantId: string;
  agentId: string;
  venue: TradeVenue;
  key: string;
  body: unknown;
}

interface StoredRecord {
  v: 1;
  bodyHash: string;
  state: "inflight" | "complete" | "submission_unknown";
  owner: string;
  response?: TradeIdempotencyEnvelope;
  auditState?: "pending" | "recorded";
  expiresAt?: number;
}

export type TradeIdempotencyLookup =
  | { kind: "missing" }
  | { kind: "conflict" }
  | { kind: "inflight" }
  | {
      kind: "replay";
      response: TradeIdempotencyEnvelope;
      auditState: "pending" | "recorded";
      submissionState: "complete" | "submission_unknown";
    };

export interface TradeIdempotencyClaim {
  storage: "redis" | "memory";
  redisKey: string;
  memoryKey: string;
  bodyHash: string;
  owner: string;
}

export type TradeIdempotencyClaimResult =
  | { kind: "claimed"; claim: TradeIdempotencyClaim }
  | Exclude<TradeIdempotencyLookup, { kind: "missing" }>;

const CLAIM_SCRIPT = `
-- steward-trade-idempotency-claim-v1
local current = redis.call("GET", KEYS[1])
if not current then
  redis.call("SET", KEYS[1], ARGV[3], "PX", ARGV[4], "NX")
  return {"claimed"}
end
local ok, record = pcall(cjson.decode, current)
if not ok or record.v ~= 1 or type(record.bodyHash) ~= "string" then
  return {"corrupt"}
end
if record.bodyHash ~= ARGV[1] then return {"conflict"} end
if (record.state == "complete" or record.state == "submission_unknown") and record.response ~= nil then
  return {"replay", current}
end
return {"inflight"}
`;

const COMPLETE_SCRIPT = `
-- steward-trade-idempotency-complete-v1
local current = redis.call("GET", KEYS[1])
if not current then return {"missing"} end
local ok, record = pcall(cjson.decode, current)
if not ok or record.v ~= 1 then return {"corrupt"} end
if record.bodyHash ~= ARGV[1] then return {"conflict"} end
if record.owner ~= ARGV[2] then return {"not_owner"} end
redis.call("SET", KEYS[1], ARGV[3])
return {"stored"}
`;

const DEFAULT_INFLIGHT_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_MEMORY_ENTRIES = 2_000;

export class TradeIdempotencyUnavailableError extends Error {
  constructor(message = "Durable trade idempotency is unavailable") {
    super(message);
    this.name = "TradeIdempotencyUnavailableError";
  }
}

export function normalizeTradeIdempotencyKey(
  headerValue: string | undefined,
  bodyValue: string | undefined,
): { ok: true; key: string } | { ok: false; error: string } {
  const header = headerValue?.trim();
  const body = bodyValue?.trim();
  if (header && body && header !== body) {
    return { ok: false, error: "Idempotency-Key header and body value must match" };
  }
  const key = header || body;
  if (!key) return { ok: false, error: "Idempotency-Key is required" };
  if (key.length > 256) {
    return { ok: false, error: "Idempotency-Key must be at most 256 characters" };
  }
  return { ok: true, key };
}

export function allowInMemoryTradeIdempotency(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.NODE_ENV === "test" || env.STEWARD_ALLOW_IN_MEMORY_TRADE_IDEMPOTENCY === "true";
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value: unknown, inArray = false): string | undefined {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value))
      throw new TypeError("trade idempotency body contains non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item, true) ?? "null").join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .flatMap(([key, item]) => {
        const encoded = canonicalJson(item);
        return encoded === undefined ? [] : [`${JSON.stringify(key)}:${encoded}`];
      });
    return `{${entries.join(",")}}`;
  }
  return inArray ? "null" : undefined;
}

function requestBodyHash(body: unknown): string {
  const canonical = canonicalJson(body);
  if (canonical === undefined) throw new TypeError("trade idempotency body is not serializable");
  return sha256(canonical);
}

function redisKey(input: TradeIdempotencyRequest): string {
  return `trade:idempotency:v1:${sha256(
    JSON.stringify([input.tenantId, input.agentId, input.venue, input.key]),
  )}`;
}

function memoryKey(input: TradeIdempotencyRequest): string {
  return `${input.tenantId}\u0000${input.agentId}\u0000${input.venue}\u0000${input.key}`;
}

function decodeRecord(raw: string): StoredRecord | null {
  try {
    const value = JSON.parse(raw) as Partial<StoredRecord>;
    if (
      value.v !== 1 ||
      typeof value.bodyHash !== "string" ||
      (value.state !== "inflight" &&
        value.state !== "complete" &&
        value.state !== "submission_unknown") ||
      typeof value.owner !== "string" ||
      (value.state === "inflight" && typeof value.expiresAt !== "number")
    ) {
      return null;
    }
    return value as StoredRecord;
  } catch {
    return null;
  }
}

function lookupRecord(record: StoredRecord, bodyHash: string): TradeIdempotencyLookup {
  if (record.bodyHash !== bodyHash) return { kind: "conflict" };
  if (record.state === "inflight" || !record.response) return { kind: "inflight" };
  return {
    kind: "replay",
    response: record.response,
    auditState: record.auditState ?? "pending",
    submissionState: record.state,
  };
}

export class TradeOrderIdempotencyStore {
  private readonly memory = new Map<string, StoredRecord>();
  private readonly inflightTtlMs: number;
  private readonly maxMemoryEntries: number;
  private readonly memoryAllowed: boolean;

  constructor(
    private readonly getRedisClient: () => IoredisLike | null,
    options: {
      inflightTtlMs?: number;
      maxMemoryEntries?: number;
      allowMemory?: boolean;
    } = {},
  ) {
    this.inflightTtlMs = options.inflightTtlMs ?? DEFAULT_INFLIGHT_TTL_MS;
    this.maxMemoryEntries = options.maxMemoryEntries ?? DEFAULT_MAX_MEMORY_ENTRIES;
    this.memoryAllowed = options.allowMemory ?? allowInMemoryTradeIdempotency();
    if (!Number.isSafeInteger(this.inflightTtlMs) || this.inflightTtlMs < 1_000) {
      throw new Error("trade idempotency inflight ttl must be at least 1 second");
    }
    if (!Number.isSafeInteger(this.maxMemoryEntries) || this.maxMemoryEntries < 1) {
      throw new Error("trade idempotency memory bound must be positive");
    }
  }

  private cleanupMemory(now: number): void {
    for (const [key, record] of this.memory) {
      if (record.state === "inflight" && (record.expiresAt ?? 0) <= now) this.memory.delete(key);
    }
    while (this.memory.size > this.maxMemoryEntries) {
      const oldest = this.memory.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.memory.delete(oldest);
    }
  }

  private backend(): { redis: IoredisLike | null; useMemory: boolean } {
    const redis = this.getRedisClient();
    if (redis) return { redis, useMemory: false };
    if (this.memoryAllowed) return { redis: null, useMemory: true };
    throw new TradeIdempotencyUnavailableError();
  }

  async lookup(input: TradeIdempotencyRequest): Promise<TradeIdempotencyLookup> {
    const bodyHash = requestBodyHash(input.body);
    const key = redisKey(input);
    const backend = this.backend();
    if (backend.redis) {
      let raw: string | null;
      try {
        raw = await backend.redis.get(key);
      } catch {
        throw new TradeIdempotencyUnavailableError("Trade idempotency lookup failed");
      }
      if (raw === null) return { kind: "missing" };
      const record = decodeRecord(raw);
      if (!record) throw new TradeIdempotencyUnavailableError("Trade idempotency state is corrupt");
      return lookupRecord(record, bodyHash);
    }

    const now = Date.now();
    this.cleanupMemory(now);
    const record = this.memory.get(memoryKey(input));
    return record ? lookupRecord(record, bodyHash) : { kind: "missing" };
  }

  async claim(input: TradeIdempotencyRequest): Promise<TradeIdempotencyClaimResult> {
    const bodyHash = requestBodyHash(input.body);
    const rKey = redisKey(input);
    const mKey = memoryKey(input);
    const owner = randomUUID();
    const expiresAt = Date.now() + this.inflightTtlMs;
    const record: StoredRecord = {
      v: 1,
      bodyHash,
      state: "inflight",
      owner,
      expiresAt,
    };
    const backend = this.backend();
    if (backend.redis) {
      let result: unknown;
      try {
        result = await backend.redis.eval(
          CLAIM_SCRIPT,
          1,
          rKey,
          bodyHash,
          owner,
          JSON.stringify(record),
          this.inflightTtlMs,
        );
      } catch {
        throw new TradeIdempotencyUnavailableError("Trade idempotency claim failed");
      }
      if (!Array.isArray(result) || typeof result[0] !== "string") {
        throw new TradeIdempotencyUnavailableError("Trade idempotency claim returned invalid data");
      }
      if (result[0] === "claimed") {
        return {
          kind: "claimed",
          claim: { storage: "redis", redisKey: rKey, memoryKey: mKey, bodyHash, owner },
        };
      }
      if (result[0] === "conflict") return { kind: "conflict" };
      if (result[0] === "inflight") return { kind: "inflight" };
      if (result[0] === "replay" && typeof result[1] === "string") {
        const existing = decodeRecord(result[1]);
        if (existing) return lookupRecord(existing, bodyHash) as TradeIdempotencyClaimResult;
      }
      throw new TradeIdempotencyUnavailableError("Trade idempotency claim state is corrupt");
    }

    const now = Date.now();
    this.cleanupMemory(now);
    const existing = this.memory.get(mKey);
    if (existing) return lookupRecord(existing, bodyHash) as TradeIdempotencyClaimResult;
    this.memory.set(mKey, record);
    this.cleanupMemory(now);
    return {
      kind: "claimed",
      claim: { storage: "memory", redisKey: rKey, memoryKey: mKey, bodyHash, owner },
    };
  }

  async complete(
    claim: TradeIdempotencyClaim,
    response: TradeIdempotencyEnvelope,
    auditState: "pending" | "recorded" = "recorded",
    submissionState: "complete" | "submission_unknown" = "complete",
  ): Promise<void> {
    const record: StoredRecord = {
      v: 1,
      bodyHash: claim.bodyHash,
      state: submissionState,
      owner: claim.owner,
      response,
      auditState,
    };
    if (claim.storage === "redis") {
      const redis = this.getRedisClient();
      if (!redis) throw new TradeIdempotencyUnavailableError();
      let result: unknown;
      try {
        result = await redis.eval(
          COMPLETE_SCRIPT,
          1,
          claim.redisKey,
          claim.bodyHash,
          claim.owner,
          JSON.stringify(record),
        );
      } catch {
        throw new TradeIdempotencyUnavailableError("Trade idempotency completion failed");
      }
      if (!Array.isArray(result) || result[0] !== "stored") {
        throw new TradeIdempotencyUnavailableError("Trade idempotency completion was not stored");
      }
      return;
    }

    const current = this.memory.get(claim.memoryKey);
    if (!current || current.bodyHash !== claim.bodyHash || current.owner !== claim.owner) {
      throw new TradeIdempotencyUnavailableError("Trade idempotency completion lost its claim");
    }
    this.memory.delete(claim.memoryKey);
    this.memory.set(claim.memoryKey, record);
  }

  async markSubmissionUnknown(
    claim: TradeIdempotencyClaim,
    response: TradeIdempotencyEnvelope,
    auditState: "pending" | "recorded" = "pending",
  ): Promise<void> {
    await this.complete(claim, response, auditState, "submission_unknown");
  }

  /** Test-only observability for the bounded fallback. */
  memoryEntryCountForTests(): number {
    return this.memory.size;
  }
}

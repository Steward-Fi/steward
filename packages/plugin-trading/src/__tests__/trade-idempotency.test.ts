import { describe, expect, it } from "bun:test";
import type { IoredisLike } from "@stwd/redis";
import {
  allowInMemoryTradeIdempotency,
  normalizeTradeIdempotencyKey,
  type TradeIdempotencyRequest,
  TradeOrderIdempotencyStore,
} from "../trade-idempotency";

class AtomicRedisStub {
  private readonly values = new Map<string, { value: string; expiresAt?: number }>();
  private now = 0;

  advance(ms: number): void {
    this.now += ms;
  }

  private read(key: string): string | null {
    const entry = this.values.get(key);
    if (!entry) return null;
    if (entry.expiresAt !== undefined && entry.expiresAt <= this.now) {
      this.values.delete(key);
      return null;
    }
    return entry.value;
  }

  async get(key: string): Promise<string | null> {
    return this.read(key);
  }

  async eval(script: string, _numKeys: number, ...args: (string | number)[]): Promise<unknown> {
    const [key, bodyHash, owner, serialized] = args.map(String);
    const current = this.read(key);
    if (script.includes("steward-trade-idempotency-claim-v1")) {
      if (!current) {
        this.values.set(key, { value: serialized, expiresAt: this.now + Number(args[4]) });
        return ["claimed"];
      }
      const record = JSON.parse(current) as {
        bodyHash: string;
        state: string;
        response?: unknown;
      };
      if (record.bodyHash !== bodyHash) return ["conflict"];
      if (
        (record.state === "complete" || record.state === "submission_unknown") &&
        record.response !== undefined
      ) {
        return ["replay", current];
      }
      return ["inflight"];
    }
    if (script.includes("steward-trade-idempotency-complete-v1")) {
      if (!current) return ["missing"];
      const record = JSON.parse(current) as { bodyHash: string; owner: string };
      if (record.bodyHash !== bodyHash) return ["conflict"];
      if (record.owner !== owner) return ["not_owner"];
      this.values.set(key, { value: serialized });
      return ["stored"];
    }
    throw new Error("unexpected script");
  }

  client(): IoredisLike {
    return this as unknown as IoredisLike;
  }
}

function request(key: string, body: unknown = { sessionId: "session-1", amount: 10 }) {
  return {
    tenantId: "tenant-1",
    agentId: "agent-1",
    venue: "polymarket" as const,
    key,
    body,
  } satisfies TradeIdempotencyRequest;
}

describe("trade order idempotency", () => {
  it("allows memory only for tests or an explicit opt-in", () => {
    expect(allowInMemoryTradeIdempotency({ NODE_ENV: "test" })).toBe(true);
    expect(
      allowInMemoryTradeIdempotency({ STEWARD_ALLOW_IN_MEMORY_TRADE_IDEMPOTENCY: "true" }),
    ).toBe(true);
    expect(allowInMemoryTradeIdempotency({ STEWARD_RUNTIME: "embedded" })).toBe(false);
    expect(allowInMemoryTradeIdempotency({ NODE_ENV: "production" })).toBe(false);
  });

  it("normalizes matching keys and rejects missing or mismatched values", () => {
    expect(normalizeTradeIdempotencyKey(" key-1 ", "key-1")).toEqual({
      ok: true,
      key: "key-1",
    });
    expect(normalizeTradeIdempotencyKey(undefined, undefined)).toEqual({
      ok: false,
      error: "Idempotency-Key is required",
    });
    expect(normalizeTradeIdempotencyKey("key-1", "key-2")).toEqual({
      ok: false,
      error: "Idempotency-Key header and body value must match",
    });
  });

  it("replays the same response and conflicts on a different body", async () => {
    const store = new TradeOrderIdempotencyStore(() => null, { allowMemory: true });
    const first = await store.claim(request("replay"));
    expect(first.kind).toBe("claimed");
    if (first.kind !== "claimed") throw new Error("claim expected");
    const response = { status: 200 as const, body: { ok: true, orderId: "order-1" } };
    await store.complete(first.claim, response);

    expect(await store.claim(request("replay"))).toEqual({
      kind: "replay",
      response,
      auditState: "recorded",
      submissionState: "complete",
    });
    expect(await store.claim(request("replay", { sessionId: "session-1", amount: 11 }))).toEqual({
      kind: "conflict",
    });
  });

  it("rejects a concurrent duplicate while the first submission is in flight", async () => {
    const store = new TradeOrderIdempotencyStore(() => null, { allowMemory: true });
    expect((await store.claim(request("inflight"))).kind).toBe("claimed");
    expect(await store.claim(request("inflight"))).toEqual({ kind: "inflight" });
  });

  it("replays across independent router stores through shared Redis state", async () => {
    const redis = new AtomicRedisStub();
    const routerA = new TradeOrderIdempotencyStore(() => redis.client());
    const routerB = new TradeOrderIdempotencyStore(() => redis.client());
    const first = await routerA.claim(request("cross-router"));
    expect(first.kind).toBe("claimed");
    if (first.kind !== "claimed") throw new Error("claim expected");
    const response = {
      status: 200 as const,
      body: { ok: true, orderId: "durable-order" },
      headers: { "X-Steward-Audit-State": "pending" },
    };
    await routerA.complete(first.claim, response, "pending");

    expect(await routerB.lookup(request("cross-router"))).toEqual({
      kind: "replay",
      response,
      auditState: "pending",
      submissionState: "complete",
    });
  });

  it("keeps submission-unknown terminal state after the inflight lease would expire", async () => {
    const redis = new AtomicRedisStub();
    const store = new TradeOrderIdempotencyStore(() => redis.client(), {
      inflightTtlMs: 1_000,
    });
    const first = await store.claim(request("unknown-terminal"));
    expect(first.kind).toBe("claimed");
    if (first.kind !== "claimed") throw new Error("claim expected");
    const response = {
      status: 202 as const,
      body: {
        ok: false,
        error: "Trade submission status unknown; operator reconciliation is required",
      },
      headers: { "X-Steward-Order-State": "submission_unknown" },
    };
    await store.markSubmissionUnknown(first.claim, response, "pending");

    redis.advance(60_000);
    expect(await store.claim(request("unknown-terminal"))).toEqual({
      kind: "replay",
      response,
      auditState: "pending",
      submissionState: "submission_unknown",
    });
  });

  it("evicts old fallback entries instead of growing without bound", async () => {
    const store = new TradeOrderIdempotencyStore(() => null, {
      allowMemory: true,
      maxMemoryEntries: 2,
    });
    await store.claim(request("one"));
    await store.claim(request("two"));
    await store.claim(request("three"));

    expect(store.memoryEntryCountForTests()).toBe(2);
    expect(await store.lookup(request("one"))).toEqual({ kind: "missing" });
    expect((await store.lookup(request("three"))).kind).toBe("inflight");
  });
});

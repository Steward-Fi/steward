import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { parseSubmitTrade, submitTradeAction } from "../actions/submit-trade.js";

const OLD_ENV = { ...process.env };

function setTradeEnv() {
  process.env.STEWARD_API_URL = "https://steward.example";
  process.env.STEWARD_JWT = "jwt-test";
  process.env.STEWARD_TRADE_SESSION_ID = "ses_test";
}

function mockMemory(text: string) {
  return { content: { text } } as any;
}

describe("SUBMIT_TRADE action", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    process.env = { ...OLD_ENV };
    setTradeEnv();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    process.env = { ...OLD_ENV };
  });

  it("has the expected Eliza action metadata", () => {
    expect(submitTradeAction.name).toBe("SUBMIT_TRADE");
    expect(submitTradeAction.similes).toEqual(["buy", "sell", "long", "short", "perp", "trade"]);
    expect(submitTradeAction.description).toContain("Requires active trade session");
    expect(submitTradeAction.examples?.length).toBeGreaterThanOrEqual(4);
  });

  it("parses buy/long market orders from text", () => {
    expect(parseSubmitTrade(mockMemory("buy 0.05 BTC long"), undefined, {} as any)).toMatchObject({
      coin: "BTC",
      side: "buy",
      size: 0.05,
      sessionId: "ses_test",
    });
  });

  it("parses sell/short limit orders from text", () => {
    expect(
      parseSubmitTrade(mockMemory("sell 0.1 ETH short limit 3450"), undefined, {} as any),
    ).toMatchObject({
      coin: "ETH",
      side: "sell",
      size: 0.1,
      limitPx: 3450,
    });
  });

  it("validate checks env and active session", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: true, data: { status: "active" } }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      submitTradeAction.validate({} as any, mockMemory("buy 0.01 BTC") as any),
    ).resolves.toBe(true);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://steward.example/v1/trade/sessions/ses_test",
      expect.objectContaining({
        headers: { Authorization: "Bearer jwt-test", Accept: "application/json" },
        redirect: "error",
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("posts parsed order with Bearer JWT and returns confirmation", async () => {
    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            ok: true,
            data: { orderId: "oid_1", status: "open", filledQty: 0, avgPrice: 0, txHash: null },
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const result = await submitTradeAction.handler(
      {} as any,
      mockMemory("buy 0.01 BTC long") as any,
    );

    expect(result?.success).toBe(true);
    expect(result?.text).toBe(
      "submitted: long 0.01 BTC at market via hyperliquid. order id oid_1.",
    );
    const [, request] = fetchMock.mock.calls[0];
    expect(fetchMock.mock.calls[0][0]).toBe("https://steward.example/v1/trade/hyperliquid/order");
    expect(request.headers.Authorization).toBe("Bearer jwt-test");
    expect(request.redirect).toBe("error");
    expect(request.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(request.body)).toMatchObject({
      sessionId: "ses_test",
      coin: "BTC",
      side: "buy",
      size: 0.01,
      leverage: 1,
      reduceOnly: false,
    });
  });

  it("surfaces policy violations from Steward", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({ code: "policy-violation", reason: "leverage-cap: max 2x" }),
            {
              status: 400,
            },
          ),
      ),
    );

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 1 BTC 3x") as any);
    expect(result?.success).toBe(false);
    expect(result?.text).toBe("policy rejected: leverage-cap: max 2x");
  });

  it("handles expired JWT gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "invalid-jwt" }), { status: 401 })),
    );

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);
    expect(result?.success).toBe(false);
    expect(result?.text).toBe("session expired or invalid, ask shadow to refresh");
  });

  it("handles venue/server errors gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "HL unavailable" }), { status: 502 })),
    );

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);
    expect(result?.success).toBe(false);
    expect(result?.text).toBe("venue error, will retry later");
  });

  it("rejects oversized chunked responses without reflecting their contents", async () => {
    const secretCanary = "provider-secret-canary";
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("x".repeat(1024 * 1024)));
        controller.enqueue(new TextEncoder().encode(secretCanary));
      },
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 502 })),
    );

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);

    expect(result?.success).toBe(false);
    expect(result?.text).toBe("venue error, will retry later");
    expect(JSON.stringify(result)).not.toContain(secretCanary);
    expect(cancelled).toBe(true);
  });

  it("aborts a stalled request at the bounded deadline", async () => {
    vi.useFakeTimers();
    let observedSignal: AbortSignal | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_url: string, init?: RequestInit) =>
          await new Promise<Response>((_resolve, reject) => {
            observedSignal = init?.signal as AbortSignal;
            observedSignal.addEventListener(
              "abort",
              () => reject(new Error("secret socket error")),
              {
                once: true,
              },
            );
          }),
      ),
    );

    const pending = submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await pending;

    expect(observedSignal?.aborted).toBe(true);
    expect(result?.success).toBe(false);
    expect(result?.text).toBe("venue error, will retry later");
    expect(JSON.stringify(result)).not.toContain("secret socket error");
  });

  it("cancels a stalled response body at the same bounded deadline", async () => {
    vi.useFakeTimers();
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull: () => new Promise<void>(() => {}),
      cancel() {
        cancelled = true;
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status: 502 })),
    );

    const pending = submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);
    await vi.advanceTimersByTimeAsync(10_000);
    const result = await pending;

    expect(cancelled).toBe(true);
    expect(result?.success).toBe(false);
    expect(result?.error).toBe("Steward request timed out");
    expect(result?.text).toBe("venue error, will retry later");
  });

  it("removes its response-body abort listener after a completed response", async () => {
    let signal: AbortSignal | undefined;
    let addSpy: ReturnType<typeof vi.spyOn> | undefined;
    let removeSpy: ReturnType<typeof vi.spyOn> | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init?: RequestInit) => {
        signal = init?.signal as AbortSignal;
        addSpy = vi.spyOn(signal, "addEventListener");
        removeSpy = vi.spyOn(signal, "removeEventListener");
        return new Response(JSON.stringify({ error: "HL unavailable" }), { status: 502 });
      }),
    );

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);

    expect(result?.success).toBe(false);
    expect(addSpy).toHaveBeenCalledTimes(1);
    const listener = addSpy?.mock.calls[0]?.[1];
    expect(removeSpy).toHaveBeenCalledWith("abort", listener);
    expect(signal?.aborted).toBe(false);
  });

  it("rejects a non-localhost plaintext STEWARD_API_URL before any request", async () => {
    process.env.STEWARD_API_URL = "http://steward.example";
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      submitTradeAction.validate({} as any, mockMemory("buy 0.01 BTC") as any),
    ).resolves.toBe(false);

    const result = await submitTradeAction.handler({} as any, mockMemory("buy 0.01 BTC") as any);
    expect(result?.success).toBe(false);
    expect(result?.text).toBe(
      "Trading is unavailable because Steward JWT/API env is not configured.",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still allows loopback http STEWARD_API_URL for local dev", async () => {
    process.env.STEWARD_API_URL = "http://127.0.0.1:7860";
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ ok: true, data: { status: "active" } }), { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      submitTradeAction.validate({} as any, mockMemory("buy 0.01 BTC") as any),
    ).resolves.toBe(true);
  });
});

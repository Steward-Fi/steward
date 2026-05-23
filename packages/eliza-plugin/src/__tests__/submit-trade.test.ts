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
    expect(fetchMock).toHaveBeenCalledWith("https://steward.example/v1/trade/sessions/ses_test", {
      headers: { Authorization: "Bearer jwt-test", Accept: "application/json" },
    });
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
});

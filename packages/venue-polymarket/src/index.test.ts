import { describe, expect, test } from "bun:test";
import type { EthersSignerLike, PolymarketAccount } from "./credentials";
import { listPositions } from "./data";
import { normalizeGammaMarket } from "./discovery";
import { sdkEffectiveSize } from "./execution";
import {
  createPolymarketBuilderConfig,
  deriveActualFill,
  getClobTokenIds,
  getOutcomePrices,
  getOutcomes,
  isBuilderEnabled,
  isPolymarketUnauthorized,
  PolymarketExecutionAdapter,
  parseMaybeJsonArray,
  resolveBuilderConfig,
  roundOrderSize,
  toClobCompatibleSigner,
} from "./index";
import { getBatchPriceHistory, getOrderbooks, getPriceHistory, getPrices } from "./marketdata";

// ---------------------------------------------------------------------------
// Test fixtures — a fake signer + account. NO network.
// ---------------------------------------------------------------------------

const FUNDER = "0x0985cCC0fD7C568d493874D845471D5F4B1D9c3c";
const SIGNER_ADDR = "0x1111111111111111111111111111111111111111";

const fakeSigner: EthersSignerLike = {
  address: SIGNER_ADDR,
  async getAddress() {
    return SIGNER_ADDR;
  },
  async signMessage() {
    return "0xsig";
  },
  async signTypedData() {
    return "0xtyped";
  },
};

const account: PolymarketAccount = {
  apiCredentials: { key: "k", secret: "s", passphrase: "p" },
  funderAddress: FUNDER,
  signer: fakeSigner,
};

// A fetch that never touches the network; asserts no call slips through unless allowed.
function notFetch(): typeof fetch {
  return (async () => {
    throw new Error("network not allowed in this test");
  }) as unknown as typeof fetch;
}

// ---------------------------------------------------------------------------
// Precision rounding — BUY 2dp / SELL 5dp asymmetry
// ---------------------------------------------------------------------------

describe("roundOrderSize precision", () => {
  test("BUY converts USD->shares and rounds DOWN to 2 decimals", () => {
    // $10 at price 0.37 = 27.027... shares -> 27.02 (floor 2dp)
    expect(roundOrderSize("buy", 10, 0.37)).toBe(27.02);
  });

  test("BUY floors, never rounds up", () => {
    // $1 at 0.33 = 3.0303 -> 3.03
    expect(roundOrderSize("buy", 1, 0.33)).toBe(3.03);
  });

  test("BUY throws when price <= 0", () => {
    expect(() => roundOrderSize("buy", 10, 0)).toThrow();
  });

  test("SELL rounds shares to 5 decimals (floor)", () => {
    expect(roundOrderSize("sell", 12.3456789, 0.5)).toBe(12.34567);
  });

  test("SELL keeps small share amounts", () => {
    expect(roundOrderSize("sell", 0.000019, 0.5)).toBe(0.00001);
  });

  test("sdkEffectiveSize floors to 2dp (the SDK's internal size rounding)", () => {
    expect(sdkEffectiveSize(0.005)).toBe(0); // SDK would zero this out
    expect(sdkEffectiveSize(12.34567)).toBe(12.34);
    expect(sdkEffectiveSize(0.01)).toBe(0.01);
  });
});

// ---------------------------------------------------------------------------
// deriveActualFill — making/taking -> actual amount/price
// ---------------------------------------------------------------------------

describe("deriveActualFill", () => {
  test("BUY: takingAmount = shares, price = making/taking", () => {
    const r = deriveActualFill(
      "buy",
      { makingAmount: "10", takingAmount: "20" },
      { amount: 10, price: 0.5 },
    );
    expect(r.actualAmount).toBe(20);
    expect(r.actualPrice).toBeCloseTo(0.5, 10);
  });

  test("SELL: makingAmount = shares, price = taking/making", () => {
    const r = deriveActualFill(
      "sell",
      { makingAmount: "20", takingAmount: "12" },
      { amount: 20, price: 0.6 },
    );
    expect(r.actualAmount).toBe(20);
    expect(r.actualPrice).toBeCloseTo(0.6, 10);
  });

  test("BUY base-unit (6dp) response is normalized to shares", () => {
    // 20 shares acquired for 10 USDC, reported as 6-decimal base units.
    const r = deriveActualFill(
      "buy",
      { makingAmount: "10000000", takingAmount: "20000000" },
      { amount: 20, price: 0.5 },
    );
    expect(r.actualAmount).toBe(20); // NOT 20000000
    expect(r.actualPrice).toBeCloseTo(0.5, 10); // ratio unit-invariant
  });

  test("SELL base-unit (6dp) response is normalized to shares", () => {
    const r = deriveActualFill(
      "sell",
      { makingAmount: "20000000", takingAmount: "12000000" },
      { amount: 20, price: 0.6 },
    );
    expect(r.actualAmount).toBe(20);
    expect(r.actualPrice).toBeCloseTo(0.6, 10);
  });

  test("falls back when amounts missing", () => {
    const r = deriveActualFill("buy", {}, { amount: 7, price: 0.42 });
    expect(r).toEqual({ actualAmount: 7, actualPrice: 0.42 });
  });

  test("PRESENT-but-zero amounts => 0 filled, no price (resting GTC limit, NOT fallback)", () => {
    const r = deriveActualFill(
      "buy",
      { makingAmount: "0", takingAmount: "0" },
      { amount: 1, price: 0.1 },
    );
    expect(r).toEqual({ actualAmount: 0, actualPrice: undefined });
  });

  test("one-sided zero (no div-by-zero) => 0 filled", () => {
    const r = deriveActualFill(
      "buy",
      { makingAmount: "10", takingAmount: "0" },
      { amount: 1, price: 0.1 },
    );
    expect(r).toEqual({ actualAmount: 0, actualPrice: undefined });
  });

  test("unparsable amounts => fallback", () => {
    const r = deriveActualFill(
      "buy",
      { makingAmount: "abc", takingAmount: "xyz" },
      { amount: 7, price: 0.42 },
    );
    expect(r).toEqual({ actualAmount: 7, actualPrice: 0.42 });
  });
});

// ---------------------------------------------------------------------------
// Gamma JSON-string parsing
// ---------------------------------------------------------------------------

describe("Gamma JSON-string parsing", () => {
  test("parseMaybeJsonArray handles JSON-encoded strings", () => {
    expect(parseMaybeJsonArray('["a","b"]')).toEqual(["a", "b"]);
  });

  test("parseMaybeJsonArray passes through real arrays", () => {
    expect(parseMaybeJsonArray(["x", "y"])).toEqual(["x", "y"]);
  });

  test("parseMaybeJsonArray returns [] on garbage", () => {
    expect(parseMaybeJsonArray("not json")).toEqual([]);
    expect(parseMaybeJsonArray(null)).toEqual([]);
    expect(parseMaybeJsonArray(undefined)).toEqual([]);
  });

  test("getClobTokenIds filters to plausible numeric asset ids", () => {
    const bigId1 = "7".repeat(72);
    const bigId2 = "8".repeat(72);
    const ids = getClobTokenIds(JSON.stringify([bigId1, bigId2, "short", "abc"]));
    expect(ids).toEqual([bigId1, bigId2]);
  });

  test("getOutcomes / getOutcomePrices parse JSON-string", () => {
    expect(getOutcomes('["Yes","No"]')).toEqual(["Yes", "No"]);
    expect(getOutcomePrices('["0.6","0.4"]')).toEqual(["0.6", "0.4"]);
  });

  test("normalizeGammaMarket parses all three JSON-string fields", () => {
    const bigId1 = "7".repeat(72);
    const bigId2 = "8".repeat(72);
    const m = normalizeGammaMarket({
      id: "m1",
      question: "Will it?",
      clobTokenIds: JSON.stringify([bigId1, bigId2]),
      outcomes: '["Yes","No"]',
      outcomePrices: '["0.6","0.4"]',
      negRisk: true,
    });
    expect(m.clobTokenIds).toEqual([bigId1, bigId2]);
    expect(m.outcomes).toEqual(["Yes", "No"]);
    expect(m.outcomePrices).toEqual(["0.6", "0.4"]);
    expect(m.negRisk).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Builder attribution — OFF / 0 by default (the revenue rail, inert until enabled)
// ---------------------------------------------------------------------------

describe("builder attribution defaults OFF", () => {
  test("resolveBuilderConfig with no input/env defaults disabled, feeBps 0", () => {
    // Ensure env doesn't leak in.
    const saved = {
      en: process.env.POLYMARKET_BUILDER_ENABLED,
      url: process.env.POLYMARKET_SIGNING_SERVER_URL,
      fee: process.env.POLYMARKET_BUILDER_FEE_BPS,
    };
    delete process.env.POLYMARKET_BUILDER_ENABLED;
    delete process.env.POLYMARKET_SIGNING_SERVER_URL;
    delete process.env.POLYMARKET_BUILDER_FEE_BPS;

    const cfg = resolveBuilderConfig();
    expect(cfg.enabled).toBe(false);
    expect(cfg.feeBps).toBe(0);
    expect(isBuilderEnabled(cfg)).toBe(false);

    if (saved.en !== undefined) process.env.POLYMARKET_BUILDER_ENABLED = saved.en;
    if (saved.url !== undefined) process.env.POLYMARKET_SIGNING_SERVER_URL = saved.url;
    if (saved.fee !== undefined) process.env.POLYMARKET_BUILDER_FEE_BPS = saved.fee;
  });

  test("createPolymarketBuilderConfig returns null when disabled (no SDK import)", async () => {
    const cfg = resolveBuilderConfig({ enabled: false });
    expect(await createPolymarketBuilderConfig(cfg)).toBeNull();
  });

  test("explicit input is respected but still off without signing server", () => {
    const cfg = resolveBuilderConfig({ enabled: true, feeBps: 10, receiver: FUNDER });
    expect(cfg.enabled).toBe(true);
    expect(cfg.feeBps).toBe(10);
    // No signing server -> still treated as off (can't attribute without it).
    expect(isBuilderEnabled(cfg)).toBe(false);
  });

  test("enabled WITH signing server flips on", () => {
    const cfg = resolveBuilderConfig({
      enabled: true,
      feeBps: 10,
      receiver: FUNDER,
      signingServerUrl: "https://signer.example.com/sign",
      signingServerToken: "tok",
    });
    expect(isBuilderEnabled(cfg)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Execution adapter — tickSize/negRisk resolution + passed to createOrder,
// precision applied, all network mocked.
// ---------------------------------------------------------------------------

describe("PolymarketExecutionAdapter order build", () => {
  const bigToken = "7".repeat(72);

  // Mock the CLOB /book so resolveOrderOptions reads tickSize + negRisk.
  function bookFetch(tickSize: string, negRisk: boolean): typeof fetch {
    return (async (input: string | URL | Request) => {
      const url = String(input);
      if (url.includes("/book")) {
        return new Response(
          JSON.stringify({
            asset_id: bigToken,
            tick_size: tickSize,
            neg_risk: negRisk,
            bids: [],
            asks: [],
          }),
          { status: 200 },
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    }) as unknown as typeof fetch;
  }

  test("resolveOrderOptions reads tickSize + negRisk from the book", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: bookFetch("0.001", true) });
    const opts = await adapter.resolveOrderOptions({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.5,
    });
    expect(opts).toEqual({ tickSize: "0.001", negRisk: true });
  });

  test("resolveOrderOptions short-circuits when caller supplies both (no fetch)", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    const opts = await adapter.resolveOrderOptions({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.5,
      tickSize: "0.1",
      negRisk: false,
    });
    expect(opts).toEqual({ tickSize: "0.1", negRisk: false });
  });

  test("buildSignedOrder passes { tickSize, negRisk } + rounded size to createOrder", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: bookFetch("0.01", true) });

    // Capture createOrder args by stubbing createClobClient via prototype.
    let captured: { order: Record<string, unknown>; options: unknown } | null = null;
    const stub = {
      async createOrder(order: Record<string, unknown>, options: unknown) {
        captured = { order, options };
        return { signed: true };
      },
    };
    // @ts-expect-error private override for test
    adapter.createClobClient = async () => ({ client: stub, Side: { BUY: "BUY", SELL: "SELL" } });

    const signed = await adapter.buildSignedOrder({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.37,
    });
    expect(signed).toEqual({ signed: true });
    expect(captured).not.toBeNull();
    const cap = captured as unknown as { order: Record<string, unknown>; options: unknown };
    expect(cap.options).toEqual({ tickSize: "0.01", negRisk: true });
    expect(cap.order.tokenID).toBe(bigToken);
    expect(cap.order.side).toBe("BUY");
    // $10 @ 0.37 -> 27.02 shares (BUY floors to 2dp)
    expect(cap.order.size).toBe(27.02);
    // feeRateBps omitted when caller doesn't supply it (SDK resolves market fee)
    expect("feeRateBps" in cap.order).toBe(false);
  });

  test("buildSignedOrder includes feeRateBps only when caller supplies it", async () => {
    const adapter2 = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    let captured: Record<string, unknown> | null = null;
    const stub = {
      async createOrder(order: Record<string, unknown>) {
        captured = order;
        return { signed: true };
      },
    };
    // @ts-expect-error private override for test
    adapter2.createClobClient = async () => ({ client: stub, Side: { BUY: "BUY", SELL: "SELL" } });

    await adapter2.buildSignedOrder({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.5,
      tickSize: "0.01",
      negRisk: false,
      feeRateBps: 25,
    });
    expect((captured as unknown as Record<string, unknown>).feeRateBps).toBe(25);
  });

  test("submitOrder BUY fallback reports actualAmount in SHARES (not USD) when amounts missing", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    const stub = {
      async createOrder() {
        return { signed: true };
      },
      // postOrder accepts the order but omits making/taking amounts.
      async postOrder() {
        return { orderID: "abc", status: "matched" };
      },
    };
    // @ts-expect-error private override for test
    adapter.createClobClient = async () => ({
      client: stub,
      OrderType: { FOK: "FOK", GTC: "GTC" },
      Side: { BUY: "BUY", SELL: "SELL" },
    });

    const res = await adapter.submitOrder({
      tokenId: bigToken,
      side: "buy",
      amount: 10, // USD
      price: 0.5,
      tickSize: "0.01",
      negRisk: false,
    });
    // $10 @ 0.5 -> 20 shares. Must report shares, NOT the $10 USD notional.
    expect(res.actualAmount).toBe(20);
    expect(res.actualPrice).toBe(0.5);
    expect(res.orderId).toBe("abc");
  });

  test("submitOrder reports 0 fill for an accepted GTC limit resting on the book", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    const stub = {
      async createOrder() {
        return { signed: true };
      },
      // Accepted (has orderID) but unfilled: amounts present as "0".
      async postOrder() {
        return { orderID: "resting1", status: "live", makingAmount: "0", takingAmount: "0" };
      },
    };
    // @ts-expect-error private override for test
    adapter.createClobClient = async () => ({
      client: stub,
      OrderType: { FOK: "FOK", GTC: "GTC" },
      Side: { BUY: "BUY", SELL: "SELL" },
    });

    const res = await adapter.submitOrder({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.5,
      orderType: "limit",
      tickSize: "0.01",
      negRisk: false,
    });
    expect(res.orderId).toBe("resting1");
    expect(res.actualAmount).toBe(0); // not the requested 20 shares
    expect(res.actualPrice).toBeUndefined();
  });

  test("submitOrder does NOT fabricate a fill when the venue rejects the order", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    const stub = {
      async createOrder() {
        return { signed: true };
      },
      // Rejected: success=false, error message, no orderID, no amounts.
      async postOrder() {
        return { success: false, errorMsg: "not enough balance" };
      },
    };
    // @ts-expect-error private override for test
    adapter.createClobClient = async () => ({
      client: stub,
      OrderType: { FOK: "FOK", GTC: "GTC" },
      Side: { BUY: "BUY", SELL: "SELL" },
    });

    const res = await adapter.submitOrder({
      tokenId: bigToken,
      side: "buy",
      amount: 10,
      price: 0.5,
      tickSize: "0.01",
      negRisk: false,
    });
    expect(res.success).toBe(false);
    expect(res.actualAmount).toBe(0); // no phantom fill
    expect(res.actualPrice).toBeUndefined();
    expect(res.errorMsg).toBe("not enough balance");
  });

  test("resolveOrderOptions throws (no guess) when book lookup fails and caller didn't supply both", async () => {
    const failFetch = (async () => {
      throw new Error("book down");
    }) as unknown as typeof fetch;
    const adapter3 = new PolymarketExecutionAdapter(account, { fetch: failFetch });
    await expect(
      adapter3.resolveOrderOptions({ tokenId: bigToken, side: "buy", amount: 10, price: 0.5 }),
    ).rejects.toThrow(/refusing to guess/);
  });

  test("buildSignedOrder rejects SELL size the SDK would floor to 0", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    // 0.005 shares -> roundOrderSize gives 0.005 (>0) but SDK floors to 0.00.
    await expect(
      adapter.buildSignedOrder({
        tokenId: bigToken,
        side: "sell",
        amount: 0.005,
        price: 0.5,
        tickSize: "0.01",
        negRisk: false,
      }),
    ).rejects.toThrow(/floored to 0|2-decimal/);
  });

  test("buildSignedOrder rejects out-of-range price", async () => {
    const adapter = new PolymarketExecutionAdapter(account, { fetch: notFetch() });
    await expect(
      adapter.buildSignedOrder({ tokenId: bigToken, side: "buy", amount: 10, price: 1 }),
    ).rejects.toThrow();
    await expect(
      adapter.buildSignedOrder({ tokenId: bigToken, side: "buy", amount: 10, price: 0 }),
    ).rejects.toThrow();
  });

  test("constructor validates account (bad funder rejected)", () => {
    expect(
      () =>
        new PolymarketExecutionAdapter({
          ...account,
          funderAddress: "0xnotanaddress",
        }),
    ).toThrow();
  });

  test("constructor rejects a signer that cannot sign typed data", () => {
    const noSign: EthersSignerLike = { address: SIGNER_ADDR }; // no _signTypedData / signTypedData
    expect(() => new PolymarketExecutionAdapter({ ...account, signer: noSign })).toThrow(/sign/i);
  });

  test("constructor rejects a signer with no address", () => {
    const noAddr: EthersSignerLike = {
      async signTypedData() {
        return "0xsig";
      },
    };
    expect(() => new PolymarketExecutionAdapter({ ...account, signer: noAddr })).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Credentials helpers
// ---------------------------------------------------------------------------

describe("credential helpers", () => {
  test("isPolymarketUnauthorized detects 401 shapes", () => {
    expect(isPolymarketUnauthorized({ status: 401 })).toBe(true);
    expect(isPolymarketUnauthorized({ response: { status: 401 } })).toBe(true);
    expect(isPolymarketUnauthorized({ status: 500 })).toBe(false);
    expect(isPolymarketUnauthorized(null)).toBe(false);
  });

  test("toClobCompatibleSigner bridges v6 signTypedData -> v5 _signTypedData", async () => {
    const calls: unknown[][] = [];
    const v6: EthersSignerLike = {
      // only getAddress, to isolate the signTypedData bridge from the address one
      async getAddress() {
        return SIGNER_ADDR;
      },
      async signTypedData(...args: unknown[]) {
        calls.push(args);
        return "0xv6sig";
      },
    };
    expect(typeof v6._signTypedData).toBe("undefined");
    const compat = toClobCompatibleSigner(v6) as EthersSignerLike;
    // order-utils calls _signTypedData(domain, types, value)
    const sig = await compat._signTypedData?.({ name: "d" }, { T: [] }, { v: 1 });
    expect(sig).toBe("0xv6sig");
    expect(calls.length).toBe(1);
    expect(calls[0]).toEqual([{ name: "d" }, { T: [] }, { v: 1 }]);
  });

  test("toClobCompatibleSigner synthesizes getAddress() from .address", async () => {
    const onlyAddress: EthersSignerLike = {
      address: SIGNER_ADDR,
      async signTypedData() {
        return "0xsig";
      },
    };
    expect(typeof onlyAddress.getAddress).toBe("undefined");
    const compat = toClobCompatibleSigner(onlyAddress) as EthersSignerLike;
    // order-utils calls getAddress() unconditionally
    expect(await compat.getAddress?.()).toBe(SIGNER_ADDR);
    // .address still readable through the proxy
    expect(compat.address).toBe(SIGNER_ADDR);
  });

  test("toClobCompatibleSigner leaves a full v5 signer untouched", () => {
    const v5: EthersSignerLike = {
      async getAddress() {
        return SIGNER_ADDR;
      },
      async _signTypedData() {
        return "0xv5sig";
      },
    };
    expect(toClobCompatibleSigner(v5)).toBe(v5);
  });
});

// ---------------------------------------------------------------------------
// Marketdata batch — mocked network, cap enforcement, parsing
// ---------------------------------------------------------------------------

describe("marketdata batch", () => {
  test("getOrderbooks maps by asset_id, keeps empties for misses", async () => {
    const t1 = "1".repeat(72);
    const t2 = "2".repeat(72);
    const fetchMock = (async () =>
      new Response(
        JSON.stringify([
          {
            asset_id: t1,
            bids: [{ price: "0.6", size: "10" }],
            asks: [],
            tick_size: "0.01",
            neg_risk: false,
          },
        ]),
        { status: 200 },
      )) as unknown as typeof fetch;

    const books = await getOrderbooks([t1, t2], { fetch: fetchMock });
    expect(books.get(t1)?.bids.length).toBe(1);
    expect(books.get(t1)?.tickSize).toBe("0.01");
    expect(books.get(t2)?.bids.length).toBe(0); // miss -> empty
  });

  test("getOrderbooks returns empties for empty input (no fetch)", async () => {
    const books = await getOrderbooks([], { fetch: notFetch() });
    expect(books.size).toBe(0);
  });

  test("getPrices parses the live MAPPED /prices response (keyed by token+side)", async () => {
    const t1 = "1".repeat(72);
    const t2 = "2".repeat(72);
    // Live CLOB shape: { "<token_id>": { "BUY": "...", "SELL": "..." } }
    const fetchMock = (async () =>
      new Response(
        JSON.stringify({
          [t1]: { BUY: "0.61", SELL: "0.6" },
          [t2]: { BUY: "0.4", SELL: "0.41" },
        }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const prices = await getPrices(
      [
        { tokenId: t1, side: "sell" },
        { tokenId: t2, side: "buy" },
      ],
      { fetch: fetchMock },
    );
    // Requested side honored, price pulled from the right side key.
    expect(prices[0]).toEqual({ tokenId: t1, side: "sell", price: "0.6" });
    expect(prices[1]).toEqual({ tokenId: t2, side: "buy", price: "0.4" });
  });

  test("getPrices array fallback preserves requested side when side omitted", async () => {
    const t1 = "1".repeat(72);
    const t2 = "2".repeat(72);
    const fetchMock = (async () =>
      new Response(
        JSON.stringify([
          { token_id: t1, price: "0.6" }, // no side echoed
          { token_id: t2, price: "0.4", side: "BUY" }, // side echoed
        ]),
        { status: 200 },
      )) as unknown as typeof fetch;
    const prices = await getPrices(
      [
        { tokenId: t1, side: "sell" },
        { tokenId: t2, side: "buy" },
      ],
      { fetch: fetchMock },
    );
    expect(prices[0]).toEqual({ tokenId: t1, side: "sell", price: "0.6" }); // preserved request side
    expect(prices[1]).toEqual({ tokenId: t2, side: "buy", price: "0.4" }); // echoed side
  });

  test("getBatchPriceHistory enforces 20-id cap", async () => {
    const ids = Array.from({ length: 21 }, (_, i) => String(i));
    await expect(getBatchPriceHistory(ids, {}, { fetch: notFetch() })).rejects.toThrow(
      /at most 20/,
    );
  });

  test("getPriceHistory includes startTs/endTs bounds in the query", async () => {
    const t1 = "1".repeat(72);
    let capturedUrl = "";
    const fetchMock = (async (input: string | URL | Request) => {
      capturedUrl = String(input);
      return new Response(JSON.stringify({ history: [{ t: 1, p: 0.5 }] }), { status: 200 });
    }) as unknown as typeof fetch;
    const pts = await getPriceHistory(
      t1,
      { interval: "max", fidelity: 5, startTs: 1000, endTs: 2000 },
      { fetch: fetchMock },
    );
    expect(pts.length).toBe(1);
    expect(capturedUrl).toContain("startTs=1000");
    expect(capturedUrl).toContain("endTs=2000");
    expect(capturedUrl).toContain("interval=max");
    expect(capturedUrl).toContain("fidelity=5");
  });

  test("getBatchPriceHistory filters valid price points", async () => {
    const t1 = "1".repeat(72);
    const fetchMock = (async () =>
      new Response(
        JSON.stringify({
          history: {
            [t1]: [
              { t: 1, p: 0.5 },
              { t: 2, p: 5 }, // invalid (>1) -> filtered
              { t: 3, p: 0.7 },
            ],
          },
        }),
        { status: 200 },
      )) as unknown as typeof fetch;
    const hist = await getBatchPriceHistory([t1], {}, { fetch: fetchMock });
    expect(hist.get(t1)?.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Data API positions — mocked, normalization + dust filter
// ---------------------------------------------------------------------------

describe("data positions", () => {
  test("listPositions normalizes + filters dust", async () => {
    const t1 = "1".repeat(72);
    const fetchMock = (async () =>
      new Response(
        JSON.stringify([
          {
            asset: t1,
            title: "Will it?",
            outcome: "Yes",
            size: 5,
            avgPrice: 0.4,
            curPrice: 0.5,
            cashPnl: 0.5,
          },
          { asset: "2".repeat(72), size: 0 }, // dust -> filtered
        ]),
        { status: 200 },
      )) as unknown as typeof fetch;

    const positions = await listPositions({ user: FUNDER }, { fetch: fetchMock });
    expect(positions.length).toBe(1);
    expect(positions[0].tokenId).toBe(t1);
    expect(positions[0].balance).toBe(5);
    expect(positions[0].currentValue).toBeCloseTo(2.5, 10);
    expect(positions[0].unrealizedPnl).toBe(0.5);
  });
});

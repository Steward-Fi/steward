import { describe, expect, test } from "bun:test";
import { privateKeyToAccount } from "viem/accounts";
import {
  actionHash,
  cancelOrder,
  createL1TypedData,
  createWithdrawTypedData,
  getMarketableLimitPx,
  getOpenOrders,
  HyperliquidAdapter,
  type HyperliquidTransport,
  signOrder,
  submitOrder,
  toExchangeAction,
  toWithdrawAction,
} from "./index";

const PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as const;
const WALLET = privateKeyToAccount(PRIVATE_KEY).address;
const NONCE = 1_700_000_000_000;

describe("Hyperliquid L1 signing", () => {
  test("builds the documented wire action and deterministic L1 typed data", async () => {
    const action = toExchangeAction({
      coin: "BTC",
      side: "buy",
      size: 0.02,
      limitPx: "30000",
      reduceOnly: false,
    });
    expect(action).toEqual({
      type: "order",
      orders: [{ a: 0, b: true, p: "30000", s: "0.02", r: false, t: { limit: { tif: "Ioc" } } }],
      grouping: "na",
    });

    const typedData = createL1TypedData(action, NONCE, false);
    expect(typedData).toEqual({
      domain: {
        name: "Exchange",
        version: "1",
        chainId: 1337,
        verifyingContract: "0x0000000000000000000000000000000000000000",
      },
      types: {
        Agent: [
          { name: "source", type: "string" },
          { name: "connectionId", type: "bytes32" },
        ],
      },
      primaryType: "Agent",
      value: {
        source: "b",
        connectionId: actionHash(action, NONCE),
      },
    });

    const signed = await signOrder(
      PRIVATE_KEY,
      { coin: "BTC", side: "buy", size: 0.02, limitPx: "30000" },
      { nonce: NONCE, isMainnet: false },
    );
    expect(signed.action).toEqual(action);
    expect(signed.nonce).toBe(NONCE);
    expect(signed.signature.r).toMatch(/^0x[0-9a-f]{64}$/);
    expect(signed.signature.s).toMatch(/^0x[0-9a-f]{64}$/);
    expect([27, 28]).toContain(signed.signature.v);
  });

  test("uses explicit limit price without fetching the book", async () => {
    const signed = await signOrder(
      PRIVATE_KEY,
      { coin: "BTC", side: "buy", size: 0.02, limitPx: "30000" },
      {
        nonce: NONCE,
        isMainnet: false,
        transport: {
          async fetch() {
            throw new Error("unexpected fetch");
          },
        },
      },
    );
    expect(signed.action).toMatchObject({
      orders: [{ p: "30000" }],
    });
  });

  test("auto-computes marketable IOC price from best ask for buys", async () => {
    const signed = await signOrder(
      PRIVATE_KEY,
      { coin: "BTC", side: "buy", size: 0.02 },
      {
        nonce: NONCE,
        isMainnet: false,
        transport: {
          async fetch(_input, init) {
            expect(JSON.parse(String(init?.body))).toEqual({ type: "l2Book", coin: "BTC" });
            return new Response(
              JSON.stringify({ levels: [[{ px: "29900", sz: "1" }], [{ px: "30000", sz: "1" }]] }),
              { status: 200 },
            );
          },
        },
      },
    );
    expect(signed.action).toMatchObject({
      orders: [{ b: true, p: "30150" }],
    });
  });

  test("auto-computes marketable IOC price from best bid for sells", async () => {
    const px = await getMarketableLimitPx("ETH", false, {
      transport: {
        async fetch(_input, init) {
          expect(JSON.parse(String(init?.body))).toEqual({ type: "l2Book", coin: "ETH" });
          return new Response(
            JSON.stringify({ levels: [[{ px: "2500", sz: "1" }], [{ px: "2510", sz: "1" }]] }),
            { status: 200 },
          );
        },
      },
    });
    expect(px).toBe("2487.5");
  });

  test("adapter signs with vault-provided EIP-712 and submits HL payload", async () => {
    let posted: unknown;
    const transport: HyperliquidTransport = {
      async fetch(_input, init) {
        posted = JSON.parse(String(init?.body));
        return new Response(
          JSON.stringify({
            status: "ok",
            response: { type: "order", data: { statuses: [{ resting: { oid: 77738308 } }] } },
          }),
          { status: 200 },
        );
      },
    };
    const account = privateKeyToAccount(PRIVATE_KEY);
    const adapter = new HyperliquidAdapter(
      {
        async signTypedData(input) {
          return account.signTypedData({
            domain: input.domain,
            types: input.types,
            primaryType: input.primaryType,
            message: input.value,
          });
        },
      },
      "sol",
      WALLET,
      { transport, baseUrl: "https://api.hyperliquid-testnet.xyz", isMainnet: false },
    );

    const signed = await adapter.signOrder({
      coin: "ETH",
      side: "sell",
      size: 0.5,
      limitPx: "2500",
      reduceOnly: true,
      nonce: NONCE,
    });
    const result = await adapter.submitOrder(signed);
    expect(posted).toMatchObject({
      action: signed.action,
      nonce: NONCE,
      signature: signed.signature,
    });
    expect(result).toMatchObject({ orderId: "77738308", status: "resting" });
  });
});

describe("Hyperliquid withdraw (user-signed action)", () => {
  test("createWithdrawTypedData produces the exact HL EIP-712 structure", () => {
    const td = createWithdrawTypedData({
      amount: "100",
      destination: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
      time: NONCE,
    });
    // Withdraw is signed on Arbitrum (42161), NOT the L1 1337 domain.
    expect(td.domain).toEqual({
      name: "HyperliquidSignTransaction",
      version: "1",
      chainId: 42161,
      verifyingContract: "0x0000000000000000000000000000000000000000",
    });
    expect(td.primaryType).toBe("HyperliquidTransaction:Withdraw");
    expect(td.types["HyperliquidTransaction:Withdraw"]).toEqual([
      { name: "hyperliquidChain", type: "string" },
      { name: "destination", type: "string" },
      { name: "amount", type: "string" },
      { name: "time", type: "uint64" },
    ]);
    // amount stays a string; destination is lowercased.
    expect(td.value).toEqual({
      hyperliquidChain: "Mainnet",
      destination: "0xabcdef0123456789abcdef0123456789abcdef01",
      amount: "100",
      time: NONCE,
    });
    expect(typeof td.value.amount).toBe("string");
  });

  test("toWithdrawAction builds the documented withdraw3 wire shape", () => {
    const action = toWithdrawAction({
      amount: 250.5,
      destination: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
      time: NONCE,
    });
    expect(action).toEqual({
      type: "withdraw3",
      hyperliquidChain: "Mainnet",
      signatureChainId: "0xa4b1",
      amount: "250.5",
      time: NONCE,
      destination: "0xabcdef0123456789abcdef0123456789abcdef01",
    });
  });

  test("rejects malformed destination addresses", () => {
    expect(() => toWithdrawAction({ amount: "1", destination: "not-an-address" })).toThrow();
  });

  test("adapter signs withdraw with vault EIP-712 and submits to /exchange", async () => {
    let posted: any;
    let signedDomain: any;
    const account = privateKeyToAccount(PRIVATE_KEY);
    const transport: HyperliquidTransport = {
      async fetch(input, init) {
        posted = JSON.parse(String(init?.body));
        expect(String(input)).toMatch(/\/exchange$/);
        return new Response(JSON.stringify({ status: "ok", response: { type: "default" } }), {
          status: 200,
        });
      },
    };
    const adapter = new HyperliquidAdapter(
      {
        async signTypedData(i) {
          signedDomain = i.domain;
          return account.signTypedData({
            domain: i.domain,
            types: i.types,
            primaryType: i.primaryType,
            message: i.value,
          });
        },
      },
      "sol",
      WALLET,
      { transport, baseUrl: "https://api.hyperliquid.xyz" },
    );
    const signed = await adapter.signWithdraw({
      amount: "100",
      destination: "0xABCDEF0123456789abcdef0123456789ABCDEF01",
      time: NONCE,
    });
    expect(signedDomain.chainId).toBe(42161);
    expect(signed.nonce).toBe(NONCE);
    expect(signed.action).toMatchObject({ type: "withdraw3", amount: "100" });
    await adapter.submitWithdraw(signed);
    expect(posted).toMatchObject({
      action: { type: "withdraw3", destination: "0xabcdef0123456789abcdef0123456789abcdef01" },
      nonce: NONCE,
      signature: signed.signature,
    });
  });
});

describe("Hyperliquid close-all", () => {
  function mkAdapter(positions: Array<{ coin: string; szi: string }>, posted: any[]) {
    const account = privateKeyToAccount(PRIVATE_KEY);
    const transport: HyperliquidTransport = {
      async fetch(_input, init) {
        const body = JSON.parse(String(init?.body));
        if (body.type === "clearinghouseState") {
          return new Response(
            JSON.stringify({
              assetPositions: positions.map((p) => ({ position: { coin: p.coin, szi: p.szi } })),
            }),
            { status: 200 },
          );
        }
        if (body.type === "l2Book") {
          // marketable price lookup for whichever coin signOrder closes
          return new Response(
            JSON.stringify({ levels: [[{ px: "100", sz: "1" }], [{ px: "101", sz: "1" }]] }),
            { status: 200 },
          );
        }
        // /exchange order submission
        posted.push(body);
        return new Response(
          JSON.stringify({
            status: "ok",
            response: {
              type: "order",
              data: { statuses: [{ filled: { oid: 1, totalSz: "1", avgPx: "100" } }] },
            },
          }),
          { status: 200 },
        );
      },
    };
    return new HyperliquidAdapter(
      {
        async signTypedData(i) {
          return account.signTypedData({
            domain: i.domain,
            types: i.types,
            primaryType: i.primaryType,
            message: i.value,
          });
        },
      },
      "sol",
      WALLET,
      { transport, baseUrl: "https://api.hyperliquid.xyz" },
    );
  }

  test("marketClosePosition sells to close a long (reduce-only, opposite side, abs size)", async () => {
    const posted: any[] = [];
    const adapter = mkAdapter([{ coin: "BTC", szi: "0.5" }], posted);
    await adapter.marketClosePosition("BTC");
    expect(posted).toHaveLength(1);
    const order = posted[0].action.orders[0];
    expect(order.a).toBe(0); // BTC
    expect(order.b).toBe(false); // sell to close a long
    expect(order.r).toBe(true); // reduce-only
    expect(order.s).toBe("0.5");
  });

  test("marketClosePosition buys to close a short", async () => {
    const posted: any[] = [];
    const adapter = mkAdapter([{ coin: "ETH", szi: "-2" }], posted);
    await adapter.marketClosePosition("ETH");
    const order = posted[0].action.orders[0];
    expect(order.a).toBe(1); // ETH
    expect(order.b).toBe(true); // buy to close a short
    expect(order.r).toBe(true);
    expect(order.s).toBe("2");
  });

  test("closeAllPositions iterates non-zero positions and skips flat ones", async () => {
    const posted: any[] = [];
    const adapter = mkAdapter(
      [
        { coin: "BTC", szi: "0.5" },
        { coin: "SOL", szi: "0" }, // flat — skipped
        { coin: "ETH", szi: "-2" },
      ],
      posted,
    );
    const results = await adapter.closeAllPositions();
    expect(results.map((r) => r.coin)).toEqual(["BTC", "ETH"]);
    expect(posted).toHaveLength(2);
    // BTC long => sell, ETH short => buy; both reduce-only
    expect(posted[0].action.orders[0]).toMatchObject({ a: 0, b: false, r: true, s: "0.5" });
    expect(posted[1].action.orders[0]).toMatchObject({ a: 1, b: true, r: true, s: "2" });
    expect(results[0].result.status).toBe("filled");
  });
});

describe("Hyperliquid HTTP helpers", () => {
  test("normalizes venue order rejection without throwing", async () => {
    const result = await submitOrder(
      await signOrder(
        PRIVATE_KEY,
        { coin: "BTC", side: "buy", size: 0.001, limitPx: "100" },
        { nonce: NONCE },
      ),
      {
        transport: {
          async fetch() {
            return new Response(
              JSON.stringify({
                status: "ok",
                response: {
                  type: "order",
                  data: { statuses: [{ error: "Order must have minimum value of $10." }] },
                },
              }),
              { status: 200 },
            );
          },
        },
      },
    );
    expect(result).toMatchObject({
      status: "rejected",
      error: "Order must have minimum value of $10.",
    });
  });

  test("fetches open orders from info endpoint", async () => {
    const orders = await getOpenOrders(WALLET, {
      transport: {
        async fetch(_input, init) {
          expect(JSON.parse(String(init?.body))).toEqual({ type: "openOrders", user: WALLET });
          return new Response(
            JSON.stringify([
              {
                coin: "BTC",
                limitPx: "29792.0",
                oid: 91490942,
                side: "A",
                sz: "5.0",
                timestamp: 1681247412573,
              },
            ]),
            { status: 200 },
          );
        },
      },
    });
    expect(orders[0]?.oid).toBe(91490942);
  });

  test("normalizes cancel errors", async () => {
    const result = await cancelOrder(
      PRIVATE_KEY,
      { coin: "BTC", orderId: 123, nonce: NONCE },
      {
        transport: {
          async fetch() {
            return new Response(
              JSON.stringify({
                status: "ok",
                response: {
                  type: "cancel",
                  data: {
                    statuses: [{ error: "Order was never placed, already canceled, or filled." }],
                  },
                },
              }),
              { status: 200 },
            );
          },
        },
      },
    );
    expect(result).toMatchObject({
      orderId: "123",
      status: "rejected",
      error: "Order was never placed, already canceled, or filled.",
    });
  });
});

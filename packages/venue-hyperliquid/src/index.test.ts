import { describe, expect, test } from "bun:test";
import { privateKeyToAccount } from "viem/accounts";
import {
  actionHash,
  cancelOrder,
  createL1TypedData,
  getOpenOrders,
  HyperliquidAdapter,
  type HyperliquidTransport,
  signOrder,
  submitOrder,
  toExchangeAction,
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

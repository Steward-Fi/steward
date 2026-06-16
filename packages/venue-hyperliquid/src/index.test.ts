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
  resolveAssetId,
  signOrder,
  signSendAsset,
  submitOrder,
  submitSendAsset,
  toExchangeAction,
  toSendAssetAction,
  toWithdrawAction,
} from "./index";

const PRIVATE_KEY = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" as const;
const WALLET = privateKeyToAccount(PRIVATE_KEY).address;
const NONCE = 1_700_000_000_000;

const xyzSpcxTransport = (extra?: { onBody?: (body: Record<string, unknown>) => void }): HyperliquidTransport => ({
  async fetch(_input, init) {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    extra?.onBody?.(body);
    if (body.type === "perpDexs") return new Response(JSON.stringify({ xyz: 1 }), { status: 200 });
    if (body.type === "meta" && body.dex === "xyz") {
      // HL's live meta{dex:xyz} names markets with the FULL `xyz:COIN` form
      // (verified live 2026-06-15: xyz:SPCX at index 76). Mirror that here so the
      // fixture guards the real-world keying, not a bare-symbol assumption.
      const universe = Array.from({ length: 77 }, (_, index) => ({ name: index === 76 ? "xyz:SPCX" : `xyz:DUMMY${index}`, szDecimals: index === 76 ? 2 : 4 }));
      return new Response(JSON.stringify({ universe }), { status: 200 });
    }
    if (body.type === "allMids" && body.dex === "xyz") return new Response(JSON.stringify({ SPCX: "400" }), { status: 200 });
    return new Response(JSON.stringify({ error: "unexpected body", body }), { status: 500 });
  },
});

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

  test("default nonce is strictly monotonic and >= Date.now() (no same-ms collisions)", async () => {
    // No explicit nonce → uses the monotonic source. Many rapid signs in the
    // same millisecond must produce strictly-increasing nonces.
    const before = Date.now();
    const order = { coin: "BTC", side: "buy", size: 0.01, limitPx: "30000" } as const;
    const nonces: number[] = [];
    for (let i = 0; i < 50; i++) {
      const signed = await signOrder(PRIVATE_KEY, order, { isMainnet: false });
      nonces.push(signed.nonce);
    }
    for (let i = 1; i < nonces.length; i++) {
      expect(nonces[i]).toBeGreaterThan(nonces[i - 1]);
    }
    expect(nonces[0]).toBeGreaterThanOrEqual(before);
  });

  test("explicit caller-supplied nonce is still honored", async () => {
    const signed = await signOrder(
      PRIVATE_KEY,
      { coin: "BTC", side: "buy", size: 0.01, limitPx: "30000" },
      { nonce: NONCE, isMainnet: false },
    );
    expect(signed.nonce).toBe(NONCE);
  });
});


describe("Hyperliquid HIP-3 builder perps", () => {
  test("accepts builder symbols and resolves xyz:SPCX to HIP-3 asset id 110076", async () => {
    const assetId = await resolveAssetId("xyz:SPCX", { transport: xyzSpcxTransport(), baseUrl: "https://fixture.hyperliquid.test" });
    expect(assetId).toBe(110076);
  });

  test("signs xyz:SPCX with dex-scoped meta, dex-scoped mids, HIP-3 asset id, and szDecimals", async () => {
    const bodies: Record<string, unknown>[] = [];
    const signed = await signOrder(
      PRIVATE_KEY,
      { coin: "xyz:SPCX", side: "sell", size: 1.234, nonce: NONCE },
      { nonce: NONCE, isMainnet: false, baseUrl: "https://fixture-2.hyperliquid.test", transport: xyzSpcxTransport({ onBody: (body) => bodies.push(body) }) },
    );
    expect(bodies).toContainEqual({ type: "allMids", dex: "xyz" });
    expect(bodies).toContainEqual({ type: "perpDexs" });
    expect(bodies).toContainEqual({ type: "meta", dex: "xyz" });
    expect(signed.action).toMatchObject({ type: "order", orders: [{ a: 110076, b: false, p: "398", s: "1.23", r: false, t: { limit: { tif: "Ioc" } } }], grouping: "na" });
  });
});

describe("Hyperliquid HIP-3 collateral sendAsset", () => {
  const spotMetaTransport = (extra?: { onBody?: (body: Record<string, unknown>) => void; exchangeRaw?: unknown }): HyperliquidTransport => ({
    async fetch(_input, init) {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      extra?.onBody?.(body);
      if (body.type === "spotMeta") {
        return new Response(JSON.stringify({ tokens: [{ name: "USDC", index: 0, tokenId: "0xnot-sendasset-token" }] }), { status: 200 });
      }
      if (body.action && (body.action as Record<string, unknown>).type === "sendAsset") {
        return new Response(JSON.stringify(extra?.exchangeRaw ?? { status: "ok" }), { status: 200 });
      }
      return new Response(JSON.stringify({ error: "unexpected body", body }), { status: 500 });
    },
  });

  test("builds and signs sendAsset core to xyz with USDC resolved from spotMeta", async () => {
    const bodies: Record<string, unknown>[] = [];
    const signed = await signSendAsset(
      PRIVATE_KEY,
      {
        destination: WALLET,
        sourceDex: "",
        destinationDex: "xyz",
        amount: "2000",
      },
      {
        nonce: NONCE,
        isMainnet: false,
        baseUrl: "https://fixture-sendasset.hyperliquid.test",
        transport: spotMetaTransport({ onBody: (body) => bodies.push(body) }),
      },
    );

    expect(bodies).toContainEqual({ type: "spotMeta" });
    expect(signed.nonce).toBe(NONCE);
    expect(signed.action).toEqual({
      type: "sendAsset",
      destination: WALLET.toLowerCase(),
      sourceDex: "",
      destinationDex: "xyz",
      token: "USDC:0",
      amount: "2000",
      nonce: NONCE,
    });
  });

  test("falls back to configured USDC token id when spotMeta cannot resolve it", async () => {
    const action = await toSendAssetAction(
      { destination: WALLET, sourceDex: "xyz", destinationDex: "", amount: 125.5, nonce: NONCE },
      {
        usdcTokenId: "configured-usdc",
        transport: {
          async fetch() {
            return new Response(JSON.stringify({ tokens: [{ name: "PURR", tokenId: "PURR:0" }] }), { status: 200 });
          },
        },
      },
    );
    expect(action).toEqual({
      type: "sendAsset",
      destination: WALLET.toLowerCase(),
      sourceDex: "xyz",
      destinationDex: "",
      token: "configured-usdc",
      amount: "125.5",
      nonce: NONCE,
    });
  });

  test("adapter convenience methods submit the correct core-to-builder and builder-to-core directions", async () => {
    const posted: Record<string, unknown>[] = [];
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
      {
        transport: spotMetaTransport({ onBody: (body) => posted.push(body) }),
        baseUrl: "https://fixture-adapter-sendasset.hyperliquid.test",
        isMainnet: false,
      },
    );

    await adapter.transferToBuilderDex("xyz", "10");
    await adapter.transferFromBuilderDex("xyz", "5");

    const actions = posted
      .map((body) => body.action as Record<string, unknown> | undefined)
      .filter(Boolean);
    expect(actions[0]).toMatchObject({ sourceDex: "", destinationDex: "xyz", destination: WALLET.toLowerCase(), token: "USDC:0", amount: "10" });
    expect(actions[1]).toMatchObject({ sourceDex: "xyz", destinationDex: "", destination: WALLET.toLowerCase(), token: "USDC:0", amount: "5" });
  });

  test("submitSendAsset posts signed L1 payload to /exchange", async () => {
    let posted: unknown;
    const signed = await signSendAsset(PRIVATE_KEY, { destination: WALLET, sourceDex: "", destinationDex: "xyz", token: "USDC:0", amount: "1" }, { nonce: NONCE, isMainnet: false });
    const result = await submitSendAsset(signed, {
      transport: {
        async fetch(_input, init) {
          posted = JSON.parse(String(init?.body));
          return new Response(JSON.stringify({ status: "ok" }), { status: 200 });
        },
      },
    });
    expect(posted).toMatchObject({ action: signed.action, nonce: NONCE, signature: signed.signature });
    expect(result.status).toBe("ok");
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

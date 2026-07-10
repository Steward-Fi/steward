import { describe, expect, test } from "bun:test";
import { MockSwapAdapter, type SwapQuote, ZeroExSwapAdapter } from "../adapters/swap.js";
import { AdapterUnavailableError, AdapterValidationError } from "../types.js";

const USDC = { address: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", symbol: "USDC", decimals: 6 };
const WETH = {
  address: "0x4200000000000000000000000000000000000006",
  symbol: "WETH",
  decimals: 18,
};
const TAKER = "0x1111111111111111111111111111111111111111";
const ALLOWANCE_HOLDER = "0x2222222222222222222222222222222222222222";
const ROUTER = "0x3333333333333333333333333333333333333333";
const OTHER = "0x4444444444444444444444444444444444444444";
const CALLDATA = `0x12345678${"00".repeat(32)}`;

function fixedClock(ms: number): { now: () => number } {
  return { now: () => ms };
}

describe("MockSwapAdapter.getQuote", () => {
  test("returns a deterministic quote with 0.3% fee and slippage-adjusted minimum", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000000",
      chainId: 8453,
      slippageBps: 50,
    });

    expect(quote.provider).toBe("mock");
    expect(quote.amountIn).toBe("1000000");
    // fee = 1_000_000 * 30 / 10_000 = 3_000; out = 997_000
    expect(quote.feeAmount).toBe("3000");
    expect(quote.amountOut).toBe("997000");
    // minOut = 997_000 * (10_000-50)/10_000 = 992_015
    expect(quote.minAmountOut).toBe("992015");
    expect(quote.slippageBps).toBe(50);
    expect(quote.expiresAt).toBe(1_000 + 60_000);
    expect(quote.route).toHaveLength(1);
  });

  test("is deterministic across calls (same inputs -> same quoteId/output)", async () => {
    const swap = new MockSwapAdapter(fixedClock(42));
    const a = await swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "500", chainId: 8453 });
    const b = await swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "500", chainId: 8453 });
    expect(a.quoteId).toBe(b.quoteId);
    expect(a.amountOut).toBe(b.amountOut);
  });

  test("rejects zero amount (assertUint256 default disallows zero)", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "0", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects negative amount", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "-5", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects non-integer / non-numeric amount", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "1.5", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects identical from/to token", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: USDC, amount: "100", chainId: 8453 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects slippage above 10000 bps", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({
        fromToken: USDC,
        toToken: WETH,
        amount: "100",
        chainId: 8453,
        slippageBps: 10_001,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects invalid chainId", async () => {
    const swap = new MockSwapAdapter();
    await expect(
      swap.getQuote({ fromToken: USDC, toToken: WETH, amount: "100", chainId: 0 }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

describe("MockSwapAdapter.buildSwap", () => {
  test("produces an UNSIGNED intent for a fresh quote", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    const intent = await swap.buildSwap(quote, "0x1111111111111111111111111111111111111111");

    expect(intent.signed).toBe(false);
    expect(intent.kind).toBe("evm-tx");
    expect(intent.category).toBe("swap");
    expect(intent.owner).toBe("0x1111111111111111111111111111111111111111");
    // No signature-bearing fields.
    expect((intent as Record<string, unknown>).signature).toBeUndefined();
    expect((intent as Record<string, unknown>).rawTransaction).toBeUndefined();
  });

  test("rejects an expired quote", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    // Advance the clock past expiry by building with a later-now adapter.
    const later = new MockSwapAdapter(fixedClock(quote.expiresAt + 1));
    await expect(
      later.buildSwap(quote, "0x1111111111111111111111111111111111111111"),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects a malformed agent address", async () => {
    const swap = new MockSwapAdapter(fixedClock(1_000));
    const quote = await swap.getQuote({
      fromToken: USDC,
      toToken: WETH,
      amount: "1000",
      chainId: 8453,
    });
    await expect(swap.buildSwap(quote, "not-an-address")).rejects.toBeInstanceOf(
      AdapterValidationError,
    );
  });
});

function zeroExFixture(overrides: Record<string, unknown> = {}) {
  return {
    chainId: 8453,
    sellToken: USDC.address,
    buyToken: WETH.address,
    sellAmount: "1000000",
    buyAmount: "500000000000000000",
    minBuyAmount: "497500000000000000",
    allowanceTarget: ALLOWANCE_HOLDER,
    issues: { allowance: { spender: ALLOWANCE_HOLDER } },
    transaction: {
      to: ROUTER,
      data: CALLDATA,
      value: "0",
      from: TAKER,
    },
    ...overrides,
  };
}

function makeZeroEx(
  responses: Array<Response | Record<string, unknown> | ((url: URL) => Response)>,
  options: Partial<ConstructorParameters<typeof ZeroExSwapAdapter>[0]> = {},
) {
  const calls: Array<{ url: URL; headers: Headers }> = [];
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    calls.push({ url, headers: new Headers(init?.headers) });
    const next = responses.shift();
    if (!next) throw new Error("unexpected fetch");
    if (typeof next === "function") return next(url);
    if (next instanceof Response) return next;
    return Response.json(next);
  };
  const adapter = new ZeroExSwapAdapter({
    apiKey: "test-key",
    baseUrl: "https://unit.test",
    supportedChains: {
      8453: { allowanceTarget: ALLOWANCE_HOLDER, transactionTargets: [ROUTER] },
    },
    now: () => 1_000,
    fetch: fetchImpl,
    ...options,
  });
  return { adapter, calls };
}

async function getZeroExQuote(adapter: ZeroExSwapAdapter) {
  return adapter.getQuote({
    fromToken: USDC,
    toToken: WETH,
    amount: "1000000",
    chainId: 8453,
    taker: TAKER,
    slippageBps: 50,
  });
}

describe("ZeroExSwapAdapter", () => {
  test("quotes and builds from recorded 0x v2 fixtures with strict headers and query params", async () => {
    const { adapter, calls } = makeZeroEx([zeroExFixture(), zeroExFixture()]);
    const quote = await getZeroExQuote(adapter);
    const intent = await adapter.buildSwap(quote, TAKER);

    expect(quote.provider).toBe("zeroex");
    expect(quote.amountIn).toBe("1000000");
    expect(quote.amountOut).toBe("500000000000000000");
    expect(quote.minAmountOut).toBe("497500000000000000");
    expect(quote.expiresAt).toBe(31_000);
    expect(intent).toMatchObject({
      signed: false,
      kind: "evm-tx",
      chainId: 8453,
      to: ROUTER.toLowerCase(),
      value: "0",
      data: CALLDATA,
      owner: TAKER.toLowerCase(),
      category: "swap",
      provider: "zeroex",
    });
    expect(intent.metadata).toMatchObject({
      quoteId: quote.quoteId,
      amountIn: quote.amountIn,
      minAmountOut: quote.minAmountOut,
      allowanceTarget: ALLOWANCE_HOLDER.toLowerCase(),
    });

    expect(calls.map((call) => call.url.pathname)).toEqual([
      "/swap/allowance-holder/price",
      "/swap/allowance-holder/quote",
    ]);
    for (const call of calls) {
      expect(call.headers.get("0x-api-key")).toBe("test-key");
      expect(call.headers.get("0x-version")).toBe("v2");
      expect(call.url.searchParams.get("chainId")).toBe("8453");
      expect(call.url.searchParams.get("sellToken")).toBe(USDC.address.toLowerCase());
      expect(call.url.searchParams.get("buyToken")).toBe(WETH.address.toLowerCase());
      expect(call.url.searchParams.get("sellAmount")).toBe("1000000");
      expect(call.url.searchParams.get("taker")).toBe(TAKER.toLowerCase());
    }
  });

  test("rejects malformed or mutated semantic response fields", async () => {
    for (const patch of [
      { chainId: 1 },
      { sellToken: OTHER },
      { buyToken: OTHER },
      { sellAmount: "999" },
      { taker: OTHER },
      { buyAmount: "not-a-number" },
    ]) {
      const { adapter } = makeZeroEx([zeroExFixture(patch)]);
      await expect(getZeroExQuote(adapter)).rejects.toBeInstanceOf(AdapterValidationError);
    }
  });

  test("allows v2 responses without legacy allowanceTarget while binding the configured spender", async () => {
    const price = zeroExFixture();
    const build = zeroExFixture();
    delete price.allowanceTarget;
    delete build.allowanceTarget;
    const { adapter } = makeZeroEx([price, build]);
    const quote = await getZeroExQuote(adapter);
    const intent = await adapter.buildSwap(quote, TAKER);
    expect(intent.metadata).toMatchObject({ allowanceTarget: ALLOWANCE_HOLDER.toLowerCase() });
  });

  test("rejects wrong quote response amount, owner, expired quote, and unsupported chain", async () => {
    const wrongAmount = makeZeroEx([zeroExFixture(), zeroExFixture({ minBuyAmount: "1" })]).adapter;
    const quote = await getZeroExQuote(wrongAmount);
    await expect(wrongAmount.buildSwap(quote, TAKER)).rejects.toBeInstanceOf(
      AdapterValidationError,
    );

    const wrongOwner = makeZeroEx([zeroExFixture()]).adapter;
    const ownerQuote = await getZeroExQuote(wrongOwner);
    await expect(wrongOwner.buildSwap(ownerQuote, OTHER)).rejects.toBeInstanceOf(
      AdapterValidationError,
    );

    const mutatedMetadataAdapter = makeZeroEx([zeroExFixture()]).adapter;
    const mutatedMetadataQuote = await getZeroExQuote(mutatedMetadataAdapter);
    const mutableQuote = mutatedMetadataQuote as SwapQuote & {
      zeroEx: { request: { chainId: number } };
    };
    mutableQuote.zeroEx.request.chainId = 1;
    await expect(mutatedMetadataAdapter.buildSwap(mutableQuote, TAKER)).rejects.toBeInstanceOf(
      AdapterValidationError,
    );

    const expired = makeZeroEx([zeroExFixture()], { now: () => 1_000, quoteTtlMs: 10 }).adapter;
    const expiredQuote = await getZeroExQuote(expired);
    const later = makeZeroEx([], { now: () => expiredQuote.expiresAt + 1 }).adapter;
    await expect(later.buildSwap(expiredQuote, TAKER)).rejects.toBeInstanceOf(
      AdapterValidationError,
    );

    await expect(
      makeZeroEx([]).adapter.getQuote({
        fromToken: USDC,
        toToken: WETH,
        amount: "1",
        chainId: 1,
        taker: TAKER,
      }),
    ).rejects.toBeInstanceOf(AdapterValidationError);
  });

  test("rejects unsafe allowance holder, allowance spender, transaction target, calldata, and value", async () => {
    for (const patch of [
      { allowanceTarget: OTHER },
      { issues: { allowance: { spender: OTHER } } },
      { transaction: { ...zeroExFixture().transaction, to: OTHER } },
      { transaction: { ...zeroExFixture().transaction, data: "0x" } },
      { transaction: { ...zeroExFixture().transaction, value: "1.5" } },
      { transaction: { ...zeroExFixture().transaction, from: OTHER } },
    ]) {
      const { adapter } = makeZeroEx([zeroExFixture(), zeroExFixture(patch)]);
      const quote = await getZeroExQuote(adapter);
      await expect(adapter.buildSwap(quote, TAKER)).rejects.toBeInstanceOf(AdapterValidationError);
    }
  });

  test("maps 4xx, 5xx, and timeout to provider unavailable", async () => {
    for (const status of [400, 500]) {
      const { adapter } = makeZeroEx([new Response("{}", { status })]);
      await expect(getZeroExQuote(adapter)).rejects.toBeInstanceOf(AdapterUnavailableError);
    }

    const timeoutFetch = (_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(Object.assign(new Error("aborted"), { name: "AbortError" }));
        });
      });
    const adapter = new ZeroExSwapAdapter({
      apiKey: "test-key",
      baseUrl: "https://unit.test",
      supportedChains: {
        8453: { allowanceTarget: ALLOWANCE_HOLDER, transactionTargets: [ROUTER] },
      },
      timeoutMs: 1,
      fetch: timeoutFetch as typeof fetch,
    });
    await expect(getZeroExQuote(adapter)).rejects.toBeInstanceOf(AdapterUnavailableError);
  });

  test("adds affiliate fee params and rejects fee token outside buy/sell tokens", async () => {
    const { adapter, calls } = makeZeroEx([zeroExFixture()], {
      affiliateFee: { recipient: OTHER, bps: 25, token: "buy" },
    });
    await getZeroExQuote(adapter);
    expect(calls[0].url.searchParams.get("swapFeeRecipient")).toBe(OTHER.toLowerCase());
    expect(calls[0].url.searchParams.get("swapFeeBps")).toBe("25");
    expect(calls[0].url.searchParams.get("swapFeeToken")).toBe(WETH.address.toLowerCase());

    const invalidToken = makeZeroEx([zeroExFixture()], {
      affiliateFee: { recipient: OTHER, bps: 25, token: OTHER },
    }).adapter;
    await expect(getZeroExQuote(invalidToken)).rejects.toBeInstanceOf(AdapterValidationError);

    const invalidBps = makeZeroEx([zeroExFixture()], {
      affiliateFee: { recipient: OTHER, bps: 1_001, token: "sell" },
    }).adapter;
    await expect(getZeroExQuote(invalidBps)).rejects.toBeInstanceOf(AdapterValidationError);
  });
});

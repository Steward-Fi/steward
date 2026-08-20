import { afterEach, describe, expect, it } from "bun:test";
import { createPriceOracle } from "../price-oracle";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("price oracle", () => {
  it("uses only DexScreener pairs from the requested chain", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [
            {
              chainId: "ethereum",
              priceUsd: "999",
              liquidity: { usd: 10_000_000 },
            },
            {
              chainId: "base",
              priceUsd: "1.23",
              liquidity: { usd: 1_000 },
            },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 1 });

    await expect(
      oracle.getTokenUsdPrice(8453, "0x1111111111111111111111111111111111111111"),
    ).resolves.toBe(1.23);
  });

  it("returns null when no pair matches the requested chain", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "ethereum", priceUsd: "999", liquidity: { usd: 10_000_000 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 1 });

    await expect(
      oracle.getTokenUsdPrice(8453, "0x1111111111111111111111111111111111111111"),
    ).resolves.toBeNull();
  });

  it("rejects malformed token addresses without fetching (SEC-118)", async () => {
    let fetchCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls++;
      return new Response(JSON.stringify({ pairs: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 60_000 });

    // Path/query injection attempts must never reach the URL.
    await expect(oracle.getTokenUsdPrice(8453, "../admin?x=1")).resolves.toBeNull();
    await expect(oracle.getTokenUsdPrice(8453, "0x1111#frag")).resolves.toBeNull();
    // Wrong family: a base58-looking mint on an EVM chain.
    await expect(
      oracle.getTokenUsdPrice(8453, "So11111111111111111111111111111111111111112"),
    ).resolves.toBeNull();
    expect(fetchCalls).toBe(0);
  });

  it("usdToWei is exact beyond 2^53 and rounds to nearest (SEC-189)", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "base", priceUsd: "50", liquidity: { usd: 100 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    // 100 USD at $50 = exactly 2e18 wei.
    await expect(oracle.usdToWei(100, 8453)).resolves.toBe("2000000000000000000");
    // 1 USD at $3 = 1e18/3 wei. The old double math (`tokenAmount * 10 ** 18`)
    // collapses to 333333333333333312 (double rounding); exact rational math
    // rounds to nearest: 333333333333333333.
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "base", priceUsd: "3", liquidity: { usd: 100 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;
    await expect(createPriceOracle({ cacheTtlMs: 0 }).usdToWei(1, 8453)).resolves.toBe(
      "333333333333333333",
    );
  });

  it("handles large scientific-notation inputs without a Number-to-BigInt overflow", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "base", priceUsd: "1", liquidity: { usd: 100 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const result = await createPriceOracle({ cacheTtlMs: 0 }).usdToWei(Number.MAX_VALUE, 8453);
    expect(result).not.toBeNull();
    expect(result).toHaveLength(327);
    expect(result?.startsWith("17976931348623157")).toBe(true);
    expect(result?.endsWith("0".repeat(310))).toBe(true);
  });

  it("rejects a non-finite upstream price instead of throwing during BigInt conversion", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "base", priceUsd: "1e309", liquidity: { usd: 100 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    await expect(createPriceOracle({ cacheTtlMs: 0 }).usdToWei(1, 8453)).resolves.toBeNull();
  });

  it("rejects JavaScript-only numeric syntaxes in upstream decimal prices", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [
            { chainId: "base", priceUsd: "0x10", liquidity: { usd: 1_000_000 } },
            { chainId: "base", priceUsd: "0b10", liquidity: { usd: 100_000 } },
            { chainId: "base", priceUsd: "2.5", liquidity: { usd: 100 } },
          ],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    // Number("0x10") is 16, but a USD oracle must only accept the documented
    // decimal grammar. The genuine decimal pair remains eligible.
    await expect(createPriceOracle({ cacheTtlMs: 0 }).getNativeUsdPrice(8453)).resolves.toBe(2.5);
  });

  it("fails closed on an oversized chunked oracle response", async () => {
    const oversized = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(2 * 1024 * 1024));
        controller.enqueue(new Uint8Array([0]));
        controller.close();
      },
    });
    globalThis.fetch = (async () =>
      new Response(oversized, {
        status: 200,
        headers: { "content-type": "application/json" },
      })) as typeof fetch;

    await expect(createPriceOracle({ cacheTtlMs: 0 }).getNativeUsdPrice(8453)).resolves.toBeNull();
  });

  it("fails closed for unknown chains/tokens instead of assuming 18 decimals (SEC-190)", async () => {
    globalThis.fetch = (async () =>
      new Response(
        JSON.stringify({
          pairs: [{ chainId: "base", priceUsd: "50", liquidity: { usd: 100 } }],
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      )) as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    // Unknown native chain id: no DexScreener mapping anyway, but the decimals
    // path must also fail closed.
    await expect(oracle.usdToWei(100, 999_999)).resolves.toBeNull();
    // Unknown ERC-20 on a known chain: decimals unknown -> null, not 18.
    await expect(
      oracle.usdToWei(100, 8453, "0x2222222222222222222222222222222222222222"),
    ).resolves.toBeNull();
    await expect(
      oracle.weiToUsd("1000000", 8453, "0x2222222222222222222222222222222222222222"),
    ).resolves.toBeNull();
  });

  it("does not log exception text from a failed price transport", async () => {
    const canary = "api_key=price-oracle-secret";
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => warnings.push(args);
    globalThis.fetch = (async () => {
      throw new Error(canary);
    }) as typeof fetch;

    try {
      await expect(
        createPriceOracle({ cacheTtlMs: 0 }).getNativeUsdPrice(8453),
      ).resolves.toBeNull();
      expect(JSON.stringify(warnings)).not.toContain(canary);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]?.[0]).toContain("Failed to fetch price");
      expect(warnings[0]?.[1]).toEqual({ errorClass: "Error", errorCode: null });
    } finally {
      console.warn = originalWarn;
    }
  });
});

import { afterEach, describe, expect, it, mock } from "bun:test";
import {
  createPriceOracle,
  getKnownToken,
  getNativeDecimals,
  getNativeSymbol,
  getTokenDecimals,
  getWrappedNativeAddress,
  isVenueId,
  MONERO_ON_SOLANA,
  VENUE_IDS,
  VENUE_METADATA,
  WRAPPED_SOL_ON_SOLANA,
} from "../index";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  mock.restore();
});

describe("token helpers", () => {
  it("returns native token metadata and safe defaults for unknown chains", () => {
    expect(getNativeDecimals(101)).toBe(9);
    expect(getNativeSymbol(56)).toBe("BNB");
    expect(getNativeDecimals(999_999)).toBe(18);
    expect(getNativeSymbol(999_999)).toBe("ETH");
  });

  it("normalizes token addresses before looking up known ERC-20 decimals", () => {
    expect(getTokenDecimals(8453, "0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913")).toBe(6);
    expect(getTokenDecimals(1, "0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48")).toBe(6);
    expect(getTokenDecimals(1, "0x0000000000000000000000000000000000000000")).toBe(18);
  });

  it("treats missing, empty, and native token addresses as the native asset", () => {
    expect(getTokenDecimals(101)).toBe(9);
    expect(getTokenDecimals(101, "")).toBe(9);
    expect(getTokenDecimals(101, "native")).toBe(9);
  });

  it("registers Monero on Solana with its exact case-sensitive mint and decimals", () => {
    expect(MONERO_ON_SOLANA).toEqual({
      address: "WXMRyRZhsa19ety5erZhHg4N3xj3EVN92u94422teJp",
      symbol: "XMR",
      decimals: 12,
      chainId: 101,
      name: "Monero on Solana",
      website: "https://wxmr.io",
    });
    expect(getKnownToken(101, MONERO_ON_SOLANA.address)).toBe(MONERO_ON_SOLANA);
    expect(getTokenDecimals(101, MONERO_ON_SOLANA.address)).toBe(12);
    expect(getKnownToken(101, MONERO_ON_SOLANA.address.toLowerCase())).toBeUndefined();
  });

  it("registers wrapped SOL for exact SPL valuation without losing native lookup", () => {
    expect(getKnownToken(101, WRAPPED_SOL_ON_SOLANA.address)).toBe(WRAPPED_SOL_ON_SOLANA);
    expect(getTokenDecimals(101, WRAPPED_SOL_ON_SOLANA.address)).toBe(9);
    expect(getWrappedNativeAddress(101)).toBe(WRAPPED_SOL_ON_SOLANA.address);
  });

  it("exposes wrapped native addresses only for configured chains", () => {
    expect(getWrappedNativeAddress(8453)).toBe("0x4200000000000000000000000000000000000006");
    expect(getWrappedNativeAddress(101)).toBe("So11111111111111111111111111111111111111112");
    expect(getWrappedNativeAddress(102)).toBe("So11111111111111111111111111111111111111112");
  });
});

describe("venue helpers", () => {
  it("accepts every registered venue id and rejects lookalikes", () => {
    for (const venue of VENUE_IDS) {
      expect(isVenueId(venue)).toBe(true);
    }

    expect(isVenueId("Hyperliquid")).toBe(false);
    expect(isVenueId("hyperliquid ")).toBe(false);
    expect(isVenueId("unknown")).toBe(false);
  });

  it("keeps venue metadata complete and keyed by id", () => {
    for (const venue of VENUE_IDS) {
      const metadata = VENUE_METADATA[venue];
      expect(metadata.id).toBe(venue);
      expect(metadata.displayName.length).toBeGreaterThan(0);
      expect(["evm", "solana"]).toContain(metadata.chainFamily);
      expect(typeof metadata.supportsLeverage).toBe("boolean");
    }

    expect(VENUE_METADATA.polymarket.supportsLeverage).toBe(false);
    expect(VENUE_METADATA.hyperliquid.settlementCaip2).toBe("eip155:42161");
  });
});

describe("createPriceOracle", () => {
  it("chooses the highest-liquidity priced pair and caches it", async () => {
    const fetchMock = mock(
      async () =>
        new Response(
          JSON.stringify({
            pairs: [
              { chainId: "base", priceUsd: "100", liquidity: { usd: 10 } },
              { chainId: "base", priceUsd: "200", liquidity: { usd: 1_000 } },
              { chainId: "base", priceUsd: "0", liquidity: { usd: 999_999 } },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 60_000 });

    await expect(oracle.getNativeUsdPrice(8453)).resolves.toBe(200);
    await expect(oracle.getNativeUsdPrice(8453)).resolves.toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("converts native wei and SOL lamports using chain-specific decimals", async () => {
    const fetchMock = mock(
      async () =>
        new Response(
          JSON.stringify({ pairs: [{ chainId: "base", priceUsd: "50", liquidity: { usd: 100 } }] }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.weiToUsd("2000000000000000000", 8453)).resolves.toBe(100);
    await expect(oracle.usdToWei(100, 8453)).resolves.toBe("2000000000000000000");
  });

  it("values Monero on Solana with the registered 12-decimal mint", async () => {
    const fetchMock = mock(
      async () =>
        new Response(
          JSON.stringify({
            pairs: [{ chainId: "solana", priceUsd: "325.50", liquidity: { usd: 50_000 } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 60_000 });
    await expect(oracle.weiToUsd("2000000000000", 101, MONERO_ON_SOLANA.address)).resolves.toBe(
      651,
    );
  });

  it("values native SOL on both convention chains through the canonical wrapped mint", async () => {
    const fetchMock = mock(async (input: RequestInfo | URL) => {
      expect(String(input)).toEndWith("/So11111111111111111111111111111111111111112");
      return new Response(
        JSON.stringify({
          pairs: [{ chainId: "solana", priceUsd: "200", liquidity: { usd: 50_000 } }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });
    await expect(oracle.weiToUsd("1000000000", 101)).resolves.toBe(200);
    await expect(oracle.weiToUsd("500000000", 102)).resolves.toBe(100);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("values wrapped SOL token base units with the registered 9 decimals", async () => {
    globalThis.fetch = mock(
      async () =>
        new Response(
          JSON.stringify({
            pairs: [{ chainId: "solana", priceUsd: "200", liquidity: { usd: 50_000 } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        ),
    ) as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });
    await expect(
      oracle.weiToUsd("1500000000", 101, WRAPPED_SOL_ON_SOLANA.address),
    ).resolves.toBe(300);
  });

  it("keeps case-distinct Solana mint prices isolated in the cache", async () => {
    const mintUpper = "AbCMint11111111111111111111111111111111111";
    const mintLower = "abcmint11111111111111111111111111111111111";
    const fetchMock = mock(async (input: RequestInfo | URL) => {
      const price = String(input).endsWith(`/${mintUpper}`) ? "10" : "20";
      return new Response(JSON.stringify({ pairs: [{ chainId: "solana", priceUsd: price }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    const oracle = createPriceOracle({ cacheTtlMs: 60_000 });

    await expect(oracle.getTokenUsdPrice(101, mintUpper)).resolves.toBe(10);
    await expect(oracle.getTokenUsdPrice(101, mintLower)).resolves.toBe(20);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("returns null instead of throwing when no wrapped native token or pair is available", async () => {
    const fetchMock = mock(
      async () =>
        new Response(JSON.stringify({ pairs: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.getNativeUsdPrice(101)).resolves.toBeNull();
    await expect(
      oracle.getTokenUsdPrice(8453, "0x0000000000000000000000000000000000000000"),
    ).resolves.toBeNull();
  });

  it("returns null for non-OK price responses", async () => {
    const fetchMock = mock(async () => new Response("nope", { status: 503 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.getNativeUsdPrice(8453)).resolves.toBeNull();
  });
});

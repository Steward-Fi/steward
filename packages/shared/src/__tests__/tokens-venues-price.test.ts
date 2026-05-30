import { afterEach, describe, expect, it, mock } from "bun:test";
import {
  createPriceOracle,
  getNativeDecimals,
  getNativeSymbol,
  getTokenDecimals,
  getWrappedNativeAddress,
  isVenueId,
  VENUE_IDS,
  VENUE_METADATA,
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

  it("exposes wrapped native addresses only for configured chains", () => {
    expect(getWrappedNativeAddress(8453)).toBe("0x4200000000000000000000000000000000000006");
    expect(getWrappedNativeAddress(101)).toBeUndefined();
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
    const fetchMock = mock(async () =>
      new Response(
        JSON.stringify({
          pairs: [
            { priceUsd: "100", liquidity: { usd: 10 } },
            { priceUsd: "200", liquidity: { usd: 1_000 } },
            { priceUsd: "0", liquidity: { usd: 999_999 } },
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
    const fetchMock = mock(async () =>
      new Response(JSON.stringify({ pairs: [{ priceUsd: "50", liquidity: { usd: 100 } }] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.weiToUsd("2000000000000000000", 8453)).resolves.toBe(100);
    await expect(oracle.usdToWei(100, 8453)).resolves.toBe("2000000000000000000");
  });

  it("returns null instead of throwing when no wrapped native token or pair is available", async () => {
    const fetchMock = mock(async () =>
      new Response(JSON.stringify({ pairs: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.getNativeUsdPrice(101)).resolves.toBeNull();
    await expect(oracle.getTokenUsdPrice(8453, "0x0000000000000000000000000000000000000000")).resolves.toBeNull();
  });

  it("returns null for non-OK price responses", async () => {
    const fetchMock = mock(async () => new Response("nope", { status: 503 }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    const oracle = createPriceOracle({ cacheTtlMs: 0 });

    await expect(oracle.getNativeUsdPrice(8453)).resolves.toBeNull();
  });
});

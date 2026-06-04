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
});

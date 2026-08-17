/**
 * Price Oracle — fetches USD prices for native and fungible tokens via DexScreener.
 *
 * - Free API, no key required
 * - Caches prices for configurable TTL (default 60s)
 * - Graceful degradation: returns null on failure so callers can fall back to wei comparison
 */

import {
  getNativeDecimalsStrict,
  getTokenDecimalsStrict,
  getWrappedNativeAddress,
} from "./tokens.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface PriceOracle {
  /** Get native token USD price for a chain. Returns null if unavailable. */
  getNativeUsdPrice(chainId: number): Promise<number | null>;

  /** Get ERC-20 token USD price. Returns null if unavailable. */
  getTokenUsdPrice(chainId: number, tokenAddress: string): Promise<number | null>;

  /**
   * Convert a wei/lamport value to USD.
   * If tokenAddress is undefined or "native", uses native token price.
   * Returns null if price is unavailable.
   */
  weiToUsd(weiValue: string, chainId: number, tokenAddress?: string): Promise<number | null>;

  /**
   * Convert a USD value to wei/lamports.
   * If tokenAddress is undefined or "native", uses native token price.
   * Returns null if price is unavailable.
   */
  usdToWei(usdValue: number, chainId: number, tokenAddress?: string): Promise<string | null>;
}

// ─── DexScreener Response Shape ───────────────────────────────────────────────

interface DexScreenerPair {
  chainId?: string;
  priceUsd?: string;
  liquidity?: { usd?: number };
}

interface DexScreenerResponse {
  pairs?: DexScreenerPair[];
}

// ─── Cache Entry ──────────────────────────────────────────────────────────────

interface CacheEntry {
  price: number;
  fetchedAt: number;
}

// ─── Implementation ───────────────────────────────────────────────────────────

export function createPriceOracle(options?: { cacheTtlMs?: number }): PriceOracle {
  const cacheTtlMs = options?.cacheTtlMs ?? 60_000; // 60 seconds default
  const cache = new Map<string, CacheEntry>();

  function cacheKey(chainId: number, address: string): string {
    const normalized = chainId === 101 || chainId === 102 ? address : address.toLowerCase();
    return `${chainId}:${normalized}`;
  }

  function getCached(key: string): number | null {
    const entry = cache.get(key);
    if (!entry) return null;
    if (Date.now() - entry.fetchedAt > cacheTtlMs) {
      cache.delete(key);
      return null;
    }
    return entry.price;
  }

  function setCache(key: string, price: number): void {
    cache.set(key, { price, fetchedAt: Date.now() });
  }

  function dexScreenerChainId(chainId: number): string | null {
    switch (chainId) {
      case 1:
        return "ethereum";
      case 10:
        return "optimism";
      case 56:
        return "bsc";
      case 100:
        return "gnosischain";
      case 137:
        return "polygon";
      case 8453:
        return "base";
      case 42161:
        return "arbitrum";
      case 43114:
        return "avalanche";
      case 101:
        return "solana";
      default:
        return null;
    }
  }

  /**
   * Reject malformed token addresses before they reach the request URL
   * (SEC-118). EVM chains expect a 20-byte hex address; Solana a base58 mint.
   * Anything else (path/query metacharacters, wrong family) fails closed.
   */
  function isPlausibleTokenAddress(chainId: number, tokenAddress: string): boolean {
    if (chainId === 101 || chainId === 102) {
      return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(tokenAddress);
    }
    return /^0x[0-9a-fA-F]{40}$/.test(tokenAddress);
  }

  /**
   * Fetch price from DexScreener for a token address.
   * Picks the pair with highest liquidity for best accuracy.
   */
  async function fetchPrice(chainId: number, tokenAddress: string): Promise<number | null> {
    try {
      const expectedDexChainId = dexScreenerChainId(chainId);
      if (!expectedDexChainId) {
        console.warn(`[price-oracle] No DexScreener chain mapping for chainId ${chainId}`);
        return null;
      }
      if (!isPlausibleTokenAddress(chainId, tokenAddress)) {
        console.warn(
          `[price-oracle] Rejecting malformed token address for chainId ${chainId}: ${tokenAddress.slice(0, 64)}`,
        );
        return null;
      }
      const url = `https://api.dexscreener.com/latest/dex/tokens/${encodeURIComponent(tokenAddress)}`;
      const res = await fetch(url, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });

      if (!res.ok) {
        console.warn(`[price-oracle] DexScreener returned ${res.status} for ${tokenAddress}`);
        return null;
      }

      const data = (await res.json()) as DexScreenerResponse;
      if (!data.pairs || data.pairs.length === 0) {
        console.warn(`[price-oracle] No pairs found for ${tokenAddress}`);
        return null;
      }

      // Sort by liquidity (descending) and pick the best one with a valid priceUsd
      const sorted = [...data.pairs]
        .filter((p) => p.chainId === expectedDexChainId && p.priceUsd && parseFloat(p.priceUsd) > 0)
        .sort((a, b) => (b.liquidity?.usd ?? 0) - (a.liquidity?.usd ?? 0));

      if (sorted.length === 0) return null;

      return parseFloat(sorted[0].priceUsd!);
    } catch (err) {
      console.warn(`[price-oracle] Failed to fetch price for ${tokenAddress}:`, err);
      return null;
    }
  }

  async function getPrice(chainId: number, tokenAddress: string): Promise<number | null> {
    const key = cacheKey(chainId, tokenAddress);
    const cached = getCached(key);
    if (cached !== null) return cached;

    const price = await fetchPrice(chainId, tokenAddress);
    if (price !== null) {
      setCache(key, price);
    }
    return price;
  }

  const oracle: PriceOracle = {
    async getNativeUsdPrice(chainId: number): Promise<number | null> {
      // Monero (301/302) has no wrapped-native DexScreener pair, so this
      // returns null and every USD-denominated policy rule fails closed
      // (denies) for Monero requests. This is deliberate: quoting XMR via an
      // unrelated proxy pair would be dishonest pricing in a money path. Use
      // piconero-denominated limits for Monero until a vetted XMR price
      // source is added here.
      const wrappedAddress = getWrappedNativeAddress(chainId);
      if (!wrappedAddress) {
        console.warn(`[price-oracle] No wrapped native address for chainId ${chainId}`);
        return null;
      }
      return getPrice(chainId, wrappedAddress);
    },

    async getTokenUsdPrice(chainId: number, tokenAddress: string): Promise<number | null> {
      return getPrice(chainId, tokenAddress);
    },

    async weiToUsd(
      weiValue: string,
      chainId: number,
      tokenAddress?: string,
    ): Promise<number | null> {
      const isNative = !tokenAddress || tokenAddress === "native" || tokenAddress === "";
      const price = isNative
        ? await oracle.getNativeUsdPrice(chainId)
        : await oracle.getTokenUsdPrice(chainId, tokenAddress!);

      if (price === null) return null;

      // Strict decimals (SEC-190): unknown chains/tokens return null and the
      // conversion fails closed instead of guessing 18 decimals.
      const decimals = isNative
        ? getNativeDecimalsStrict(chainId)
        : getTokenDecimalsStrict(chainId, tokenAddress);
      if (decimals === null) {
        console.warn(
          `[price-oracle] Unknown decimals for chainId ${chainId} token ${tokenAddress ?? "native"}; failing closed`,
        );
        return null;
      }

      // Convert wei to token units: weiValue / 10^decimals
      // Use BigInt arithmetic to avoid floating point issues with large numbers
      const wei = BigInt(weiValue);
      const divisor = 10n ** BigInt(decimals);
      const wholePart = wei / divisor;
      const remainder = wei % divisor;

      // Convert to number: wholePart + remainder/divisor
      const tokenAmount = Number(wholePart) + Number(remainder) / Number(divisor);
      return tokenAmount * price;
    },

    async usdToWei(
      usdValue: number,
      chainId: number,
      tokenAddress?: string,
    ): Promise<string | null> {
      const isNative = !tokenAddress || tokenAddress === "native" || tokenAddress === "";
      const price = isNative
        ? await oracle.getNativeUsdPrice(chainId)
        : await oracle.getTokenUsdPrice(chainId, tokenAddress!);

      if (price === null || price === 0) return null;

      // Strict decimals (SEC-190): unknown chains/tokens fail closed.
      const decimals = isNative
        ? getNativeDecimalsStrict(chainId)
        : getTokenDecimalsStrict(chainId, tokenAddress);
      if (decimals === null) {
        console.warn(
          `[price-oracle] Unknown decimals for chainId ${chainId} token ${tokenAddress ?? "native"}; failing closed`,
        );
        return null;
      }

      if (!Number.isFinite(usdValue) || usdValue < 0) return null;

      // Rational arithmetic (SEC-189): scale the USD input and price to
      // micro-unit integers and divide in BigInt, so values beyond 2^53 stay
      // exact. Rounds to nearest (half up) — an explicit rounding policy,
      // replacing the old double-math `Math.floor(tokenAmount * 10**decimals)`
      // which lost precision and always rounded down.
      const usdMicros = BigInt(Math.round(usdValue * 1_000_000));
      const priceMicros = BigInt(Math.round(price * 1_000_000));
      if (priceMicros <= 0n) return null;
      const numerator = usdMicros * 10n ** BigInt(decimals);
      const wei = (numerator * 2n + priceMicros) / (priceMicros * 2n);
      return wei.toString();
    },
  };

  return oracle;
}

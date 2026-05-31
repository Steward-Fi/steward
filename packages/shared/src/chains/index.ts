/**
 * Chain provider registry.
 *
 * To add a new chain:
 *   1. Create `chains/<name>.ts` exporting a `ChainProvider`.
 *   2. Import it below and add it to the `CHAIN_PROVIDERS` array.
 *
 * Everything else (CAIP-2 lookups, explorer URLs, badge colors, wagmi/UI
 * config) reads from this single source of truth.
 */
import { arbitrum } from "./arbitrum.js";
import { base, baseSepolia } from "./base.js";
import { bsc, bscTestnet } from "./bsc.js";
import { ethereum } from "./ethereum.js";
import { gnosis } from "./gnosis.js";
import { polygon } from "./polygon.js";
import { solana, solanaDevnet } from "./solana.js";
import type { ChainProvider } from "./types.js";

export {
  isSigningCurve,
  isSigningCurveSupported,
  RAW_SIGNING_CHAIN_SUPPORT,
  rawSigningChainSupport,
  type RawSigningChain,
  type RawSigningChainSupport,
  SIGNING_CURVE_SUPPORT,
  type SigningCurve,
  type SigningCurveSupport,
  STARK_UNSUPPORTED_REASON,
  SUPPORTED_SIGNING_CURVES,
  signingCurveSupport,
} from "./signing.js";
export type { ChainProvider } from "./types.js";

/** All registered chain providers. Add new entries here. */
export const CHAIN_PROVIDERS: readonly ChainProvider[] = [
  ethereum,
  bsc,
  bscTestnet,
  polygon,
  gnosis,
  base,
  baseSepolia,
  arbitrum,
  solana,
  solanaDevnet,
];

/** Lookup helpers built from the registry. */
export const CHAIN_PROVIDERS_BY_CAIP2: Record<string, ChainProvider> = Object.freeze(
  Object.fromEntries(CHAIN_PROVIDERS.map((c) => [c.caip2, c])),
);

export const CHAIN_PROVIDERS_BY_NUMERIC: Record<number, ChainProvider> = Object.freeze(
  Object.fromEntries(CHAIN_PROVIDERS.map((c) => [c.numericId, c])),
);

export function getChainProviderByCaip2(caip2: string): ChainProvider | undefined {
  return CHAIN_PROVIDERS_BY_CAIP2[caip2];
}

export function getChainProviderByNumeric(numericId: number): ChainProvider | undefined {
  return CHAIN_PROVIDERS_BY_NUMERIC[numericId];
}

export {
  arbitrum,
  base,
  baseSepolia,
  bsc,
  bscTestnet,
  ethereum,
  gnosis,
  polygon,
  solana,
  solanaDevnet,
};

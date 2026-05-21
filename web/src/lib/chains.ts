/**
 * Frontend chain metadata.
 *
 * Derived from the single source of truth in `@stwd/shared`'s
 * `CHAIN_PROVIDERS` registry. To add a new chain, add it once in
 * `packages/shared/src/chains/` and it shows up here automatically.
 */
import { CHAIN_PROVIDERS, getChainProviderByNumeric } from "@stwd/shared";

export interface ChainMeta {
  id: number;
  name: string;
  symbol: string;
  explorerUrl: string;
  explorerTxUrl: string;
  color: string;
}

export const CHAIN_META: Record<number, ChainMeta> = Object.freeze(
  Object.fromEntries(
    CHAIN_PROVIDERS.map((p) => [
      p.numericId,
      {
        id: p.numericId,
        name: p.name,
        symbol: p.symbol,
        explorerUrl: p.explorerUrl,
        // Kept as a prefix-style string for backwards compatibility with
        // existing call sites that concatenate a tx hash directly.
        explorerTxUrl: `${p.explorerUrl}/tx/`,
        color: p.color,
      } satisfies ChainMeta,
    ]),
  ),
);

export function getChainMeta(chainId: number): ChainMeta | undefined {
  return CHAIN_META[chainId];
}

export function getExplorerTxLink(chainId: number, txHash: string): string | undefined {
  const provider = getChainProviderByNumeric(chainId);
  return provider?.explorerTxUrl(txHash);
}

export function getExplorerAddressLink(chainId: number, address: string): string | undefined {
  const provider = getChainProviderByNumeric(chainId);
  return provider?.explorerAddressUrl(address);
}

export function getChainName(chainId: number): string {
  return CHAIN_META[chainId]?.name ?? `Chain ${chainId}`;
}

export function getChainSymbol(chainId: number): string {
  return CHAIN_META[chainId]?.symbol ?? "ETH";
}

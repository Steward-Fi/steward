export interface ChainMeta {
  id: number;
  name: string;
  symbol: string;
  explorerUrl: string;
  explorerTxUrl: string;
  color: string; // for chain badge
}

export const CHAIN_META: Record<number, ChainMeta> = {
  1: { id: 1, name: "Ethereum", symbol: "ETH", explorerUrl: "https://etherscan.io", explorerTxUrl: "https://etherscan.io/tx/", color: "#627EEA" },
  56: { id: 56, name: "BSC", symbol: "BNB", explorerUrl: "https://bscscan.com", explorerTxUrl: "https://bscscan.com/tx/", color: "#F0B90B" },
  137: { id: 137, name: "Polygon", symbol: "POL", explorerUrl: "https://polygonscan.com", explorerTxUrl: "https://polygonscan.com/tx/", color: "#8247E5" },
  8453: { id: 8453, name: "Base", symbol: "ETH", explorerUrl: "https://basescan.org", explorerTxUrl: "https://basescan.org/tx/", color: "#0052FF" },
  42161: { id: 42161, name: "Arbitrum", symbol: "ETH", explorerUrl: "https://arbiscan.io", explorerTxUrl: "https://arbiscan.io/tx/", color: "#28A0F0" },
};

export function getChainMeta(chainId: number): ChainMeta | undefined {
  return CHAIN_META[chainId];
}

export function getExplorerTxLink(chainId: number, txHash: string): string | undefined {
  const meta = CHAIN_META[chainId];
  return meta ? `${meta.explorerTxUrl}${txHash}` : undefined;
}

export function getExplorerAddressLink(chainId: number, address: string): string | undefined {
  const meta = CHAIN_META[chainId];
  return meta ? `${meta.explorerUrl}/address/${address}` : undefined;
}

export function getChainName(chainId: number): string {
  return CHAIN_META[chainId]?.name ?? `Chain ${chainId}`;
}

export function getChainSymbol(chainId: number): string {
  return CHAIN_META[chainId]?.symbol ?? "ETH";
}

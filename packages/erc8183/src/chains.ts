import type { ERC8183ChainConfig } from "./types";

// TODO: fill from BNB ERC-8183 deployment — testnet first.
// Real AgenticCommerce, EvaluatorRouter, OptimisticPolicy, and payment token addresses
// are intentionally left undefined. The client requires explicit addresses at runtime
// and will throw rather than silently using fake mainnet deployments.
export const ERC8183_CHAIN_CONFIGS: Record<number, ERC8183ChainConfig> = {
  97: {
    chainId: 97,
    name: "BSC Testnet",
    rpcUrl: "https://data-seed-prebsc-1-s1.binance.org:8545",
    addresses: {},
  },
  56: {
    chainId: 56,
    name: "BSC",
    rpcUrl: "https://bsc-dataseed.binance.org",
    addresses: {},
  },
};

export function getERC8183ChainConfig(chainId: number): ERC8183ChainConfig | undefined {
  return ERC8183_CHAIN_CONFIGS[chainId];
}

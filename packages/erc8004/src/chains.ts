/**
 * Known ERC-8004 registry deployments per chain.
 *
 * All addresses are placeholders until contracts are deployed.
 */

import type { RegistryConfig } from "./types";

/**
 * Sentinel address used for every chain until real registry contracts are
 * deployed. Any config still carrying this address is NOT a live registry and
 * must never be used to fabricate on-chain data.
 */
export const PLACEHOLDER_REGISTRY = "0x0000000000000000000000000000000000008004";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

/**
 * Returns true only when the config points at a real, deployed registry — i.e.
 * a non-placeholder, non-zero EVM address. This is the single source of truth
 * for whether on-chain calls can be trusted.
 */
export function isRegistryConfigured(config: Pick<RegistryConfig, "registryAddress">): boolean {
  const addr = config.registryAddress?.trim().toLowerCase();
  if (!addr || !/^0x[0-9a-f]{40}$/.test(addr)) return false;
  if (addr === PLACEHOLDER_REGISTRY.toLowerCase()) return false;
  if (addr === ZERO_ADDRESS.toLowerCase()) return false;
  return true;
}

export const REGISTRY_CONFIGS: Record<number, RegistryConfig> = {
  8453: {
    chainId: 8453,
    name: "Base",
    rpcUrl: "https://mainnet.base.org",
    registryAddress: PLACEHOLDER_REGISTRY,
  },
  1: {
    chainId: 1,
    name: "Ethereum",
    rpcUrl: "https://eth.llamarpc.com",
    registryAddress: PLACEHOLDER_REGISTRY,
  },
  56: {
    chainId: 56,
    name: "BSC",
    rpcUrl: "https://bsc-dataseed.binance.org",
    registryAddress: PLACEHOLDER_REGISTRY,
  },
  100: {
    chainId: 100,
    name: "Gnosis",
    rpcUrl: "https://rpc.gnosischain.com",
    registryAddress: PLACEHOLDER_REGISTRY,
  },
  42161: {
    chainId: 42161,
    name: "Arbitrum",
    rpcUrl: "https://arb1.arbitrum.io/rpc",
    registryAddress: PLACEHOLDER_REGISTRY,
  },
};

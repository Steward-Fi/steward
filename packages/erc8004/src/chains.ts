/**
 * Known ERC-8004 registry deployments per chain.
 */

import type { Address } from "viem";
import type { RegistryConfig } from "./types";

export const ERC8004_IDENTITY_REGISTRY_ADDRESS: Address =
  "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";

export const ERC8004_REPUTATION_REGISTRY_ADDRESS: Address =
  "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63";

/**
 * Sentinel address used for chains where real registry contracts are not
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

function registryConfig(
  params: Omit<RegistryConfig, "registryAddress" | "identityRegistry" | "reputationRegistry">,
): RegistryConfig {
  return {
    ...params,
    registryAddress: ERC8004_IDENTITY_REGISTRY_ADDRESS,
    identityRegistry: ERC8004_IDENTITY_REGISTRY_ADDRESS,
    reputationRegistry: ERC8004_REPUTATION_REGISTRY_ADDRESS,
  };
}

export const REGISTRY_CONFIGS: Record<number, RegistryConfig> = {
  8453: registryConfig({
    chainId: 8453,
    name: "Base",
    rpcUrl: "https://mainnet.base.org",
  }),
  1: registryConfig({
    chainId: 1,
    name: "Ethereum",
    rpcUrl: "https://eth.llamarpc.com",
  }),
  56: registryConfig({
    chainId: 56,
    name: "BSC",
    rpcUrl: "https://bsc-dataseed.binance.org",
  }),
  97: registryConfig({
    chainId: 97,
    name: "BSC Testnet",
    rpcUrl: "https://data-seed-prebsc-1-s1.binance.org:8545",
  }),
  100: registryConfig({
    chainId: 100,
    name: "Gnosis",
    rpcUrl: "https://rpc.gnosischain.com",
  }),
  42161: registryConfig({
    chainId: 42161,
    name: "Arbitrum",
    rpcUrl: "https://arb1.arbitrum.io/rpc",
  }),
};

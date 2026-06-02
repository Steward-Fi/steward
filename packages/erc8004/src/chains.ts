/**
 * Known ERC-8004 registry deployments per chain.
 */

import type { Address } from "viem";
import type { RegistryConfig } from "./types";

export const ERC8004_IDENTITY_REGISTRY_ADDRESS: Address =
  "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432";

export const ERC8004_REPUTATION_REGISTRY_ADDRESS: Address =
  "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63";

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

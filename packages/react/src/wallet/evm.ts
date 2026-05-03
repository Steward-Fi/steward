/**
 * EVM-only wallet entry. Import this when your app only needs SIWE
 * (no Solana). Requires only EVM peer deps: wagmi, viem, RainbowKit,
 * @tanstack/react-query.
 *
 * Usage:
 *   import { EVMWalletProvider, createDefaultWagmiConfig } from "@stwd/react/wallet/evm";
 */

export type {
  CreateDefaultWagmiConfigOptions,
  DefaultWagmiChains,
  EVMWalletProviderProps,
} from "../providers/EVMProvider.js";
export {
  createDefaultWagmiConfig,
  EVMWalletProvider,
} from "../providers/EVMProvider.js";

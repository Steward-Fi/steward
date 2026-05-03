/**
 * Backwards-compatible barrel that re-exports both EVM and Solana
 * provider modules. Importing this file evaluates both peer-dep trees,
 * so consumers who only need one chain should import from
 * `./EVMProvider.js` or `./SolanaProvider.js` directly (or use the
 * `@stwd/react/wallet/evm` and `@stwd/react/wallet/solana` subpath
 * exports).
 *
 * Existing imports from `@stwd/react/wallet` continue to work.
 */

export type {
  CreateDefaultWagmiConfigOptions,
  DefaultWagmiChains,
  EVMWalletProviderProps,
} from "./EVMProvider.js";
export { createDefaultWagmiConfig, EVMWalletProvider } from "./EVMProvider.js";
export type { SolanaWalletProviderProps } from "./SolanaProvider.js";
export {
  createDefaultSolanaWallets,
  DEFAULT_SOLANA_WALLETS,
  SolanaWalletProvider,
} from "./SolanaProvider.js";

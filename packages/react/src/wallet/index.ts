import {
  registerEvmWalletPanel,
  registerSolanaWalletPanel,
} from "../internal/walletPanelRegistry.js";

// Side-effect registration: importing `@stwd/react/wallet` registers the
// wallet panel loaders so `<StewardLogin showWallets>` can find them.
// This keeps the root entry (`@stwd/react`) free of any references to
// wallet peer deps. Bundlers that don't see this subpath imported never
// pull wagmi / RainbowKit / @solana/* into their dep graph.
registerEvmWalletPanel({
  load: () =>
    import("../components/WalletLogin.EVM.js") as Promise<{
      default: import("react").ComponentType<unknown>;
    }>,
});
registerSolanaWalletPanel({
  load: () =>
    import("../components/WalletLogin.Solana.js") as Promise<{
      default: import("react").ComponentType<unknown>;
    }>,
});

export type {
  StewardLoginWithWalletsEvmConfig,
  StewardLoginWithWalletsProps,
  StewardLoginWithWalletsSolanaConfig,
} from "./components/StewardLoginWithWallets.js";
export { StewardLoginWithWallets } from "./components/StewardLoginWithWallets.js";
export type {
  WalletChains,
  WalletLoginClassOverrides,
  WalletLoginProps,
} from "../components/WalletLogin.js";
export { WalletLogin } from "../components/WalletLogin.js";
export type {
  CreateDefaultWagmiConfigOptions,
  DefaultWagmiChains,
  EVMWalletProviderProps,
  SolanaWalletProviderProps,
} from "../providers/WalletProviders.js";
export {
  createDefaultWagmiConfig,
  DEFAULT_SOLANA_WALLETS,
  EVMWalletProvider,
  SolanaWalletProvider,
} from "../providers/WalletProviders.js";

import { connectorsForWallets } from "@rainbow-me/rainbowkit";
import {
  coinbaseWallet,
  injectedWallet,
  ledgerWallet,
  metaMaskWallet,
  rabbyWallet,
  rainbowWallet,
  safeWallet,
  trustWallet,
  walletConnectWallet,
} from "@rainbow-me/rainbowkit/wallets";
import { type Config, createConfig, http } from "wagmi";
import { arbitrum, base, bsc, mainnet, optimism, polygon } from "wagmi/chains";

/**
 * WalletConnect projectId.
 *
 * Resolved from `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` and falls back to a
 * shared default. Production deployments should configure their own projectId
 * via env to avoid rate-limit collisions on the shared key.
 */
const projectId =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "2c7ddf841a48e522748c5e2782d73443";

/**
 * Lazy factory for the wagmi/RainbowKit config.
 *
 * Why lazy: `connectorsForWallets()` and `createConfig()` build wallet
 * connector instances that touch browser globals (indexedDB, localStorage,
 * window) inside their constructors. If we evaluate this at module scope,
 * Next prerender during `next build` will throw `ReferenceError: indexedDB
 * is not defined` because import side effects run on the server too. The
 * factory + memo pattern keeps the config singleton-equivalent on the
 * client while never running on the server.
 */
let cachedConfig: Config | undefined;
export function getWagmiConfig(): Config {
  if (cachedConfig) return cachedConfig;
  const connectors = connectorsForWallets(
    [
      {
        groupName: "Recommended",
        wallets: [metaMaskWallet, coinbaseWallet, walletConnectWallet],
      },
      {
        groupName: "More",
        wallets: [
          rainbowWallet,
          rabbyWallet,
          trustWallet,
          ledgerWallet,
          safeWallet,
          injectedWallet,
        ],
      },
    ],
    { appName: "Steward", projectId },
  );
  cachedConfig = createConfig({
    connectors,
    chains: [mainnet, base, polygon, optimism, arbitrum, bsc],
    transports: {
      [mainnet.id]: http(),
      [base.id]: http(),
      [polygon.id]: http(),
      [optimism.id]: http(),
      [arbitrum.id]: http(),
      [bsc.id]: http(),
    },
    ssr: true,
  });
  return cachedConfig;
}

/**
 * Solana JSON-RPC endpoint.
 *
 * Defaults to mainnet-beta public RPC. Production should use a private
 * provider (Helius, QuickNode, Triton, etc.) via
 * `NEXT_PUBLIC_SOLANA_RPC_URL`.
 */
export const SOLANA_RPC_URL =
  process.env.NEXT_PUBLIC_SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";

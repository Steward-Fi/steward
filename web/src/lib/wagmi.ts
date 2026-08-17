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
import { arbitrum, base, bsc, gnosis, mainnet, optimism, polygon } from "wagmi/chains";

/**
 * WalletConnect projectId.
 *
 * Resolved from `NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID`. The shared built-in
 * fallback exists only so local dev and the e2e harness work out of the box —
 * every default build otherwise shares one public quota/identity, which can be
 * rate-limited or abused by third parties (SEC-157). The production deploy
 * pipeline (cf:build/cf:preview/cf:deploy) refuses to build without the env
 * var (scripts/assert-production-deploy-env.mjs), and production builds warn
 * loudly at runtime if the fallback is somehow still in use.
 */
const SHARED_FALLBACK_PROJECT_ID = "2c7ddf841a48e522748c5e2782d73443";
const projectId = process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || SHARED_FALLBACK_PROJECT_ID;

if (process.env.NODE_ENV === "production" && projectId === SHARED_FALLBACK_PROJECT_ID) {
  console.warn(
    "[steward] NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID is unset: this build shares the default WalletConnect projectId quota/identity. Configure a dedicated projectId for production.",
  );
}

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
    chains: [mainnet, base, polygon, gnosis, optimism, arbitrum, bsc],
    transports: {
      [mainnet.id]: http(),
      [base.id]: http(),
      [polygon.id]: http(),
      [gnosis.id]: http(),
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

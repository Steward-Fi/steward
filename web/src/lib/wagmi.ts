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
import { createConfig, http } from "wagmi";
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

const connectors = connectorsForWallets(
  [
    {
      groupName: "Recommended",
      wallets: [metaMaskWallet, coinbaseWallet, walletConnectWallet],
    },
    {
      groupName: "More",
      wallets: [rainbowWallet, rabbyWallet, trustWallet, ledgerWallet, safeWallet, injectedWallet],
    },
  ],
  { appName: "Steward", projectId },
);

export const wagmiConfig = createConfig({
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

/**
 * Solana JSON-RPC endpoint.
 *
 * Defaults to mainnet-beta public RPC. Production should use a private
 * provider (Helius, QuickNode, Triton, etc.) via
 * `NEXT_PUBLIC_SOLANA_RPC_URL`.
 */
export const SOLANA_RPC_URL =
  process.env.NEXT_PUBLIC_SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";

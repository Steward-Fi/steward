/**
 * Wallet Login example, two usage patterns.
 *
 * Pattern A: Use the bundled <EVMWalletProvider> / <SolanaWalletProvider>
 *            wrappers. Fastest path for greenfield apps.
 *
 * Pattern B: Bring your own wagmi + Solana provider stack. Preferred for apps
 *            that already have wallet providers mounted elsewhere.
 *
 * This file is documentation, not shipped code. It is not part of the build.
 */

import { StewardProvider } from "@stwd/react";
import {
  createDefaultWagmiConfig,
  DEFAULT_SOLANA_WALLETS,
  EVMWalletProvider,
  SolanaWalletProvider,
  WalletLogin,
} from "@stwd/react/wallet";
import { StewardClient } from "@stwd/sdk";

import "@stwd/react/styles.css";
import "@rainbow-me/rainbowkit/styles.css";
import "@solana/wallet-adapter-react-ui/styles.css";

import { base, mainnet } from "wagmi/chains";

// Use your own production WalletConnect project ID when possible. The fallback
// below is Steward-owned and keeps the example working for first-time testing.
const walletConnectProjectId =
  process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID || "2c7ddf841a48e522748c5e2782d73443";

// ─── Pattern A: bundled wrappers ─────────────────────────────────────────────

const wagmiConfig = createDefaultWagmiConfig({
  appName: "Steward",
  projectId: walletConnectProjectId,
  chains: [mainnet, base],
});

const stewardClient = new StewardClient({
  baseUrl: "https://api.steward.fi",
  apiKey: "…",
});

export function PatternA() {
  return (
    <StewardProvider
      client={stewardClient}
      agentId="agent_abc"
      auth={{ baseUrl: "https://api.steward.fi" }}
    >
      <EVMWalletProvider config={wagmiConfig}>
        <SolanaWalletProvider endpoint="https://api.mainnet-beta.solana.com">
          <WalletLogin
            chains="both"
            showWallets
            onSuccess={(result, kind) => {
              console.log("signed in via", kind, result.token);
            }}
            onError={(err, kind) => {
              console.error(kind, err);
            }}
          />
        </SolanaWalletProvider>
      </EVMWalletProvider>
    </StewardProvider>
  );
}

// ─── Pattern B: bring your own providers ─────────────────────────────────────

import { darkTheme, RainbowKitProvider } from "@rainbow-me/rainbowkit";
import {
  ConnectionProvider,
  WalletProvider as SolanaAdapterProvider,
} from "@solana/wallet-adapter-react";
import { WalletModalProvider } from "@solana/wallet-adapter-react-ui";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WagmiProvider } from "wagmi";

const queryClient = new QueryClient();

export function PatternB() {
  const solanaWallets = [...DEFAULT_SOLANA_WALLETS];
  return (
    <WagmiProvider config={wagmiConfig}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider theme={darkTheme()} modalSize="compact">
          <ConnectionProvider endpoint="https://api.mainnet-beta.solana.com">
            <SolanaAdapterProvider wallets={solanaWallets} autoConnect>
              <WalletModalProvider>
                <StewardProvider
                  client={stewardClient}
                  agentId="agent_abc"
                  auth={{ baseUrl: "https://api.steward.fi" }}
                >
                  <WalletLogin chains="both" showWallets />
                </StewardProvider>
              </WalletModalProvider>
            </SolanaAdapterProvider>
          </ConnectionProvider>
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

// ─── Single-chain example ────────────────────────────────────────────────────

export function EvmOnly() {
  return (
    <StewardProvider
      client={stewardClient}
      agentId="agent_abc"
      auth={{ baseUrl: "https://api.steward.fi" }}
    >
      <EVMWalletProvider config={wagmiConfig}>
        <WalletLogin chains="evm" showWallets />
      </EVMWalletProvider>
    </StewardProvider>
  );
}

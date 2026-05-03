import {
  connectorsForWallets,
  darkTheme,
  RainbowKitProvider,
  type Theme,
} from "@rainbow-me/rainbowkit";
import {
  coinbaseWallet,
  injectedWallet,
  ledgerWallet,
  metaMaskWallet,
  phantomWallet,
  rabbyWallet,
  rainbowWallet,
  safeWallet,
  trustWallet,
  walletConnectWallet,
} from "@rainbow-me/rainbowkit/wallets";
import {
  ConnectionProvider,
  WalletProvider,
  type WalletProviderProps,
} from "@solana/wallet-adapter-react";
import { WalletModalProvider } from "@solana/wallet-adapter-react-ui";
import {
  Coin98WalletAdapter,
  CoinbaseWalletAdapter,
  MathWalletAdapter,
  PhantomWalletAdapter,
  SolflareWalletAdapter,
  TrustWalletAdapter,
} from "@solana/wallet-adapter-wallets";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { type ReactNode, useMemo } from "react";
import type { Chain, Transport } from "viem";
// All imports from optional peer dependencies are intentional. These two
// wrappers are opt-in utilities; consumers who ship their own wagmi / Solana
// providers should import them directly instead of using these.
import { createConfig, http, type Config as WagmiConfig, WagmiProvider } from "wagmi";

// ─── EVM wrapper ─────────────────────────────────────────────────────────────

export type DefaultWagmiChains = readonly [Chain, ...Chain[]];

type DefaultWagmiTransports<TChains extends DefaultWagmiChains> = Record<
  TChains[number]["id"],
  Transport
>;

export interface CreateDefaultWagmiConfigOptions<TChains extends DefaultWagmiChains> {
  /** WalletConnect Cloud project ID. Get one at https://cloud.walletconnect.com. */
  projectId: string;
  /** wagmi chains to support. Must include at least one chain. */
  chains: TChains;
  /** App name shown in wallet connection prompts. Defaults to "Steward". */
  appName?: string;
  /** Enable wagmi SSR support. Defaults to true. */
  ssr?: boolean;
}

function createDefaultTransports<TChains extends DefaultWagmiChains>(
  chains: TChains,
): DefaultWagmiTransports<TChains> {
  return Object.fromEntries(
    chains.map((chain) => [chain.id, http()]),
  ) as DefaultWagmiTransports<TChains>;
}

/**
 * Creates a wagmi config with Steward's curated RainbowKit wallet order.
 * Consumers can keep passing their own config to EVMWalletProvider when they
 * need full control.
 */
export function createDefaultWagmiConfig<TChains extends DefaultWagmiChains>({
  projectId,
  chains,
  appName = "Steward",
  ssr = true,
}: CreateDefaultWagmiConfigOptions<TChains>): WagmiConfig {
  const connectors = connectorsForWallets(
    [
      {
        groupName: "Recommended",
        wallets: [
          metaMaskWallet,
          coinbaseWallet,
          walletConnectWallet,
          rainbowWallet,
          rabbyWallet,
          trustWallet,
          phantomWallet,
          ledgerWallet,
          safeWallet,
          injectedWallet,
        ],
      },
    ],
    { appName, projectId },
  );

  return createConfig({
    chains,
    connectors,
    transports: createDefaultTransports(chains),
    ssr,
  }) as WagmiConfig;
}

export interface EVMWalletProviderProps {
  /** wagmi v2 `Config` created with `createConfig()` or `createDefaultWagmiConfig()`. */
  config: WagmiConfig;
  /**
   * TanStack Query client. Pass yours if the host app already has one;
   * otherwise a default client is created and scoped to this subtree.
   */
  queryClient?: QueryClient;
  /** RainbowKit theme. Defaults to dark. Pass `null` to skip theming. */
  theme?: Theme | null;
  /** RainbowKit modal size. Defaults to "compact". */
  modalSize?: "compact" | "wide";
  /** Reconnect on mount. Defaults to true. */
  reconnectOnMount?: boolean;
  children?: ReactNode;
}

/**
 * Wraps children with wagmi + RainbowKit + TanStack Query providers. This is
 * an optional convenience. Most apps already have their own wagmi setup;
 * skip this wrapper if so. `<WalletLogin chains="evm">` only needs the
 * ambient wagmi + RainbowKit + QueryClient context to exist above it.
 *
 * Remember to import `@rainbow-me/rainbowkit/styles.css` once at your app root.
 */
export function EVMWalletProvider({
  config,
  queryClient,
  theme,
  modalSize = "compact",
  reconnectOnMount = true,
  children,
}: EVMWalletProviderProps) {
  const resolvedTheme = theme === null ? null : (theme ?? darkTheme());
  const client = useMemo(() => queryClient ?? new QueryClient(), [queryClient]);
  return (
    <WagmiProvider config={config} reconnectOnMount={reconnectOnMount}>
      <QueryClientProvider client={client}>
        <RainbowKitProvider theme={resolvedTheme} modalSize={modalSize}>
          {children}
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  );
}

// ─── Solana wrapper ──────────────────────────────────────────────────────────

// Default Solana wallet adapters. Hardware wallets (Ledger, Trezor) are
// intentionally excluded from defaults: their adapter packages do not
// implement `signMessage`, so they cannot complete the SIWS sign-in flow.
// Additionally, `@ledgerhq/errors` ships a non-extension import that
// `ERR_MODULE_NOT_FOUND`s under Node ESM/SSR, which would break apps that
// import `@stwd/react/wallet` server-side. Apps that want hardware support
// in non-login contexts can extend the wallet list explicitly.
export const DEFAULT_SOLANA_WALLETS = [
  new PhantomWalletAdapter(),
  new SolflareWalletAdapter(),
  new CoinbaseWalletAdapter(),
  new TrustWalletAdapter(),
  new MathWalletAdapter(),
  new Coin98WalletAdapter(),
] satisfies WalletProviderProps["wallets"];

export interface SolanaWalletProviderProps {
  /** JSON-RPC endpoint (`https://api.mainnet-beta.solana.com`, Helius, etc.). */
  endpoint: string;
  /**
   * Wallet adapters. Defaults to DEFAULT_SOLANA_WALLETS. Pass an explicit
   * array to narrow, replace, or extend the list.
   *
   * Backpack, Brave, and other Solana Wallet Standard wallets are discovered
   * by wallet-adapter at runtime when the browser wallet is present.
   */
  wallets?: WalletProviderProps["wallets"];
  /** Auto-connect previously selected wallet on mount. Defaults to true. */
  autoConnect?: boolean;
  children?: ReactNode;
}

/**
 * Wraps children with Solana wallet-adapter providers. Optional convenience.
 *
 * Remember to import `@solana/wallet-adapter-react-ui/styles.css` once at your
 * app root.
 */
export function SolanaWalletProvider({
  endpoint,
  wallets,
  autoConnect = true,
  children,
}: SolanaWalletProviderProps) {
  const resolvedWallets = wallets ?? DEFAULT_SOLANA_WALLETS;

  return (
    <ConnectionProvider endpoint={endpoint}>
      <WalletProvider wallets={resolvedWallets} autoConnect={autoConnect}>
        <WalletModalProvider>{children}</WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}

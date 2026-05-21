"use client";

/**
 * <StewardLoginWithWallets>
 *
 * Drop-in component that bundles `<StewardLogin showWallets>` with the
 * wagmi + RainbowKit + Solana provider trees so consumers can mount wallet
 * login with a single component, no manual provider wiring.
 *
 * This is the bundled wallet-login surface. It is purely additive over
 * `<StewardLogin>` + the manual provider wrap path, which still works for
 * consumers who want full control of their wallet provider configuration.
 *
 * Peer deps: importing this component pulls BOTH EVM and Solana peer
 * trees. Apps that want only one chain should use the manual path
 * (`<StewardLogin showWallets={{ evm: true }}>` + `<EVMWalletProvider>`)
 * and import from the chain-specific subpaths
 * `@stwd/react/wallet/evm` or `@stwd/react/wallet/solana`.
 */

import { type ReactNode, useMemo } from "react";
import type { Chain } from "viem";
import type { Config as WagmiConfig } from "wagmi";
import { arbitrum, base, bsc, mainnet, optimism, polygon } from "wagmi/chains";
import {
  createDefaultWagmiConfig,
  EVMWalletProvider,
  type EVMWalletProviderProps,
} from "../providers/EVMProvider.js";
import {
  SolanaWalletProvider,
  type SolanaWalletProviderProps,
} from "../providers/SolanaProvider.js";
import type { StewardLoginProps } from "../types.js";
import { StewardLogin } from "./StewardLogin.js";

/** Steward-owned WalletConnect Cloud project ID, suitable for development.
 *  Production apps should bring their own. */
const STEWARD_DEFAULT_WALLETCONNECT_PROJECT_ID = "2c7ddf841a48e522748c5e2782d73443";

/** Default chain set for the bundled EVM wagmi config. */
const DEFAULT_EVM_CHAINS = [mainnet, base, polygon, optimism, arbitrum, bsc] as const;

/** Default Solana JSON-RPC endpoint. Production apps should pass a private RPC
 *  (Helius, QuickNode) via `solana.endpoint`. The public mainnet-beta
 *  endpoint is rate-limited and not for production. */
const DEFAULT_SOLANA_ENDPOINT = "https://api.mainnet-beta.solana.com";

export interface StewardLoginWithWalletsEvmConfig {
  /** Pre-built wagmi `Config`. Takes precedence over the rest of this object. */
  config?: WagmiConfig;
  /** WalletConnect Cloud projectId. Falls back to
   *  `process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID` then to a Steward
   *  shared default for dev. Apps SHOULD set their own in production. */
  projectId?: string;
  /** Chains to support. Defaults to a curated EVM mainnet set. */
  chains?: readonly [Chain, ...Chain[]];
  /** App name shown in the WalletConnect connection prompt. Default: "Steward". */
  appName?: string;
  /** Forwarded to `<EVMWalletProvider>` (theme / modalSize / queryClient / etc). */
  providerProps?: Omit<EVMWalletProviderProps, "config" | "children">;
}

export interface StewardLoginWithWalletsSolanaConfig {
  /** JSON-RPC endpoint. Default: public mainnet-beta. */
  endpoint?: string;
  /** Override default wallet adapter list. */
  wallets?: SolanaWalletProviderProps["wallets"];
  /** Auto-connect previously selected wallet on mount. Default true. */
  autoConnect?: boolean;
}

export interface StewardLoginWithWalletsProps extends StewardLoginProps {
  /** EVM provider configuration. */
  evm?: StewardLoginWithWalletsEvmConfig;
  /** Solana provider configuration. */
  solana?: StewardLoginWithWalletsSolanaConfig;
  /** Per-chain enable gates. Set `evm: false` to skip EVM wrap, `solana: false`
   *  to skip Solana wrap. By default, both wraps are applied. */
  enable?: { evm?: boolean; solana?: boolean };
}

// Bundlers (Next, Vite, esbuild, etc) inline public env vars at build
// time but ONLY when they see the bare member expression
// `process.env.NEXT_PUBLIC_X`. Webpack's DefinePlugin and Vite's `define`
// match a MemberExpression AST node; an OptionalMemberExpression
// (`process?.env?.X`) is a different node shape and is left alone.
// We therefore reference each var via plain `process.env.X` and guard
// `process` itself with `typeof` so this still works in browser-only
// runtimes that lack a `process` global.
//
// In server (Node) builds: this is just a runtime env read.
// In bundler-targeted client builds: Webpack/Vite/esbuild rewrite each
// `process.env.NEXT_PUBLIC_X` to the literal string at compile time, so
// the value is baked into the consumer's bundle.

declare const process: { env: Record<string, string | undefined> } | undefined;

function readWalletConnectProjectIdEnv(): string | undefined {
  try {
    if (typeof process === "undefined") return undefined;
    return process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID;
  } catch {
    return undefined;
  }
}

function readSolanaRpcEnv(): string | undefined {
  try {
    if (typeof process === "undefined") return undefined;
    return process.env.NEXT_PUBLIC_SOLANA_RPC_URL;
  } catch {
    return undefined;
  }
}

function resolveProjectId(override: string | undefined): string {
  if (override) return override;
  return readWalletConnectProjectIdEnv() ?? STEWARD_DEFAULT_WALLETCONNECT_PROJECT_ID;
}

function resolveSolanaEndpoint(override: string | undefined): string {
  if (override) return override;
  return readSolanaRpcEnv() ?? DEFAULT_SOLANA_ENDPOINT;
}

/**
 * The simplest possible wallet-login surface, one component.
 *
 * Wraps children with `<EVMWalletProvider>` and `<SolanaWalletProvider>`
 * (each can be disabled via `enable`) and renders `<StewardLogin>` with
 * the requested `showWallets` value. All other `<StewardLogin>` props
 * are forwarded.
 *
 * Always mount inside a `<StewardProvider>` so the auth context is available.
 */
export function StewardLoginWithWallets({
  evm,
  solana,
  enable,
  ...loginProps
}: StewardLoginWithWalletsProps) {
  const evmEnabled = enable?.evm !== false;
  const solanaEnabled = enable?.solana !== false;

  const wagmiConfig = useMemo<WagmiConfig | null>(() => {
    if (!evmEnabled) return null;
    if (evm?.config) return evm.config;
    return createDefaultWagmiConfig({
      projectId: resolveProjectId(evm?.projectId),
      chains: evm?.chains ?? (DEFAULT_EVM_CHAINS as unknown as readonly [Chain, ...Chain[]]),
      appName: evm?.appName ?? "Steward",
    });
  }, [evmEnabled, evm?.config, evm?.projectId, evm?.chains, evm?.appName]);

  const solanaEndpoint = useMemo(
    () => (solanaEnabled ? resolveSolanaEndpoint(solana?.endpoint) : null),
    [solanaEnabled, solana?.endpoint],
  );

  // Default showWallets to true: this component exists specifically to
  // surface wallet sign-in. Consumers can still pass showWallets={false}
  // to fall back to passkey/email/oauth-only behavior, e.g. for A/B tests.
  const showWallets = loginProps.showWallets ?? {
    evm: evmEnabled,
    solana: solanaEnabled,
  };

  let tree: ReactNode = <StewardLogin {...loginProps} showWallets={showWallets} />;

  if (solanaEnabled && solanaEndpoint) {
    tree = (
      <SolanaWalletProvider
        endpoint={solanaEndpoint}
        wallets={solana?.wallets}
        autoConnect={solana?.autoConnect}
      >
        {tree}
      </SolanaWalletProvider>
    );
  }

  if (evmEnabled && wagmiConfig) {
    tree = (
      <EVMWalletProvider {...(evm?.providerProps ?? {})} config={wagmiConfig}>
        {tree}
      </EVMWalletProvider>
    );
  }

  return <>{tree}</>;
}

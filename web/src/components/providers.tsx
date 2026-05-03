"use client";

import { StewardProvider, useAuth } from "@stwd/react";
import { createElement, type ReactNode, useEffect, useRef, useState } from "react";
import { setAuthToken, steward } from "@/lib/api";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

const API_URL = process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

/**
 * Syncs the Steward auth JWT into the legacy API client once.
 * Uses a ref to avoid re-creating the client on every render.
 */
function AuthTokenSync({ children }: { children: ReactNode }) {
  const auth = useAuth();
  const lastToken = useRef<string | null>(null);

  useEffect(() => {
    if (!auth.isAuthenticated) {
      lastToken.current = null;
      return;
    }
    const token = auth.getToken();
    if (token && token !== lastToken.current) {
      lastToken.current = token;
      setAuthToken(token);
    }
  }, [auth.isAuthenticated, auth.getToken]);

  return <>{children}</>;
}

/**
 * Client-only wallet provider tree.
 *
 * Mounted via `useEffect` so the wallet provider chunks (wagmi +
 * @solana/*) are NEVER evaluated during Next prerender. On the server
 * this component renders `children` directly (zero wallet code on
 * the prerendered HTML). On the client, after hydration, we swap in
 * the full provider tree.
 *
 * This is the SSR-safe alternative to wrapping the whole app in
 * `next/dynamic({ ssr: false })`, which would blank every prerendered
 * page until the wallet bundle loaded.
 */
function WalletProviderTree({ children }: { children: ReactNode }) {
  const [Mounted, setMounted] = useState<{
    EVMWalletProvider: React.ComponentType<{ config: unknown; children: ReactNode }>;
    SolanaWalletProvider: React.ComponentType<{ endpoint: string; children: ReactNode }>;
    config: unknown;
    rpc: string;
  } | null>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([import("@stwd/react/wallet"), import("@/lib/wagmi")]).then(([wallet, wagmi]) => {
      if (cancelled) return;
      setMounted({
        EVMWalletProvider: wallet.EVMWalletProvider as never,
        SolanaWalletProvider: wallet.SolanaWalletProvider as never,
        config: wagmi.getWagmiConfig(),
        rpc: wagmi.SOLANA_RPC_URL,
      });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (!Mounted) {
    // Server render and pre-hydration client render: pass children
    // through unchanged. Wallet UI just won't be available until the
    // dynamic chunks land. Pages without wallets render normally.
    return <>{children}</>;
  }

  return (
    <Mounted.EVMWalletProvider config={Mounted.config}>
      <Mounted.SolanaWalletProvider endpoint={Mounted.rpc}>{children}</Mounted.SolanaWalletProvider>
    </Mounted.EVMWalletProvider>
  );
}

export function Providers({ children }: { children: ReactNode }) {
  return createElement(
    StewardProvider as any,
    {
      client: steward as any,
      auth: { baseUrl: API_URL },
    },
    createElement(WalletProviderTree, null, createElement(AuthTokenSync, null, children)),
  ) as any;
}

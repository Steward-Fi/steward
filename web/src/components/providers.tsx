"use client";

import { StewardProvider, useAuth } from "@stwd/react";
import { EVMWalletProvider } from "@stwd/react/wallet";
import dynamic from "next/dynamic";
import { createElement, type ReactNode, useEffect, useRef } from "react";
import { setAuthToken, steward } from "@/lib/api";
import { SOLANA_RPC_URL, wagmiConfig } from "@/lib/wagmi";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

// Solana wallet provider must be client-only. Solana's wallet-adapter
// constructs adapter instances eagerly at module load and several of
// them touch `indexedDB` / `localStorage` in their constructors, which
// throw `ReferenceError: indexedDB is not defined` when Next prerenders
// client components during `next build`. Loading via next/dynamic with
// ssr:false defers the entire subtree to the browser. This is also what
// most production Solana dapps (Jupiter, Drift, Magic Eden) do.
const SolanaWalletProvider = dynamic(
  () => import("@stwd/react/wallet").then((m) => m.SolanaWalletProvider),
  { ssr: false },
);

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

export function Providers({ children }: { children: ReactNode }) {
  return createElement(
    StewardProvider as any,
    {
      client: steward as any,
      auth: { baseUrl: API_URL },
    },
    createElement(
      EVMWalletProvider as any,
      { config: wagmiConfig },
      createElement(
        SolanaWalletProvider as any,
        { endpoint: SOLANA_RPC_URL },
        createElement(AuthTokenSync, null, children),
      ),
    ),
  ) as any;
}

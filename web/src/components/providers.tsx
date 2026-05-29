"use client";

import { StewardProvider, useAuth } from "@stwd/react";
import { createElement, type ReactNode, useEffect, useRef, useState } from "react";
import { clearAuthToken, setAuthToken, steward } from "@/lib/api";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

const API_URL = process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

/**
 * SECURITY (XSS risk — tracked hardening): this wires the Steward auth tokens
 * (including the long-lived REFRESH token, key `steward_refresh_token`) into
 * `window.sessionStorage`. sessionStorage is readable by any JavaScript running
 * in this origin, so a successful XSS would be able to exfiltrate the refresh
 * token and mint new access tokens.
 *
 * Mitigations in place:
 *   1. PRIMARY: a strict Content-Security-Policy (script-src 'self' only — see
 *      web/next.config.ts `headers()` and web/vercel.json) drastically reduces
 *      the attack surface for injecting hostile script in the first place.
 *   2. sessionStorage (not localStorage) scopes the token to the tab session,
 *      so it is cleared when the tab closes rather than persisting on disk.
 *
 * RECOMMENDED FUTURE HARDENING: move the refresh token to a Secure, HttpOnly,
 * SameSite=Strict cookie issued by a server route so it is unreadable from JS.
 * That is a larger architectural change (server-side cookie issuance +
 * CSRF protection on refresh) and is intentionally NOT done here — do it as a
 * dedicated, fully-tested change rather than a partial swap.
 */
const authStorage = {
  getItem(key: string): string | null {
    if (typeof window === "undefined") return null;
    return window.sessionStorage.getItem(key);
  },
  setItem(key: string, value: string): void {
    if (typeof window === "undefined") return;
    window.sessionStorage.setItem(key, value);
  },
  removeItem(key: string): void {
    if (typeof window === "undefined") return;
    window.sessionStorage.removeItem(key);
  },
};

/**
 * Syncs the Steward auth JWT into the legacy API client once.
 * Uses a ref to avoid re-creating the client on every render.
 */
function AuthTokenSync({ children }: { children: ReactNode }) {
  const auth = useAuth();
  const lastToken = useRef<string | null>(null);
  const sessionToken = auth.session?.token ?? null;

  useEffect(() => {
    if (!auth.isAuthenticated) {
      lastToken.current = null;
      clearAuthToken();
      return;
    }
    const token = sessionToken ?? auth.getToken();
    if (token && token !== lastToken.current) {
      lastToken.current = token;
      setAuthToken(token);
    }
  }, [auth.isAuthenticated, auth.getToken, auth.activeTenantId, sessionToken]);

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
      auth: { baseUrl: API_URL, storage: authStorage },
    },
    createElement(WalletProviderTree, null, createElement(AuthTokenSync, null, children)),
  ) as any;
}

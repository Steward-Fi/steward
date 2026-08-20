"use client";

import { StewardProvider, useAuth } from "@stwd/react";
import { usePathname } from "next/navigation";
import { createElement, type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { clearAuthToken, setAuthToken, steward } from "@/lib/api";
import { STEWARD_API_URL } from "@/lib/steward-api-url";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

const API_URL = STEWARD_API_URL;

/**
 * SECURITY (SEC-018): the long-lived Steward REFRESH token is no longer kept
 * in JS-readable storage. The SDK's auth client is configured with
 * `authProxyUrl: "/api/auth"`, so:
 *   - sign-in deposits the refresh token with the same-origin route handlers
 *     in `app/api/auth/`, which store it in an HttpOnly, SameSite=Strict
 *     host-bound cookie (`__Host-steward_rt`) that page JavaScript cannot read;
 *   - session refresh / revoke / tenant-switch go through those routes, which
 *     inject the cookie-held token before forwarding to the Steward API and
 *     return only the short-lived access token to the browser;
 *   - a successful XSS can ride the live session (as it can with any design)
 *     but can no longer exfiltrate a refresh token to mint sessions offline.
 *
 * Only the short-lived ACCESS token (and transient OAuth PKCE state) uses the
 * storage shim below. Defense in depth remains the strict nonce-based CSP in
 * `web/src/middleware.ts` (script-src 'self' + nonce), and sessionStorage (not
 * localStorage) scopes the access token to the tab session.
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
 * One-time cleanup: sessions established before the SEC-018 cookie custody
 * change left `steward_refresh_token` in sessionStorage. The SDK no longer
 * reads that key (the HttpOnly cookie is authoritative), so remove it to keep
 * the long-lived token out of JS-readable storage for upgraded sessions too.
 */
function removeLegacyRefreshToken(): void {
  if (typeof window === "undefined") return;
  window.sessionStorage.removeItem("steward_refresh_token");
}

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
  const pathname = usePathname();
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

  if (pathname === "/dashboard/webhooks" || pathname?.startsWith("/dashboard/webhooks/")) {
    // Webhook administration does not use wallet capabilities. Keep it outside
    // the optional wallet wrappers so their late load cannot remount the page
    // and repeat configuration or delivery requests.
    return children;
  }

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
  const stewardAuthConfig = useMemo(
    () => ({ baseUrl: API_URL, storage: authStorage, authProxyUrl: "/api/auth" }),
    [],
  );

  useEffect(() => {
    removeLegacyRefreshToken();
  }, []);

  return createElement(
    StewardProvider as any,
    {
      client: steward as any,
      auth: stewardAuthConfig,
    },
    createElement(WalletProviderTree, null, createElement(AuthTokenSync, null, children)),
  ) as any;
}

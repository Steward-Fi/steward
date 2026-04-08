"use client";

/**
 * auth-provider.tsx
 *
 * Handles passkey, email magic-link, and SIWE auth for the dashboard.
 * SIWE (wallet) sign-in still uses raw fetch + wagmi because it needs chainId
 * in the SiweMessage payload.
 */

import {
  createElement,
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useAccount, useDisconnect, useSignMessage } from "wagmi";
import { SiweMessage } from "siwe";

import { sendMagicLink, signInWithPasskey } from "@/lib/auth-api";
import { setAuthToken, setCredentials } from "@/lib/api";

const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

// ─── Types ────────────────────────────────────────────────────────────────────

interface TenantInfo {
  tenantId: string;
  tenantName: string;
  apiKey?: string;
}

export interface AuthContextType {
  /** Ethereum address — set when signed in via wallet (SIWE) */
  address: string | undefined;
  /** Email — set when signed in via passkey or magic link */
  email: string | undefined;
  /** User UUID — set when signed in via passkey or magic link */
  userId: string | undefined;
  /** Tenant info — set when signed in via wallet (SIWE) */
  tenant: TenantInfo | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  /** SIWE wallet sign-in */
  signIn: () => Promise<void>;
  /** Passkey sign-in or registration. */
  signInWithPasskey: (email: string) => Promise<void>;
  /** Send a magic link to the given email. */
  signInWithEmail: (
    email: string,
  ) => Promise<{ ok: boolean; expiresAt?: string }>;
  /** Finalise a magic-link login (called by callback page) */
  completeEmailAuth: (
    result: { token: string; user: { id: string; email: string } },
  ) => void;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

/** localStorage key used across the whole app for the JWT. */
const TOKEN_KEY = "steward_session";

function getStoredToken(): string | null {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem(TOKEN_KEY);
}

function setStoredToken(token: string): void {
  if (typeof localStorage !== "undefined") {
    localStorage.setItem(TOKEN_KEY, token);
  }
}

function clearStoredToken(): void {
  if (typeof localStorage !== "undefined") {
    localStorage.removeItem(TOKEN_KEY);
  }
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }): any {
  // Wagmi (wallet)
  const { address, chainId, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  // Auth state
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [email, setEmail] = useState<string | undefined>(undefined);
  const [userId, setUserId] = useState<string | undefined>(undefined);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const signingRef = useRef(false);

  // ── Session validation on mount ─────────────────────────────────────────────

  useEffect(() => {
    validateSession();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // When wallet disconnects, clear auth state (only if wallet was the auth method)
  useEffect(() => {
    if (!isConnected && isAuthenticated && tenant) {
      clearSession();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isConnected]);

  async function validateSession() {
    const token = getStoredToken();
    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/auth/session`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = (await res.json()) as {
        authenticated: boolean;
        address?: string;
        tenantId?: string;
        tenantName?: string;
        apiKey?: string;
        userId?: string;
        email?: string;
      };

      if (data.authenticated) {
        setIsAuthenticated(true);

        if (data.address && data.tenantId) {
          // SIWE session
          const tenantInfo: TenantInfo = {
            tenantId: data.tenantId,
            tenantName: data.tenantName || data.tenantId,
            apiKey: data.apiKey,
          };
          setTenant(tenantInfo);
          if (tenantInfo.apiKey) {
            setCredentials(tenantInfo.tenantId, tenantInfo.apiKey);
          }
        } else if (data.userId) {
          // User session (passkey / email)
          setAuthToken(token);
          setUserId(data.userId);
          setEmail(data.email);
        }
      } else {
        clearStoredToken();
      }
    } catch {
      // Session check failed — don't clear (might be a network hiccup)
    } finally {
      setIsLoading(false);
    }
  }

  function clearSession() {
    clearStoredToken();
    setIsAuthenticated(false);
    setTenant(null);
    setEmail(undefined);
    setUserId(undefined);
  }

  // ── SIWE (wallet) sign-in ───────────────────────────────────────────────────
  // Raw fetch flow — kept because SiweMessage needs chainId context and the
  // dashboard also consumes tenant details from the verify response.

  const signIn = useCallback(async () => {
    if (!address || !chainId || signingRef.current) return;
    signingRef.current = true;

    try {
      const nonceRes = await fetch(`${API_URL}/auth/nonce`);
      const { nonce } = (await nonceRes.json()) as { nonce: string };

      const message = new SiweMessage({
        domain: window.location.host,
        address,
        statement: "Sign in to Steward",
        uri: window.location.origin,
        version: "1",
        chainId,
        nonce,
      });

      const messageString = message.prepareMessage();
      const signature = await signMessageAsync({ message: messageString });

      const verifyRes = await fetch(`${API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: messageString, signature }),
      });

      const verifyData = (await verifyRes.json()) as {
        token?: string;
        error?: string;
        tenant?: { id: string; name: string; apiKey?: string };
      };

      if (verifyData.token) {
        setStoredToken(verifyData.token);
        setIsAuthenticated(true);

        if (verifyData.tenant) {
          const tenantInfo: TenantInfo = {
            tenantId: verifyData.tenant.id,
            tenantName: verifyData.tenant.name,
            apiKey: verifyData.tenant.apiKey,
          };
          setTenant(tenantInfo);
          if (tenantInfo.apiKey) {
            setCredentials(tenantInfo.tenantId, tenantInfo.apiKey);
          }
        }
      } else {
        throw new Error(verifyData.error || "Verification failed");
      }
    } catch (err) {
      console.error("SIWE sign-in failed:", err);
      throw err;
    } finally {
      signingRef.current = false;
    }
  }, [address, chainId, signMessageAsync]);

  // ── Passkey sign-in ─────────────────────────────────────────────────────────

  const handlePasskeySignIn = useCallback(
    async (inputEmail: string) => {
      const result = await signInWithPasskey(inputEmail);
      setStoredToken(result.token);
      setAuthToken(result.token);
      setIsAuthenticated(true);
      setUserId(result.user.id);
      setEmail(result.user.email);
    },
    [],
  );

  // ── Email magic link ────────────────────────────────────────────────────────

  const handleEmailSignIn = useCallback(
    async (inputEmail: string): Promise<{ ok: boolean; expiresAt?: string }> => {
      return sendMagicLink(inputEmail);
    },
    [],
  );

  /**
   * Called by the /auth/callback/email page after the magic link is verified.
   * Stores the JWT and updates auth state without a full page reload.
   */
  const completeEmailAuth = useCallback(
    (result: { token: string; user: { id: string; email: string } }) => {
      setStoredToken(result.token);
      setAuthToken(result.token);
      setIsAuthenticated(true);
      setUserId(result.user.id);
      setEmail(result.user.email);
    },
    [],
  );

  // ── Sign out ────────────────────────────────────────────────────────────────

  const signOut = useCallback(async () => {
    const token = getStoredToken();
    if (token) {
      try {
        await fetch(`${API_URL}/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Best-effort
      }
    }
    clearSession();
    // Only disconnect wallet if it was the auth method
    if (tenant) disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [disconnect, tenant]);

  // ── Context value ───────────────────────────────────────────────────────────

  return createElement(
    AuthContext.Provider,
    {
      value: {
        address,
        email,
        userId,
        tenant,
        isAuthenticated,
        isLoading,
        signIn,
        signInWithPasskey: handlePasskeySignIn,
        signInWithEmail: handleEmailSignIn,
        completeEmailAuth,
        signOut,
      },
    },
    children,
  );
}

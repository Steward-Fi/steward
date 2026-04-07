"use client";

/**
 * auth-provider.tsx
 *
 * Uses @stwd/sdk's StewardAuth class for passkey and email magic-link auth.
 * SIWE (wallet) sign-in still uses raw fetch + wagmi because it needs chainId
 * in the SiweMessage, which the SDK's built-in signInWithSIWE doesn't carry.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useAccount, useDisconnect, useSignMessage } from "wagmi";
import { SiweMessage } from "siwe";
import { StewardAuth } from "@stwd/sdk";

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
  /**
   * Passkey sign-in/registration.
   * Delegates to StewardAuth.signInWithPasskey from @stwd/sdk.
   */
  signInWithPasskey: (email: string) => Promise<void>;
  /**
   * Send a magic link to the given email.
   * Delegates to StewardAuth.signInWithEmail from @stwd/sdk.
   */
  signInWithEmail: (
    email: string,
  ) => Promise<{ ok: boolean; expiresAt?: string }>;
  /** Finalise a magic-link login (called by callback page) */
  completeEmailAuth: (result: { token: string; user: { id: string; email: string } }) => void;
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

/**
 * Bridge StewardAuth's internal storage key to our existing TOKEN_KEY.
 * This keeps session continuity if the user already had a stored token.
 */
function makeSdkStorage() {
  return {
    getItem(_key: string): string | null {
      if (typeof localStorage === "undefined") return null;
      return localStorage.getItem(TOKEN_KEY);
    },
    setItem(_key: string, value: string): void {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(TOKEN_KEY, value);
      }
    },
    removeItem(_key: string): void {
      if (typeof localStorage !== "undefined") {
        localStorage.removeItem(TOKEN_KEY);
      }
    },
  };
}

// ─── Provider ─────────────────────────────────────────────────────────────────

export function AuthProvider({ children }: { children: ReactNode }) {
  // Wagmi (wallet)
  const { address, chainId, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  /**
   * StewardAuth SDK instance.
   * Handles passkey (WebAuthn) and email magic-link flows end-to-end.
   */
  const sdkAuth = useMemo(
    () => new StewardAuth({ baseUrl: API_URL, storage: makeSdkStorage() }),
    [],
  );

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
    const token = sdkAuth.getToken();
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
        sdkAuth.signOut(); // clears localStorage via our bridge
      }
    } catch {
      // Session check failed — don't clear (might be a network hiccup)
    } finally {
      setIsLoading(false);
    }
  }

  function clearSession() {
    sdkAuth.signOut(); // removes TOKEN_KEY via our bridge
    setIsAuthenticated(false);
    setTenant(null);
    setEmail(undefined);
    setUserId(undefined);
  }

  // ── SIWE (wallet) sign-in ───────────────────────────────────────────────────
  // Raw fetch flow — kept because SiweMessage needs chainId context, which the
  // SDK's built-in signInWithSIWE doesn't carry. Tenant data also comes in the
  // SIWE verify response and is dashboard-specific.

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
        localStorage.setItem(TOKEN_KEY, verifyData.token);
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

  // ── Passkey sign-in — via StewardAuth SDK ───────────────────────────────────

  const handlePasskeySignIn = useCallback(
    async (inputEmail: string) => {
      const result = await sdkAuth.signInWithPasskey(inputEmail);
      // TOKEN_KEY already written by our storage bridge inside sdkAuth
      setAuthToken(result.token);
      setIsAuthenticated(true);
      setUserId(result.user.id);
      setEmail(result.user.email);
    },
    [sdkAuth],
  );

  // ── Email magic link — via StewardAuth SDK ──────────────────────────────────

  const handleEmailSignIn = useCallback(
    async (inputEmail: string): Promise<{ ok: boolean; expiresAt?: string }> => {
      const res = await sdkAuth.signInWithEmail(inputEmail);
      return { ok: res.ok, expiresAt: res.expiresAt };
    },
    [sdkAuth],
  );

  /**
   * Called by the /auth/callback/email page after the magic link is verified.
   * Stores the JWT and updates auth state without a full page reload.
   */
  const completeEmailAuth = useCallback(
    (result: { token: string; user: { id: string; email: string } }) => {
      localStorage.setItem(TOKEN_KEY, result.token);
      setAuthToken(result.token);
      setIsAuthenticated(true);
      setUserId(result.user.id);
      setEmail(result.user.email);
    },
    [],
  );

  // ── Sign out ────────────────────────────────────────────────────────────────

  const signOut = useCallback(async () => {
    const token = sdkAuth.getToken();
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
  }, [sdkAuth, disconnect, tenant]);

  // ── Context value ───────────────────────────────────────────────────────────

  return (
    <AuthContext
      value={{
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
      }}
    >
      {children}
    </AuthContext>
  );
}

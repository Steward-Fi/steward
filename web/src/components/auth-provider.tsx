"use client";

import {
  createContext,
  useContext,
  useEffect,
  useState,
  useCallback,
  useRef,
  type ReactNode,
} from "react";
import { useAccount, useSignMessage, useDisconnect } from "wagmi";
import { SiweMessage } from "siwe";
import { setCredentials } from "@/lib/api";

const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

interface TenantInfo {
  tenantId: string;
  tenantName: string;
  apiKey?: string;
}

interface AuthContextType {
  address: string | undefined;
  tenant: TenantInfo | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

const TOKEN_KEY = "steward_session";

export function AuthProvider({ children }: { children: ReactNode }) {
  const { address, chainId, isConnected } = useAccount();
  const { signMessageAsync } = useSignMessage();
  const { disconnect } = useDisconnect();

  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const signingRef = useRef(false);

  // Validate existing session on mount
  useEffect(() => {
    validateSession();
  }, []);

  // When wallet disconnects, clear auth state
  useEffect(() => {
    if (!isConnected && isAuthenticated) {
      clearSession();
    }
  }, [isConnected]);

  async function validateSession() {
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      const res = await fetch(`${API_URL}/auth/session`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();

      if (data.authenticated) {
        setIsAuthenticated(true);
        if (data.address && data.tenantId) {
          const tenantInfo: TenantInfo = {
            tenantId: data.tenantId,
            tenantName: data.tenantName || data.tenantId,
            apiKey: data.apiKey,
          };
          setTenant(tenantInfo);
          if (tenantInfo.apiKey) {
            setCredentials(tenantInfo.tenantId, tenantInfo.apiKey);
          }
        }
      } else {
        localStorage.removeItem(TOKEN_KEY);
      }
    } catch {
      // Session check failed — don't clear, might be network issue
    } finally {
      setIsLoading(false);
    }
  }

  function clearSession() {
    localStorage.removeItem(TOKEN_KEY);
    setIsAuthenticated(false);
    setTenant(null);
  }

  const signIn = useCallback(async () => {
    if (!address || !chainId || signingRef.current) return;
    signingRef.current = true;

    try {
      // 1. Get nonce
      const nonceRes = await fetch(`${API_URL}/auth/nonce`);
      const { nonce } = await nonceRes.json();

      // 2. Construct SIWE message
      const message = new SiweMessage({
        domain: window.location.host,
        address: address,
        statement: "Sign in to Steward",
        uri: window.location.origin,
        version: "1",
        chainId: chainId,
        nonce: nonce,
      });

      const messageString = message.prepareMessage();

      // 3. Sign with wallet
      const signature = await signMessageAsync({ message: messageString });

      // 4. Verify with API
      const verifyRes = await fetch(`${API_URL}/auth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: messageString, signature }),
      });

      const verifyData = await verifyRes.json();

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

  const signOut = useCallback(async () => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      try {
        await fetch(`${API_URL}/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // Logout API call is best-effort
      }
    }
    clearSession();
    disconnect();
  }, [disconnect]);

  return (
    <AuthContext.Provider
      value={{
        address,
        tenant,
        isAuthenticated,
        isLoading,
        signIn,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

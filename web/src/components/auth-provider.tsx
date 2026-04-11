"use client";

/**
 * auth-provider.tsx — Compatibility shim.
 *
 * Wraps the new @stwd/react useAuth hook to provide backward-compatible
 * properties (address, tenant, email, userId, signIn, etc.) so existing
 * dashboard pages keep working without rewrites.
 */

import { useMemo, useEffect } from "react";
import { useAuth as useNewAuth } from "@stwd/react";
import { setAuthToken } from "@/lib/api";

interface TenantInfo {
  tenantId: string;
  tenantName: string;
  apiKey?: string;
}

export interface AuthContextType {
  address: string | undefined;
  email: string | undefined;
  userId: string | undefined;
  tenant: TenantInfo | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  signIn: () => Promise<void>;
  signInWithPasskey: (email: string) => Promise<void>;
  signInWithEmail: (email: string) => Promise<{ ok: boolean; expiresAt?: string }>;
  completeEmailAuth: (result: { token: string; user: { id: string; email: string } }) => void;
  signOut: () => Promise<void>;
}

export function useAuth(): AuthContextType {
  const auth = useNewAuth();

  // Wire the JWT into the API client so dashboard pages can make authenticated calls
  useEffect(() => {
    const token = auth.getToken();
    if (token) {
      setAuthToken(token);
    }
  }, [auth.isAuthenticated, auth.session]);

  return useMemo(() => {
    const user = auth.user;
    const session = auth.session;

    // Build backward-compatible tenant object from session
    const tenant: TenantInfo | null =
      auth.activeTenantId
        ? {
            tenantId: auth.activeTenantId,
            tenantName: auth.activeTenantId,
            apiKey: undefined,
          }
        : null;

    return {
      address: (user as any)?.address ?? undefined,
      email: user?.email ?? undefined,
      userId: user?.id ?? undefined,
      tenant,
      isAuthenticated: auth.isAuthenticated,
      isLoading: auth.isLoading,
      signIn: async () => {
        // No-op for backward compat; SIWE is handled by StewardLogin now
      },
      signInWithPasskey: async (email: string) => {
        await auth.signInWithPasskey(email);
      },
      signInWithEmail: async (email: string) => {
        const result = await auth.signInWithEmail(email);
        return { ok: true, expiresAt: (result as any).expiresAt };
      },
      completeEmailAuth: () => {
        // No-op; handled by StewardEmailCallback now
      },
      signOut: async () => {
        auth.signOut();
      },
    };
  }, [auth]);
}

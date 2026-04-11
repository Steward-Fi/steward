"use client";

import { createElement, useEffect, useRef, type ReactNode } from "react";
import { StewardProvider, useAuth } from "@stwd/react";
import { steward, setAuthToken } from "@/lib/api";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

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
  }, [auth.isAuthenticated, auth.session]);

  return <>{children}</>;
}

export function Providers({ children }: { children: ReactNode }) {
  return createElement(
    StewardProvider as any,
    {
      client: steward as any,
      auth: { baseUrl: API_URL },
    },
    createElement(AuthTokenSync, null, children),
  ) as any;
}

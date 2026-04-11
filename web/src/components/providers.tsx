"use client";

import { createElement, useEffect, type ReactNode } from "react";
import { StewardProvider, useAuth } from "@stwd/react";
import { steward, setAuthToken } from "@/lib/api";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
import "@simplewebauthn/browser";

const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

/**
 * Syncs the Steward auth JWT into the API client so all dashboard
 * pages can make authenticated API calls via Bearer token.
 */
function AuthTokenSync({ children }: { children: ReactNode }) {
  const auth = useAuth();

  useEffect(() => {
    if (auth.isAuthenticated) {
      const token = auth.getToken();
      if (token) {
        setAuthToken(token);
      }
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

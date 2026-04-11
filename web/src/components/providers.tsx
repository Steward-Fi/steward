"use client";

import { createElement, type ReactNode } from "react";
import { StewardProvider } from "@stwd/react";
import { steward } from "@/lib/api";

// Pre-import @simplewebauthn/browser so it's in the client bundle.
// The SDK dynamically imports it for passkeys, but bundlers don't always
// resolve dynamic imports to client chunks. This ensures it's available.
import "@simplewebauthn/browser";

const API_URL =
  process.env.NEXT_PUBLIC_STEWARD_API_URL || "https://api.steward.fi";

export function Providers({ children }: { children: ReactNode }) {
  return createElement(
    StewardProvider as any,
    {
      client: steward as any,
      auth: { baseUrl: API_URL },
    },
    children,
  ) as any;
}

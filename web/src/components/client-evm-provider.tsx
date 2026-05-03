"use client";

import { EVMWalletProvider } from "@stwd/react/wallet";
import type * as React from "react";
import { type ReactNode, useMemo } from "react";
import { getWagmiConfig } from "@/lib/wagmi";

/**
 * Client-only wrapper around `<EVMWalletProvider>`.
 *
 * Builds the wagmi/RainbowKit config via the lazy `getWagmiConfig()`
 * factory inside `useMemo`, so connector construction (which touches
 * `indexedDB` / `localStorage` / `window`) only runs in the browser.
 *
 * This component is only ever loaded via `next/dynamic({ ssr: false })`
 * from `providers.tsx`, never imported at module scope by SSR-evaluated
 * code.
 */
export default function ClientEVMProvider({ children }: { children: ReactNode }) {
  const config = useMemo(() => getWagmiConfig(), []);
  // EVMWalletProvider's `children` prop type is from a slightly different
  // copy of @types/react (transitively via wagmi). Cast to keep TypeScript
  // happy across both copies.
  const Provider = EVMWalletProvider as unknown as React.ComponentType<{
    config: ReturnType<typeof getWagmiConfig>;
    children: ReactNode;
  }>;
  return <Provider config={config}>{children}</Provider>;
}

"use client";

/**
 * wallet-provider.tsx — Deprecated.
 *
 * Auth and wallet context now handled by StewardProvider from @stwd/react.
 * Kept as a no-op export for any stale imports.
 */

import type { ReactNode } from "react";

export function WalletProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

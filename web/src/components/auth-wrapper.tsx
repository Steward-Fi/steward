"use client";

/**
 * auth-wrapper.tsx — Deprecated. Auth is now handled by StewardProvider.
 * Kept as a no-op for any stale imports.
 */

import { type ReactNode } from "react";

export function AuthWrapper({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

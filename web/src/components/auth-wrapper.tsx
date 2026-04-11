"use client";

// DEPRECATED: Auth is now handled by @stwd/react StewardProvider. This file kept for import compatibility.

import { type ReactNode } from "react";

export function AuthWrapper({ children }: { children: ReactNode }) {
  return <>{children}</>;
}

"use client";

import { AuthProvider } from "@/components/auth-provider";
import type { ReactNode } from "react";

export function AuthWrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>;
}

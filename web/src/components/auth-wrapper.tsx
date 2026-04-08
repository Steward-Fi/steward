"use client";

import { createElement, type ReactNode } from "react";
import { AuthProvider } from "@/components/auth-provider";

export function AuthWrapper({ children }: { children: ReactNode }) {
  return createElement(AuthProvider, null, children) as any;
}

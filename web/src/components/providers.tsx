"use client";

import { createElement, type ReactNode } from "react";
import { StewardProvider } from "@stwd/react";
import { steward } from "@/lib/api";

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

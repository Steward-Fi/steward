"use client";

import { createElement, type ReactNode } from "react";
import dynamic from "next/dynamic";

const WalletProvider = dynamic(
  () =>
    import("@/components/wallet-provider").then((m) => ({
      default: m.WalletProvider,
    })),
  { ssr: false }
);

export function Providers({ children }: { children: ReactNode }) {
  return createElement(WalletProvider as any, null, children as any) as any;
}

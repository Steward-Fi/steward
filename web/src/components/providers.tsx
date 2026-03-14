"use client";

import dynamic from "next/dynamic";
import type { ReactNode } from "react";

const WalletProvider = dynamic(
  () =>
    import("@/components/wallet-provider").then((m) => ({
      default: m.WalletProvider,
    })),
  { ssr: false }
);

export function Providers({ children }: { children: ReactNode }) {
  return <WalletProvider>{children}</WalletProvider>;
}

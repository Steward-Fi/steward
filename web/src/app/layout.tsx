import type { Metadata } from "next";
import { syne, instrumentSans } from "@/lib/fonts";
import "./globals.css";

export const metadata: Metadata = {
  title: "Steward — Agent Wallet Infrastructure",
  description:
    "Managed wallets for AI agents with policy enforcement, multi-tenant isolation, and webhook-driven approvals. Self-hosted.",
  openGraph: {
    title: "Steward — Agent Wallet Infrastructure",
    description: "Managed wallets for AI agents. Policy enforcement. Self-hosted.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${syne.variable} ${instrumentSans.variable}`}
    >
      <body className="noise-overlay">{children}</body>
    </html>
  );
}

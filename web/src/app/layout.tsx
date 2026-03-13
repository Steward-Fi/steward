import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Steward — Agent Wallet Infrastructure",
  description: "Give your agents wallets. Keep the keys safe. Let users set the rules. Open source policy-enforced signing for AI agents.",
  openGraph: {
    title: "Steward — Agent Wallet Infrastructure",
    description: "Policy-enforced wallet signing for AI agents. Open source, self-hostable, designed to embed.",
    url: "https://steward.fi",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Steward — Agent Wallet Infrastructure",
    description: "Policy-enforced wallet signing for AI agents.",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased font-sans">
        {children}
      </body>
    </html>
  );
}

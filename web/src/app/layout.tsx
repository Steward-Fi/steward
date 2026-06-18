import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import "@stwd/react/styles.css";
import "@rainbow-me/rainbowkit/styles.css";
import "@solana/wallet-adapter-react-ui/styles.css";
import { Providers } from "@/components/providers";

// Self-hosted fonts (checked into the repo) so the build needs no network egress.
const sans = localFont({
  src: [
    { path: "./fonts/HankenGrotesk-400.ttf", weight: "400", style: "normal" },
    { path: "./fonts/HankenGrotesk-500.ttf", weight: "500", style: "normal" },
    { path: "./fonts/HankenGrotesk-600.ttf", weight: "600", style: "normal" },
    { path: "./fonts/HankenGrotesk-700.ttf", weight: "700", style: "normal" },
    { path: "./fonts/HankenGrotesk-800.ttf", weight: "800", style: "normal" },
  ],
  variable: "--font-sans",
  display: "swap",
  fallback: ["Avenir Next", "Segoe UI", "system-ui", "sans-serif"],
});

const mono = localFont({
  src: [
    { path: "./fonts/JetBrainsMono-400.ttf", weight: "400", style: "normal" },
    { path: "./fonts/JetBrainsMono-500.ttf", weight: "500", style: "normal" },
    { path: "./fonts/JetBrainsMono-700.ttf", weight: "700", style: "normal" },
  ],
  variable: "--font-jetbrains",
  display: "swap",
  fallback: ["JetBrains Mono", "Fira Code", "monospace"],
});

export const dynamic = "force-dynamic";

const metadataBase = (() => {
  const url = process.env.NEXT_PUBLIC_STEWARD_WEB_URL ?? "https://steward.fi";
  try {
    return new URL(url);
  } catch {
    return new URL("https://steward.fi");
  }
})();

export const metadata: Metadata = {
  metadataBase,
  title: "Steward: wallets and policy for humans and agents",
  description:
    "The open, self-hostable wallet and governance rail for humans and agents. Embedded wallets, a policy engine with spend caps and kill-switch, and a proxy gateway. MIT-licensed, no per-transaction toll.",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "32x32" },
      { url: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    apple: [{ url: "/apple-touch-icon.png", sizes: "180x180", type: "image/png" }],
  },
  manifest: "/site.webmanifest",
  openGraph: {
    title: "Steward: wallets and policy for humans and agents",
    description:
      "The open, self-hostable wallet and governance rail for humans and agents. MIT-licensed, no per-transaction toll. Own your keys, policies, and data.",
    type: "website",
    images: [
      {
        url: "/logo.png",
        width: 1463,
        height: 1463,
        alt: "Steward compass star logo",
      },
    ],
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${sans.variable} ${mono.variable}`}>
      <body className="noise-overlay">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}

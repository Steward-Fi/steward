import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Steward — Agent Wallet Infrastructure",
  description: "Give your agents wallets. Keep the keys safe. Let users set the rules.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, fontFamily: "system-ui, -apple-system, sans-serif" }}>
        {children}
      </body>
    </html>
  );
}

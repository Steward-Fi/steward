import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { arbitrum, base, bsc, mainnet, polygon } from "wagmi/chains";

export const config = getDefaultConfig({
  appName: "Steward",
  projectId: process.env.NEXT_PUBLIC_WC_PROJECT_ID || "steward-dev",
  chains: [base, mainnet, polygon, arbitrum, bsc],
  ssr: true,
});

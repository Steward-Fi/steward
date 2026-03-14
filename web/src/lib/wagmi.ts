import { getDefaultConfig } from "@rainbow-me/rainbowkit";
import { base, mainnet, polygon, arbitrum, bsc } from "wagmi/chains";

export const config = getDefaultConfig({
  appName: "Steward",
  projectId: process.env.NEXT_PUBLIC_WC_PROJECT_ID || "steward-dev",
  chains: [base, mainnet, polygon, arbitrum, bsc],
  ssr: true,
});

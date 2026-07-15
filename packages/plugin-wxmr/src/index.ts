/** Opt-in wxmr.io bridge provider for Steward. */
import type { StewardPlugin } from "@stwd/shared";
import { WxmrBridgeAdapter } from "./wxmr-bridge";

export * from "./wxmr-bridge";

const rpcUrl = process.env.WXMR_SOLANA_RPC_URL ?? process.env.SOLANA_RPC_URL;

export const wxmrPlugin: StewardPlugin = {
  name: "wxmr",
  version: "0.1.0",
  adapters: [
    {
      category: "bridge",
      provider: "wxmr",
      adapter: new WxmrBridgeAdapter({ rpcUrl }),
    },
  ],
};

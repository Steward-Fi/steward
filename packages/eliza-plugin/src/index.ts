/**
 * @stwd/eliza-plugin — Steward wallet management for ElizaOS agents.
 *
 * Policy-enforced signing, balances, and approval flows.
 * Drop-in plugin: add to your character's plugins array and set STEWARD_API_URL.
 */
import type { Plugin } from "@elizaos/core";
import { StewardService } from "./services/StewardService.js";
import { signTransactionAction } from "./actions/sign-transaction.js";
import { transferAction } from "./actions/transfer.js";
import { walletStatusProvider } from "./providers/wallet-status.js";
import { balanceProvider } from "./providers/balance.js";
import { approvalRequiredEvaluator } from "./evaluators/approval.js";

export const stewardPlugin: Plugin = {
  name: "@stwd/eliza-plugin",
  description:
    "Steward wallet management — policy-enforced signing, balances, and approval flows for ElizaOS agents",

  services: [StewardService],

  actions: [signTransactionAction, transferAction],

  providers: [walletStatusProvider, balanceProvider],

  evaluators: [approvalRequiredEvaluator],
};

export default stewardPlugin;

// Re-exports for consumers
export { StewardService } from "./services/StewardService.js";
export type { StewardPluginConfig } from "./types.js";
export { signTransactionAction } from "./actions/sign-transaction.js";
export { transferAction } from "./actions/transfer.js";
export { walletStatusProvider } from "./providers/wallet-status.js";
export { balanceProvider } from "./providers/balance.js";
export { approvalRequiredEvaluator } from "./evaluators/approval.js";

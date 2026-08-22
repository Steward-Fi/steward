/**
 * @stwd/eliza-plugin - Steward wallet management for ElizaOS agents.
 *
 * Policy-enforced signing, balances, and approval flows.
 * Add the plugin to a character and explicitly configure its Steward API URL,
 * authentication credential, and agent identity.
 */
import type { Plugin } from "@elizaos/core";
import { callGovernedApiAction } from "./actions/call-governed-api.js";
import { checkSpendAction } from "./actions/check-spend.js";
import { listApprovalsAction } from "./actions/list-approvals.js";
import { providerAction } from "./actions/provider-action.js";
import { requestApprovalAction } from "./actions/request-approval.js";
import { signTransactionAction } from "./actions/sign-transaction.js";
import { submitTradeAction } from "./actions/submit-trade.js";
import { transferAction } from "./actions/transfer.js";
import { approvalRequiredEvaluator } from "./evaluators/approval.js";
import { balanceProvider } from "./providers/balance.js";
import { pendingApprovalsProvider } from "./providers/pending-approvals.js";
import { providerActionsProvider } from "./providers/provider-actions.js";
import { walletStatusProvider } from "./providers/wallet-status.js";
import { StewardService } from "./services/StewardService.js";

export const stewardPlugin: Plugin = {
  name: "@stwd/eliza-plugin",
  description:
    "Steward wallet management - policy-enforced signing, balances, and approval flows for ElizaOS agents",

  services: [StewardService],

  actions: [
    callGovernedApiAction,
    requestApprovalAction,
    signTransactionAction,
    transferAction,
    checkSpendAction,
    listApprovalsAction,
    providerAction,
    submitTradeAction,
  ],

  providers: [
    walletStatusProvider,
    balanceProvider,
    pendingApprovalsProvider,
    providerActionsProvider,
  ],

  evaluators: [approvalRequiredEvaluator],
};

export default stewardPlugin;

export { callGovernedApiAction } from "./actions/call-governed-api.js";
export { checkSpendAction } from "./actions/check-spend.js";
export { listApprovalsAction } from "./actions/list-approvals.js";
export { providerAction } from "./actions/provider-action.js";
export { requestApprovalAction } from "./actions/request-approval.js";
export { signTransactionAction } from "./actions/sign-transaction.js";
export { submitTradeAction } from "./actions/submit-trade.js";
export { transferAction } from "./actions/transfer.js";
export { approvalRequiredEvaluator } from "./evaluators/approval.js";
export { balanceProvider } from "./providers/balance.js";
export { pendingApprovalsProvider } from "./providers/pending-approvals.js";
export { providerActionsProvider } from "./providers/provider-actions.js";
export { walletStatusProvider } from "./providers/wallet-status.js";
// Re-exports for consumers
export { StewardService } from "./services/StewardService.js";
export type { StewardPluginConfig } from "./types.js";

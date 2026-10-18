/**
 * @stwd/eliza-plugin - Steward wallet management for ElizaOS agents.
 *
 * Policy-enforced signing, balances, and approval flows.
 * Add the plugin to a character and explicitly configure its Steward API URL,
 * authentication credential, and agent identity.
 *
 * Every exported action is wrapped with a sender-authorization guard (see
 * ./authz.ts): spend actions run only for the configured owner in a direct
 * message, and unknown senders can only chat.
 */
import type { Plugin } from "@elizaos/core";
import { callGovernedApiAction as rawCallGovernedApiAction } from "./actions/call-governed-api.js";
import { checkSpendAction as rawCheckSpendAction } from "./actions/check-spend.js";
import { listApprovalsAction as rawListApprovalsAction } from "./actions/list-approvals.js";
import { providerAction as rawProviderAction } from "./actions/provider-action.js";
import { requestApprovalAction as rawRequestApprovalAction } from "./actions/request-approval.js";
import { signTransactionAction as rawSignTransactionAction } from "./actions/sign-transaction.js";
import { submitTradeAction as rawSubmitTradeAction } from "./actions/submit-trade.js";
import { transferAction as rawTransferAction } from "./actions/transfer.js";
import { guardAction } from "./authz.js";
import { approvalRequiredEvaluator } from "./evaluators/approval.js";
import { balanceProvider } from "./providers/balance.js";
import { pendingApprovalsProvider } from "./providers/pending-approvals.js";
import { providerActionsProvider } from "./providers/provider-actions.js";
import { walletStatusProvider } from "./providers/wallet-status.js";
import { StewardService } from "./services/StewardService.js";

// Exported actions are always the guarded versions. Unguarded internals stay
// private to this package.
export const callGovernedApiAction = guardAction(rawCallGovernedApiAction);
export const checkSpendAction = guardAction(rawCheckSpendAction);
export const listApprovalsAction = guardAction(rawListApprovalsAction);
export const providerAction = guardAction(rawProviderAction);
export const requestApprovalAction = guardAction(rawRequestApprovalAction);
export const signTransactionAction = guardAction(rawSignTransactionAction);
export const submitTradeAction = guardAction(rawSubmitTradeAction);
export const transferAction = guardAction(rawTransferAction);

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

export {
  type ActionAuthzPolicy,
  type AuthzDecision,
  type AuthzDenyCode,
  authorizeSender,
  guardAction,
  type RiskClass,
  resolveSender,
  type SenderContext,
  type SenderRole,
  STEWARD_ACTION_POLICIES,
} from "./authz.js";
export { approvalRequiredEvaluator } from "./evaluators/approval.js";
export { balanceProvider } from "./providers/balance.js";
export { pendingApprovalsProvider } from "./providers/pending-approvals.js";
export { providerActionsProvider } from "./providers/provider-actions.js";
export { walletStatusProvider } from "./providers/wallet-status.js";
// Re-exports for consumers
export { StewardService } from "./services/StewardService.js";
export type { StewardPluginConfig } from "./types.js";

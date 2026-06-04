/**
 * Reputation-threshold policy evaluator.
 *
 * Gates transactions based on the agent's reputation score.
 * If no score is available in context, falls back to the configured fallbackAction.
 *
 * Each configurable action maps to a distinct engine outcome when the score is
 * below `minScore` (or when no score is available and `fallbackAction` applies):
 *   - `approve`          → `passed: true` (the policy does not block this tx).
 *   - `require-approval` → `passed: false` + `requiresManualApproval: true`
 *                          (the engine routes the tx to the manual-approval
 *                          queue instead of hard-rejecting it).
 *   - `block`            → `passed: false` (hard deny).
 *   - anything else      → `passed: false` (fail closed / hard deny).
 *
 * `requiresManualApproval` is an engine-internal signal (see
 * `ManualApprovalSignal` / `engine.ts`); it is structurally compatible with the
 * public `PolicyResult` shape so it never leaks into persisted/serialised
 * results, but the engine honours it for non-`auto-approve-threshold` policies.
 */

import type { PolicyResult, PolicyRule } from "@stwd/shared";
import type { ManualApprovalSignal } from "../manual-approval";

export interface ReputationThresholdConfig {
  minScore: number;
  action: "approve" | "require-approval" | "block";
  source: "internal" | "onchain" | "combined";
  fallbackAction: "approve" | "require-approval" | "block";
}

export interface ReputationThresholdContext {
  reputationScore?: number;
}

type ReputationThresholdAction = ReputationThresholdConfig["action"];

/**
 * Translate a configured action into a policy result for the case where the
 * reputation gate did NOT clear (score below minimum, or fallback applies).
 *
 * Fails closed: only the explicit `approve` and `require-approval` actions get
 * non-deny treatment; `block` and any unrecognised/missing action deny.
 */
function resultForUnmetThreshold(
  base: { policyId: string; type: PolicyRule["type"] },
  action: ReputationThresholdAction | undefined,
  reason: string,
): PolicyResult & ManualApprovalSignal {
  if (action === "approve") {
    return { ...base, passed: true, reason };
  }
  if (action === "require-approval") {
    // Not auto-approved, but not a hard deny either: route to manual review.
    return { ...base, passed: false, requiresManualApproval: true, reason };
  }
  // "block" and any unknown/missing action → hard deny (fail closed).
  return { ...base, passed: false, reason };
}

export function evaluateReputationThreshold(
  rule: PolicyRule,
  ctx: ReputationThresholdContext,
): PolicyResult & ManualApprovalSignal {
  const config = rule.config as unknown as ReputationThresholdConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  if (ctx.reputationScore === undefined || ctx.reputationScore === null) {
    // No score available, use fallback action.
    return resultForUnmetThreshold(
      base,
      config.fallbackAction,
      `No reputation score available; fallback action: ${config.fallbackAction}`,
    );
  }

  if (ctx.reputationScore >= config.minScore) {
    return {
      ...base,
      passed: true,
      reason: `Reputation score ${ctx.reputationScore} meets minimum ${config.minScore}`,
    };
  }

  return resultForUnmetThreshold(
    base,
    config.action,
    `Reputation score ${ctx.reputationScore} below minimum ${config.minScore} (action: ${config.action})`,
  );
}

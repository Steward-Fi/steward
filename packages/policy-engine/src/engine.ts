import type { PolicyResult, PolicyRule, PriceOracle, SignRequest } from "@stwd/shared";
import { type EvaluatorContext, evaluatePolicy } from "./evaluators";

export interface TransactionSimulationRequest extends SignRequest {
  kind?: "transaction";
}

export interface ProxySimulationRequest {
  kind: "proxy";
  method: string;
  url: string;
  body?: unknown;
  data?: unknown;
  value?: string;
  chainId?: number;
}

export type PolicySimulationRequest = TransactionSimulationRequest | ProxySimulationRequest;

export interface PolicyEvaluationContext {
  request: SignRequest;
  recentTxCount24h: number;
  recentTxCount1h: number;
  spentToday: bigint;
  spentThisWeek: bigint;
  /** Optional price oracle for USD-based policy evaluation */
  priceOracle?: PriceOracle;
  /** Optional reputation score for reputation-based policies */
  reputationScore?: number;
  /** Sprint 4: trading venue (for `venue-allowlist`). */
  venue?: string;
  /** Sprint 4: requested leverage multiple (for `leverage-cap`). */
  leverage?: number;
  /** Sprint 4: pre-computed USD value of the action. */
  valueUsd?: number;
}

export interface EvaluationResult {
  approved: boolean;
  results: PolicyResult[];
  requiresManualApproval: boolean;
}

function isProxyRequest(request: PolicySimulationRequest): request is ProxySimulationRequest {
  return (
    request.kind === "proxy" || ("method" in request && "url" in request && !("to" in request))
  );
}

function extractProxyValue(request: ProxySimulationRequest): string {
  if (request.value !== undefined) return String(request.value);

  const candidates = [request.body, request.data];
  for (const candidate of candidates) {
    if (candidate && typeof candidate === "object" && "value" in candidate) {
      const value = (candidate as { value?: unknown }).value;
      if (value !== undefined && value !== null) return String(value);
    }
  }

  return "0";
}

/**
 * Policy Engine - evaluates a set of policy rules against a transaction request.
 *
 * Logic:
 * - All enabled policies must pass for auto-approval
 * - If auto-approve-threshold fails but all other policies pass, tx is queued for manual approval
 * - If any hard policy (spending-limit, approved-addresses, rate-limit, time-window) fails, tx is rejected
 */
export class PolicyEngine {
  /**
   * Evaluate all policies for an agent's transaction request.
   *
   * Now async to support USD-based evaluations that require price oracle lookups.
   */
  async evaluate(policies: PolicyRule[], ctx: PolicyEvaluationContext): Promise<EvaluationResult> {
    if (policies.length === 0) {
      // No policies = everything auto-approved (dangerous but valid for testing)
      return { approved: true, results: [], requiresManualApproval: false };
    }

    const evaluatorCtx: EvaluatorContext = {
      request: ctx.request,
      recentTxCount24h: ctx.recentTxCount24h,
      recentTxCount1h: ctx.recentTxCount1h,
      spentToday: ctx.spentToday,
      spentThisWeek: ctx.spentThisWeek,
      priceOracle: ctx.priceOracle,
      reputationScore: ctx.reputationScore,
      venue: ctx.venue,
      leverage: ctx.leverage,
      valueUsd: ctx.valueUsd,
    };

    const results: PolicyResult[] = await Promise.all(
      policies.map((policy) => evaluatePolicy(policy, evaluatorCtx)),
    );

    const hardPolicies = results.filter((r) => r.type !== "auto-approve-threshold");
    const autoApproveResult = results.find((r) => r.type === "auto-approve-threshold");

    const allHardPass = hardPolicies.every((r) => r.passed);
    const autoApprovePass = autoApproveResult ? autoApproveResult.passed : true;

    if (allHardPass && autoApprovePass) {
      return { approved: true, results, requiresManualApproval: false };
    }

    if (allHardPass && !autoApprovePass) {
      // Hard policies pass but value exceeds auto-approve threshold
      // Queue for manual approval
      return { approved: false, results, requiresManualApproval: true };
    }

    // Hard policy failed - reject
    return { approved: false, results, requiresManualApproval: false };
  }

  /**
   * Evaluate policy simulation input. Transaction requests use the full policy set;
   * proxy/API-call requests only apply rate/spend style controls that are meaningful
   * without an on-chain recipient.
   */
  async simulate(
    policies: PolicyRule[],
    ctx: Omit<PolicyEvaluationContext, "request"> & { request: PolicySimulationRequest },
  ): Promise<EvaluationResult> {
    if (!isProxyRequest(ctx.request)) {
      const { kind: _kind, ...request } = ctx.request;
      return this.evaluate(policies, { ...ctx, request });
    }

    const proxyPolicies = policies.filter((policy) =>
      ["rate-limit", "spending-limit", "auto-approve-threshold"].includes(policy.type),
    );

    const syntheticRequest: SignRequest = {
      agentId: "proxy-simulation",
      tenantId: "proxy-simulation",
      to: "0x0000000000000000000000000000000000000000",
      value: extractProxyValue(ctx.request),
      data: typeof ctx.request.data === "string" ? ctx.request.data : undefined,
      chainId: ctx.request.chainId ?? 84532,
    };

    return this.evaluate(proxyPolicies, { ...ctx, request: syntheticRequest });
  }
}

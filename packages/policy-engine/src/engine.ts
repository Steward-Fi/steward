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
  /**
   * Privy-style condition set items keyed by conditionSetId. Callers load these
   * from tenant-scoped storage before evaluating policies.
   */
  conditionSets?: Record<string, string[]>;
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
 * `policy.evaluated` audit event.
 *
 * Engine emits one of these per `evaluate()` call when an audit hook is
 * attached. The shape is intentionally JSON-serialisable so callers can
 * persist it as a row in any audit log table without further mapping.
 * Contains no private keys, no SIWE signatures, no oracle internals.
 */
export interface PolicyEvaluatedEvent {
  event: "policy.evaluated";
  agentId: string;
  tenantId: string;
  venue?: string;
  leverage?: number;
  verdict: "ALLOW" | "NACK" | "NEEDS_MANUAL";
  results: PolicyResult[];
  /** Caller-provided correlation id (e.g. trade-session id, request id). */
  correlationId?: string;
  timestamp: string;
}

export type AuditHook = (event: PolicyEvaluatedEvent) => void | Promise<void>;

export interface PolicyEngineOptions {
  /**
   * Sprint 4: optional sink for `policy.evaluated` audit events. Trade-
   * sessions wires this to the proxy audit log so every evaluation is
   * traceable to its inputs and verdict. Failures inside the hook are
   * swallowed so they don't block the trade.
   */
  auditHook?: AuditHook;
}

/**
 * Policy Engine — evaluates a set of policy rules against a transaction request.
 *
 * Logic:
 * - All enabled policies must pass for auto-approval
 * - If auto-approve-threshold fails but all other policies pass, tx is queued for manual approval
 * - If any hard policy (spending-limit, approved-addresses, rate-limit, time-window) fails, tx is rejected
 */
export class PolicyEngine {
  private readonly auditHook?: AuditHook;

  constructor(options: PolicyEngineOptions = {}) {
    if (options.auditHook) this.auditHook = options.auditHook;
  }

  /**
   * Evaluate all policies for an agent's transaction request.
   *
   * Now async to support USD-based evaluations that require price oracle lookups.
   */
  async evaluate(
    policies: PolicyRule[],
    ctx: PolicyEvaluationContext & { correlationId?: string },
  ): Promise<EvaluationResult> {
    if (policies.length === 0) {
      return { approved: false, results: [], requiresManualApproval: false };
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
      conditionSets: ctx.conditionSets,
    };

    const results: PolicyResult[] = await Promise.all(
      policies.map((policy) => evaluatePolicy(policy, evaluatorCtx)),
    );

    const hardPolicies = results.filter((r) => r.type !== "auto-approve-threshold");
    const autoApproveResults = results.filter((r) => r.type === "auto-approve-threshold");

    const allHardPass = hardPolicies.every((r) => r.passed);
    const autoApprovePass =
      autoApproveResults.length === 0 || autoApproveResults.every((r) => r.passed);

    let evaluationResult: EvaluationResult;
    if (allHardPass && autoApprovePass) {
      evaluationResult = { approved: true, results, requiresManualApproval: false };
    } else if (allHardPass && !autoApprovePass) {
      // Hard policies pass but value exceeds auto-approve threshold
      // Queue for manual approval
      evaluationResult = { approved: false, results, requiresManualApproval: true };
    } else {
      // Hard policy failed - reject
      evaluationResult = { approved: false, results, requiresManualApproval: false };
    }

    await this.emitAuditEvent(ctx, results, evaluationResult);
    return evaluationResult;
  }

  private async emitAuditEvent(
    ctx: PolicyEvaluationContext & { correlationId?: string },
    results: PolicyResult[],
    evaluation: EvaluationResult,
  ): Promise<void> {
    if (!this.auditHook) return;
    const verdict: PolicyEvaluatedEvent["verdict"] = evaluation.approved
      ? "ALLOW"
      : evaluation.requiresManualApproval
        ? "NEEDS_MANUAL"
        : "NACK";
    const event: PolicyEvaluatedEvent = {
      event: "policy.evaluated",
      agentId: ctx.request.agentId,
      tenantId: ctx.request.tenantId,
      ...(ctx.venue !== undefined ? { venue: ctx.venue } : {}),
      ...(ctx.leverage !== undefined ? { leverage: ctx.leverage } : {}),
      verdict,
      results,
      ...(ctx.correlationId !== undefined ? { correlationId: ctx.correlationId } : {}),
      timestamp: new Date().toISOString(),
    };
    try {
      await this.auditHook(event);
    } catch {
      // Audit failures must never block a trade. The engine swallows.
    }
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

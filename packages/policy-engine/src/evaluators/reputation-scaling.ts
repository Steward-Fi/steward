/**
 * Reputation-scaling policy evaluator.
 *
 * Dynamically computes a per-transaction spending limit based on the
 * agent's reputation score. Higher reputation = higher limit.
 */

import type { PolicyResult, PolicyRule } from "@stwd/shared";

export interface ReputationScalingConfig {
  /** Base per-tx limit in wei (score = 0) */
  baseMaxPerTx: string;
  /** Maximum per-tx limit in wei (score = 100) */
  maxMaxPerTx: string;
  /** Interpolation curve */
  curve: "linear" | "logarithmic";
}

export interface ReputationScalingContext {
  reputationScore?: number;
  txValue: bigint;
}

/**
 * Compute the effective limit for a given reputation score and config.
 *
 * Total on the score: a non-finite score (NaN/±Infinity from a corrupt
 * reputation feed) is treated as 0 — the lowest limit — rather than throwing
 * inside `BigInt(NaN)` (SEC-105).
 */
export function computeScaledLimit(config: ReputationScalingConfig, score: number): bigint {
  const base = BigInt(config.baseMaxPerTx);
  const max = BigInt(config.maxMaxPerTx);
  const finiteScore = Number.isFinite(score) ? score : 0;
  const clampedScore = Math.max(0, Math.min(finiteScore, 100));

  if (config.curve === "logarithmic") {
    // ln(1 + score) / ln(101) gives 0..1 with diminishing returns
    const ratio = Math.log(1 + clampedScore) / Math.log(101);
    // Use fixed-point multiplication: multiply range by ratio * 10000 then divide
    const ratioFixed = BigInt(Math.round(ratio * 10000));
    return base + ((max - base) * ratioFixed) / 10000n;
  }

  // Linear: base + (max - base) * (score / 100)
  const range = max - base;
  // Scores are allowed to be fractional. Convert through the same fixed-point
  // representation as the logarithmic curve instead of BigInt(score), which
  // throws for ordinary values such as 72.5 and turns policy evaluation into a
  // 500 rather than a deterministic decision.
  const scoreFixed = BigInt(Math.round(clampedScore * 10_000));
  return base + (range * scoreFixed) / 1_000_000n;
}

export function evaluateReputationScaling(
  rule: PolicyRule,
  ctx: ReputationScalingContext,
): PolicyResult {
  const config = rule.config as unknown as ReputationScalingConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  // Fail closed with a structured deny on malformed config instead of throwing
  // inside `BigInt(...)` (SEC-105) — consistent with the other defensive
  // evaluators.
  const isUint256 = (value: unknown): value is string => {
    if (typeof value !== "string" || !/^\d+$/.test(value)) return false;
    const normalized = value.replace(/^0+/, "") || "0";
    const max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    return (
      normalized.length < max.length || (normalized.length === max.length && normalized <= max)
    );
  };
  if (
    !config ||
    !isUint256(config.baseMaxPerTx) ||
    !isUint256(config.maxMaxPerTx) ||
    BigInt(config.maxMaxPerTx) < BigInt(config.baseMaxPerTx) ||
    (config.curve !== "linear" && config.curve !== "logarithmic")
  ) {
    return {
      ...base,
      passed: false,
      reason: "Reputation-scaling config requires ordered uint256 wei limits and a supported curve",
    };
  }

  // Default to score 0 (lowest limit) when no score available
  const score = ctx.reputationScore ?? 0;
  const limit = computeScaledLimit(config, score);

  if (ctx.txValue <= limit) {
    return {
      ...base,
      passed: true,
      reason: `Transaction value ${ctx.txValue} within reputation-scaled limit ${limit} (score: ${score})`,
    };
  }

  return {
    ...base,
    passed: false,
    reason: `Transaction value ${ctx.txValue} exceeds reputation-scaled limit ${limit} (score: ${score})`,
  };
}

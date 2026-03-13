import type {
  PolicyRule,
  PolicyResult,
  SignRequest,
  SpendingLimitConfig,
  ApprovedAddressesConfig,
  AutoApproveConfig,
  RateLimitConfig,
  TimeWindowConfig,
} from "@steward/shared";

export interface EvaluatorContext {
  request: SignRequest;
  recentTxCount24h: number;
  recentTxCount1h: number;
  spentToday: bigint;
  spentThisWeek: bigint;
}

/**
 * Evaluate a single policy rule against a transaction request.
 * Returns pass/fail with reason.
 */
export function evaluatePolicy(
  rule: PolicyRule,
  ctx: EvaluatorContext
): PolicyResult {
  if (!rule.enabled) {
    return { policyId: rule.id, type: rule.type, passed: true, reason: "Policy disabled" };
  }

  switch (rule.type) {
    case "spending-limit":
      return evaluateSpendingLimit(rule, ctx);
    case "approved-addresses":
      return evaluateApprovedAddresses(rule, ctx);
    case "auto-approve-threshold":
      return evaluateAutoApprove(rule, ctx);
    case "rate-limit":
      return evaluateRateLimit(rule, ctx);
    case "time-window":
      return evaluateTimeWindow(rule, ctx);
    default:
      return { policyId: rule.id, type: rule.type, passed: false, reason: `Unknown policy type: ${rule.type}` };
  }
}

function evaluateSpendingLimit(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as SpendingLimitConfig;
  const txValue = BigInt(ctx.request.value);
  const base = { policyId: rule.id, type: rule.type } as const;

  if (txValue > BigInt(config.maxPerTx)) {
    return { ...base, passed: false, reason: `Transaction value ${txValue} exceeds per-tx limit ${config.maxPerTx}` };
  }

  if (ctx.spentToday + txValue > BigInt(config.maxPerDay)) {
    return { ...base, passed: false, reason: `Would exceed daily spending limit (${config.maxPerDay})` };
  }

  if (ctx.spentThisWeek + txValue > BigInt(config.maxPerWeek)) {
    return { ...base, passed: false, reason: `Would exceed weekly spending limit (${config.maxPerWeek})` };
  }

  return { ...base, passed: true };
}

function evaluateApprovedAddresses(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as ApprovedAddressesConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const target = ctx.request.to.toLowerCase();
  const listed = config.addresses.map((a) => a.toLowerCase());

  if (config.mode === "whitelist") {
    if (!listed.includes(target)) {
      return { ...base, passed: false, reason: `Address ${ctx.request.to} not in whitelist` };
    }
  } else {
    if (listed.includes(target)) {
      return { ...base, passed: false, reason: `Address ${ctx.request.to} is blacklisted` };
    }
  }

  return { ...base, passed: true };
}

function evaluateAutoApprove(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as AutoApproveConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const txValue = BigInt(ctx.request.value);

  if (txValue <= BigInt(config.threshold)) {
    return { ...base, passed: true, reason: "Below auto-approve threshold" };
  }

  return { ...base, passed: false, reason: `Value ${txValue} exceeds auto-approve threshold ${config.threshold}` };
}

function evaluateRateLimit(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as RateLimitConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  if (ctx.recentTxCount1h >= config.maxTxPerHour) {
    return { ...base, passed: false, reason: `Hourly tx limit reached (${config.maxTxPerHour})` };
  }

  if (ctx.recentTxCount24h >= config.maxTxPerDay) {
    return { ...base, passed: false, reason: `Daily tx limit reached (${config.maxTxPerDay})` };
  }

  return { ...base, passed: true };
}

function evaluateTimeWindow(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as TimeWindowConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const now = new Date();
  const hour = now.getUTCHours();
  const day = now.getUTCDay();

  if (config.allowedDays.length > 0 && !config.allowedDays.includes(day)) {
    return { ...base, passed: false, reason: `Transactions not allowed on day ${day}` };
  }

  if (config.allowedHours.length > 0) {
    const inWindow = config.allowedHours.some((w) => hour >= w.start && hour < w.end);
    if (!inWindow) {
      return { ...base, passed: false, reason: `Current hour ${hour} UTC not in allowed windows` };
    }
  }

  return { ...base, passed: true };
}

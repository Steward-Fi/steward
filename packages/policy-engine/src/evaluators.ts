import {
  type AllowedChainsConfig,
  type ApprovedAddressesConfig,
  type AutoApproveConfig,
  type ConditionSetConfig,
  type ContractAllowlistConfig,
  type PolicyResult,
  type PolicyRule,
  type PriceOracle,
  type RateLimitConfig,
  type SignRequest,
  type SpendingLimitConfig,
  type TimeWindowConfig,
  toCaip2,
} from "@stwd/shared";
import { evaluateLeverageCap } from "./evaluators/leverage-cap";
import { evaluateReputationScaling } from "./evaluators/reputation-scaling";
import { evaluateReputationThreshold } from "./evaluators/reputation-threshold";
import { evaluateVenueAllowlist } from "./evaluators/venue-allowlist";

const MAX_UINT256_DECIMAL =
  "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const MAX_UINT256_DECIMAL_DIGITS = 78;

export interface EvaluatorContext {
  request: SignRequest;
  recentTxCount24h: number;
  recentTxCount1h: number;
  spentToday: bigint;
  spentThisWeek: bigint;
  /** Optional price oracle for USD-based policy evaluation */
  priceOracle?: PriceOracle;
  /** Optional reputation score for reputation-based policies */
  reputationScore?: number;
  /**
   * Sprint 4: trading venue the request is destined for. Required by the
   * `venue-allowlist` evaluator. Trade-sessions sets this from the venue
   * adapter dispatch step; non-trade signing requests leave it undefined.
   */
  venue?: string;
  /**
   * Sprint 4: requested leverage multiple (e.g. 2 = 2x). Required by the
   * `leverage-cap` evaluator. Undefined for non-leveraged trades and for
   * spot transfers.
   */
  leverage?: number;
  /**
   * Optional pre-computed USD value of the action. Trade-sessions can
   * populate this so evaluators don't all re-quote the oracle.
   */
  valueUsd?: number;
  conditionSets?: Record<string, string[]>;
}

function parseUint256Decimal(value: unknown): bigint | null {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  const normalized = value.replace(/^0+/, "") || "0";
  if (normalized.length > MAX_UINT256_DECIMAL_DIGITS) return null;
  if (normalized.length === MAX_UINT256_DECIMAL_DIGITS && normalized > MAX_UINT256_DECIMAL) {
    return null;
  }
  return BigInt(normalized);
}

/**
 * Evaluate a single policy rule against a transaction request.
 * Returns pass/fail with reason.
 *
 * Now async to support USD-based evaluations that need price lookups.
 */
export async function evaluatePolicy(
  rule: PolicyRule,
  ctx: EvaluatorContext,
): Promise<PolicyResult> {
  if (!rule.enabled) {
    return {
      policyId: rule.id,
      type: rule.type,
      passed: true,
      reason: "Policy disabled",
    };
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
    case "allowed-chains":
      return evaluateAllowedChains(rule, ctx);
    case "condition-set":
      return evaluateConditionSet(rule, ctx);
    case "contract-allowlist":
      return evaluateContractAllowlist(rule, ctx);
    case "reputation-threshold":
      return evaluateReputationThreshold(rule, {
        reputationScore: ctx.reputationScore,
      });
    case "reputation-scaling": {
      const txValue = parseUint256Decimal(ctx.request.value);
      if (txValue === null) {
        return {
          policyId: rule.id,
          type: rule.type,
          passed: false,
          reason: "Transaction value must be a uint256 wei string",
        };
      }
      return evaluateReputationScaling(rule, {
        reputationScore: ctx.reputationScore,
        txValue,
      });
    }
    case "venue-allowlist":
      return evaluateVenueAllowlist(rule, { venue: ctx.venue });
    case "leverage-cap":
      return evaluateLeverageCap(rule, { leverage: ctx.leverage });
    default:
      return {
        policyId: rule.id,
        type: rule.type,
        passed: false,
        reason: `Unknown policy type: ${rule.type}`,
      };
  }
}

/**
 * Normalize spending-limit config to the canonical format (maxPerTx/maxPerDay/maxPerWeek).
 * Accepts both the canonical format and the simplified maxAmount/period format.
 */
function normalizeSpendingLimitConfig(config: Record<string, unknown>): SpendingLimitConfig {
  // If already in canonical format (has any of the standard fields), fill in missing with MAX_UINT
  if (config.maxPerTx !== undefined || config.maxPerTxUsd !== undefined) {
    return {
      maxPerTx: config.maxPerTx !== undefined ? String(config.maxPerTx) : MAX_UINT256_DECIMAL,
      maxPerDay: config.maxPerDay !== undefined ? String(config.maxPerDay) : MAX_UINT256_DECIMAL,
      maxPerWeek: config.maxPerWeek !== undefined ? String(config.maxPerWeek) : MAX_UINT256_DECIMAL,
      maxPerTxUsd: config.maxPerTxUsd as number | undefined,
      maxPerDayUsd: config.maxPerDayUsd as number | undefined,
      maxPerWeekUsd: config.maxPerWeekUsd as number | undefined,
    };
  }

  // Also check if any USD field is present
  if (config.maxPerDayUsd !== undefined || config.maxPerWeekUsd !== undefined) {
    return {
      maxPerTx: MAX_UINT256_DECIMAL,
      maxPerDay: MAX_UINT256_DECIMAL,
      maxPerWeek: MAX_UINT256_DECIMAL,
      maxPerTxUsd: config.maxPerTxUsd as number | undefined,
      maxPerDayUsd: config.maxPerDayUsd as number | undefined,
      maxPerWeekUsd: config.maxPerWeekUsd as number | undefined,
    };
  }

  // Convert from maxAmount/period format
  const maxAmount = String(config.maxAmount ?? "0");
  const period = String(config.period ?? "day").toLowerCase();

  switch (period) {
    case "tx":
    case "transaction":
      return {
        maxPerTx: maxAmount,
        maxPerDay: MAX_UINT256_DECIMAL,
        maxPerWeek: MAX_UINT256_DECIMAL,
      };
    case "day":
    case "daily":
      return {
        maxPerTx: maxAmount,
        maxPerDay: maxAmount,
        maxPerWeek: MAX_UINT256_DECIMAL,
      };
    case "week":
    case "weekly":
      return {
        maxPerTx: maxAmount,
        maxPerDay: MAX_UINT256_DECIMAL,
        maxPerWeek: maxAmount,
      };
    default:
      // Fallback: treat as per-tx limit
      return {
        maxPerTx: maxAmount,
        maxPerDay: MAX_UINT256_DECIMAL,
        maxPerWeek: MAX_UINT256_DECIMAL,
      };
  }
}

/**
 * Check if the spending limit config has any USD-based limits.
 */
function hasUsdLimits(config: SpendingLimitConfig): boolean {
  return (
    config.maxPerTxUsd !== undefined ||
    config.maxPerDayUsd !== undefined ||
    config.maxPerWeekUsd !== undefined
  );
}

async function evaluateSpendingLimit(
  rule: PolicyRule,
  ctx: EvaluatorContext,
): Promise<PolicyResult> {
  const config = normalizeSpendingLimitConfig(rule.config);
  const base = { policyId: rule.id, type: rule.type } as const;
  const txValue = parseUint256Decimal(ctx.request.value);
  if (txValue === null) {
    return {
      ...base,
      passed: false,
      reason: "Transaction value must be a uint256 wei string",
    };
  }

  // ── USD-based evaluation (preferred when available) ─────────────────────────
  if (hasUsdLimits(config)) {
    if (!ctx.priceOracle) {
      return {
        ...base,
        passed: false,
        reason: "USD spending limit cannot be evaluated because no price oracle is available",
      };
    }
    const chainId = ctx.request.chainId;
    const txUsd = await ctx.priceOracle.weiToUsd(ctx.request.value, chainId);

    if (txUsd === null) {
      return {
        ...base,
        passed: false,
        reason: `USD spending limit cannot be evaluated for chain ${chainId}`,
      };
    }

    // Per-transaction USD limit
    if (config.maxPerTxUsd !== undefined && txUsd > config.maxPerTxUsd) {
      return {
        ...base,
        passed: false,
        reason: `Transaction value $${txUsd.toFixed(2)} exceeds per-tx USD limit $${config.maxPerTxUsd}`,
      };
    }

    // Daily USD limit - convert spentToday from wei to USD
    if (config.maxPerDayUsd !== undefined) {
      const spentTodayUsd = await ctx.priceOracle.weiToUsd(ctx.spentToday.toString(), chainId);
      if (spentTodayUsd === null) {
        return {
          ...base,
          passed: false,
          reason: `Daily USD spending limit cannot be evaluated for chain ${chainId}`,
        };
      }
      if (spentTodayUsd + txUsd > config.maxPerDayUsd) {
        return {
          ...base,
          passed: false,
          reason: `Would exceed daily USD spending limit $${config.maxPerDayUsd} (spent today: $${spentTodayUsd.toFixed(2)} + this tx: $${txUsd.toFixed(2)})`,
        };
      }
    }

    // Weekly USD limit - convert spentThisWeek from wei to USD
    if (config.maxPerWeekUsd !== undefined) {
      const spentWeekUsd = await ctx.priceOracle.weiToUsd(ctx.spentThisWeek.toString(), chainId);
      if (spentWeekUsd === null) {
        return {
          ...base,
          passed: false,
          reason: `Weekly USD spending limit cannot be evaluated for chain ${chainId}`,
        };
      }
      if (spentWeekUsd + txUsd > config.maxPerWeekUsd) {
        return {
          ...base,
          passed: false,
          reason: `Would exceed weekly USD spending limit $${config.maxPerWeekUsd} (spent this week: $${spentWeekUsd.toFixed(2)} + this tx: $${txUsd.toFixed(2)})`,
        };
      }
    }

    return { ...base, passed: true };
  }

  // ── Wei-based evaluation (legacy / fallback) ────────────────────────────────
  // ATOMICITY CONTRACT: this evaluator is pure — it compares the caller-supplied
  // spentToday/spentThisWeek counters and reserves/commits nothing. Concurrency
  // safety for the daily/weekly caps is the CALLER's responsibility: the spend
  // counters must be read and the resulting spend written inside one per-agent
  // serialization window. In the API that is `withAgentSpendLock` →
  // `pg_advisory_xact_lock(hashtext(agentId))` wrapping getTransactionStats()
  // and the transactions-table write. Without that lock two concurrent requests
  // can read the same spentToday and both pass, double-spending the cap.
  const maxPerTx = parseUint256Decimal(config.maxPerTx);
  const maxPerDay = parseUint256Decimal(config.maxPerDay);
  const maxPerWeek = parseUint256Decimal(config.maxPerWeek);
  if (maxPerTx === null || maxPerDay === null || maxPerWeek === null) {
    return {
      ...base,
      passed: false,
      reason: "Spending limit wei values must be uint256 strings",
    };
  }

  if (txValue > maxPerTx) {
    return {
      ...base,
      passed: false,
      reason: `Transaction value ${txValue} exceeds per-tx limit ${config.maxPerTx}`,
    };
  }

  if (ctx.spentToday + txValue > maxPerDay) {
    return {
      ...base,
      passed: false,
      reason: `Would exceed daily spending limit (${config.maxPerDay})`,
    };
  }

  if (ctx.spentThisWeek + txValue > maxPerWeek) {
    return {
      ...base,
      passed: false,
      reason: `Would exceed weekly spending limit (${config.maxPerWeek})`,
    };
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
      return {
        ...base,
        passed: false,
        reason: `Address ${ctx.request.to} not in whitelist`,
      };
    }
  } else {
    if (listed.includes(target)) {
      return {
        ...base,
        passed: false,
        reason: `Address ${ctx.request.to} is blacklisted`,
      };
    }
  }

  return { ...base, passed: true };
}

async function evaluateAutoApprove(rule: PolicyRule, ctx: EvaluatorContext): Promise<PolicyResult> {
  const config = rule.config as unknown as AutoApproveConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const txValue = parseUint256Decimal(ctx.request.value);
  if (txValue === null) {
    return {
      ...base,
      passed: false,
      reason: "Transaction value must be a uint256 wei string",
    };
  }

  // ── USD-based threshold (preferred) ─────────────────────────────────────────
  if (config.thresholdUsd !== undefined) {
    if (!ctx.priceOracle) {
      return {
        ...base,
        passed: false,
        reason:
          "Auto-approve USD threshold cannot be evaluated because no price oracle is available",
      };
    }
    const chainId = ctx.request.chainId;
    const txUsd = await ctx.priceOracle.weiToUsd(ctx.request.value, chainId);

    if (txUsd === null) {
      return {
        ...base,
        passed: false,
        reason: `Auto-approve USD threshold cannot be evaluated for chain ${chainId}`,
      };
    }
    if (txUsd <= config.thresholdUsd) {
      return {
        ...base,
        passed: true,
        reason: `$${txUsd.toFixed(2)} is below auto-approve threshold $${config.thresholdUsd}`,
      };
    }
    return {
      ...base,
      passed: false,
      reason: `Value $${txUsd.toFixed(2)} exceeds auto-approve USD threshold $${config.thresholdUsd}`,
    };
  }

  // ── Wei-based threshold (legacy / fallback) ─────────────────────────────────
  if (config.threshold !== undefined) {
    const threshold = parseUint256Decimal(config.threshold);
    if (threshold === null) {
      return {
        ...base,
        passed: false,
        reason: "Auto-approve threshold must be a uint256 wei string",
      };
    }
    if (txValue <= threshold) {
      return { ...base, passed: true, reason: "Below auto-approve threshold" };
    }
    return {
      ...base,
      passed: false,
      reason: `Value ${txValue} exceeds auto-approve threshold ${config.threshold}`,
    };
  }

  // No threshold configured at all - pass (policy misconfigured but don't block)
  return { ...base, passed: true, reason: "No threshold configured" };
}

function evaluateRateLimit(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as RateLimitConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  if (ctx.recentTxCount1h >= config.maxTxPerHour) {
    return {
      ...base,
      passed: false,
      reason: `Hourly tx limit reached (${config.maxTxPerHour})`,
    };
  }

  if (ctx.recentTxCount24h >= config.maxTxPerDay) {
    return {
      ...base,
      passed: false,
      reason: `Daily tx limit reached (${config.maxTxPerDay})`,
    };
  }

  return { ...base, passed: true };
}

function evaluateTimeWindow(rule: PolicyRule, _ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as TimeWindowConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const now = new Date();
  const hour = now.getUTCHours();
  const day = now.getUTCDay();

  if (config.allowedDays.length > 0 && !config.allowedDays.includes(day)) {
    return {
      ...base,
      passed: false,
      reason: `Transactions not allowed on day ${day}`,
    };
  }

  if (config.allowedHours.length > 0) {
    const inWindow = config.allowedHours.some((w) => hour >= w.start && hour < w.end);
    if (!inWindow) {
      return {
        ...base,
        passed: false,
        reason: `Current hour ${hour} UTC not in allowed windows`,
      };
    }
  }

  return { ...base, passed: true };
}

/**
 * Allowed-chains policy: restricts transactions to a set of permitted CAIP-2 chain identifiers.
 */
function evaluateAllowedChains(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as AllowedChainsConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const chainId = ctx.request.chainId;

  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    return {
      ...base,
      passed: false,
      reason: "chainId is required for allowed-chains policy evaluation",
    };
  }

  const caip2 = toCaip2(chainId);
  if (!caip2) {
    return {
      ...base,
      passed: false,
      reason: `Chain ID ${chainId} is not a recognised chain and cannot be verified against the allowed-chains policy`,
    };
  }

  if (!config.chains.includes(caip2)) {
    return {
      ...base,
      passed: false,
      reason: `Chain ${caip2} (chainId ${chainId}) is not in the allowed chains list`,
    };
  }

  return { ...base, passed: true };
}

function extractConditionSetField(config: ConditionSetConfig, ctx: EvaluatorContext): string {
  switch (config.field ?? "ethereum_transaction.to") {
    case "to":
    case "ethereum_transaction.to":
    case "solana_system_program_instruction.Transfer.to":
      return ctx.request.to;
    case "chain_id":
    case "ethereum_transaction.chain_id":
      return String(ctx.request.chainId);
    case "value":
    case "ethereum_transaction.value":
      return ctx.request.value;
    case "data":
    case "ethereum_transaction.data":
      return ctx.request.data ?? "";
    default:
      return "";
  }
}

function normalizeConditionValue(value: string, caseSensitive: boolean | undefined): string {
  return caseSensitive ? value : value.toLowerCase();
}

function evaluateConditionSet(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as ConditionSetConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  if (!config.conditionSetId || typeof config.conditionSetId !== "string") {
    return { ...base, passed: false, reason: "conditionSetId is required" };
  }

  const values = ctx.conditionSets?.[config.conditionSetId];
  if (!values) {
    return {
      ...base,
      passed: false,
      reason: `Condition set ${config.conditionSetId} was not loaded for evaluation`,
    };
  }

  const target = normalizeConditionValue(
    extractConditionSetField(config, ctx),
    config.caseSensitive,
  );
  const listed = values.map((value) => normalizeConditionValue(value, config.caseSensitive));
  const contains = listed.includes(target);
  const operator = config.operator ?? "in_condition_set";

  if (operator === "not_in_condition_set") {
    return contains
      ? {
          ...base,
          passed: false,
          reason: `Value ${target} is present in condition set ${config.conditionSetId}`,
        }
      : { ...base, passed: true };
  }

  if (!contains) {
    return {
      ...base,
      passed: false,
      reason: `Value ${target} is not present in condition set ${config.conditionSetId}`,
    };
  }

  return { ...base, passed: true };
}

function evaluateContractAllowlist(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as ContractAllowlistConfig;
  const base = { policyId: rule.id, type: rule.type } as const;
  const data = ctx.request.data;

  if (!data || data === "0x") {
    return { ...base, passed: true, reason: "No contract calldata" };
  }

  if (!/^0x(?:[a-fA-F0-9]{2})+$/.test(data) || data.length < 10) {
    return {
      ...base,
      passed: false,
      reason: "Contract calldata must include a 4-byte function selector",
    };
  }

  const target = ctx.request.to.toLowerCase();
  const selector = data.slice(0, 10).toLowerCase();
  const contract = config.contracts?.find((entry) => entry.address.toLowerCase() === target);
  if (!contract) {
    return {
      ...base,
      passed: false,
      reason: `Contract ${ctx.request.to} is not in the contract allowlist`,
    };
  }

  const allowedSelectors = contract.selectors.map((allowed) => allowed.toLowerCase());
  if (!allowedSelectors.includes(selector)) {
    return {
      ...base,
      passed: false,
      reason: `Selector ${selector} is not allowed for contract ${ctx.request.to}`,
    };
  }

  const constraint =
    contract.constraints?.[selector] ?? contract.constraints?.[selector.toUpperCase()];
  if (constraint) {
    const constraintResult = evaluateEvmSelectorConstraint(rule, ctx, selector, data, constraint);
    if (!constraintResult.passed) return constraintResult;
  }

  return { ...base, passed: true };
}

type ContractSelectorConstraint = NonNullable<
  ContractAllowlistConfig["contracts"][number]["constraints"]
>[string];

function decodeAbiAddress(word: string): string | null {
  if (!/^[a-fA-F0-9]{64}$/.test(word)) return null;
  const prefix = word.slice(0, 24);
  if (!/^0{24}$/.test(prefix)) return null;
  return `0x${word.slice(24)}`.toLowerCase();
}

function decodeAbiUint256(word: string): bigint | null {
  if (!/^[a-fA-F0-9]{64}$/.test(word)) return null;
  return BigInt(`0x${word}`);
}

function calldataWord(data: string, index: number): string | null {
  const body = data.slice(10);
  const start = index * 64;
  const end = start + 64;
  if (body.length < end) return null;
  return body.slice(start, end);
}

function normalizeAddressList(values: string[] | undefined): string[] {
  return (values ?? []).map((value) => value.toLowerCase());
}

function checkAddressConstraint(
  base: { policyId: string; type: PolicyRule["type"] },
  label: string,
  address: string | null,
  allowlist: string[] | undefined,
  blocklist: string[] | undefined,
): PolicyResult | null {
  if (!address) {
    return {
      ...base,
      passed: false,
      reason: `Unable to decode ${label} from calldata`,
    };
  }
  const allowed = normalizeAddressList(allowlist);
  if (allowed.length > 0 && !allowed.includes(address)) {
    return {
      ...base,
      passed: false,
      reason: `${label} ${address} is not in the selector allowlist`,
    };
  }
  const blocked = normalizeAddressList(blocklist);
  if (blocked.includes(address)) {
    return {
      ...base,
      passed: false,
      reason: `${label} ${address} is in the selector blocklist`,
    };
  }
  return null;
}

function checkAmountConstraint(
  base: { policyId: string; type: PolicyRule["type"] },
  amount: bigint | null,
  maxAmount: string | undefined,
): PolicyResult | null {
  if (maxAmount === undefined) return null;
  if (amount === null) {
    return {
      ...base,
      passed: false,
      reason: "Unable to decode amount from calldata",
    };
  }
  const max = parseUint256Decimal(maxAmount);
  if (max === null) {
    return {
      ...base,
      passed: false,
      reason: "Selector maxAmount must be a uint256 decimal string",
    };
  }
  if (amount > max) {
    return {
      ...base,
      passed: false,
      reason: `Token amount ${amount} exceeds selector maxAmount ${maxAmount}`,
    };
  }
  return null;
}

function evaluateEvmSelectorConstraint(
  rule: PolicyRule,
  ctx: EvaluatorContext,
  selector: string,
  data: string,
  constraint: ContractSelectorConstraint,
): PolicyResult {
  const base = { policyId: rule.id, type: rule.type } as const;

  switch (selector) {
    case "0xa9059cbb": {
      const recipient = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const amount = decodeAbiUint256(calldataWord(data, 1) ?? "");
      return (
        checkAddressConstraint(
          base,
          "recipient",
          recipient,
          constraint.recipientAllowlist,
          constraint.recipientBlocklist,
        ) ??
        checkAmountConstraint(base, amount, constraint.maxAmount) ?? { ...base, passed: true }
      );
    }
    case "0x095ea7b3": {
      const spender = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const amount = decodeAbiUint256(calldataWord(data, 1) ?? "");
      return (
        checkAddressConstraint(
          base,
          "spender",
          spender,
          constraint.spenderAllowlist,
          constraint.spenderBlocklist,
        ) ??
        checkAmountConstraint(base, amount, constraint.maxAmount) ?? { ...base, passed: true }
      );
    }
    case "0x23b872dd": {
      const from = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const recipient = decodeAbiAddress(calldataWord(data, 1) ?? "");
      const amount = decodeAbiUint256(calldataWord(data, 2) ?? "");
      return (
        checkAddressConstraint(
          base,
          "from",
          from,
          constraint.fromAllowlist,
          constraint.fromBlocklist,
        ) ??
        checkAddressConstraint(
          base,
          "recipient",
          recipient,
          constraint.recipientAllowlist,
          constraint.recipientBlocklist,
        ) ??
        checkAmountConstraint(base, amount, constraint.maxAmount) ?? { ...base, passed: true }
      );
    }
    default:
      return { ...base, passed: true };
  }
}

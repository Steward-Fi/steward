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
  type RawSigningChainConditionConfig,
  rawSigningChainSupport,
  type SignRequest,
  type SpendingLimitConfig,
  type TimeWindowConfig,
  type TypedDataConditionConfig,
  type TypedDataDomain,
  type TypedDataField,
  type TypedDataMessageCondition,
  toCaip2,
} from "@stwd/shared";
import { type AggregationLookup, evaluateAggregation } from "./evaluators/aggregation";
import { evaluateLeverageCap } from "./evaluators/leverage-cap";
import { evaluateReputationScaling } from "./evaluators/reputation-scaling";
import { evaluateReputationThreshold } from "./evaluators/reputation-threshold";
import { evaluateVenueAllowlist } from "./evaluators/venue-allowlist";
import type { ManualApprovalSignal } from "./manual-approval";
import { evaluateRegisteredPolicy } from "./policy-rule-registry";

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
  /**
   * Authoritative rolling-aggregate lookup for `aggregation` policies. Callers
   * wire this from a server-side provider (Redis rolling counters / tx
   * history). When absent, aggregation policies fail closed (deny).
   */
  aggregations?: AggregationLookup;
  /**
   * Decoded EIP-712 typed-data payload for `typed-data` policies. Populated
   * ONLY by the typed-data signing route; absent on ordinary transaction
   * signs. A `typed-data` policy is "not applicable" (passes) when this is
   * undefined, so it cannot interfere with normal tx signing.
   */
  typedData?: {
    domain: TypedDataDomain;
    types: Record<string, TypedDataField[]>;
    primaryType: string;
    value: Record<string, unknown>;
  };
  rawSigning?: {
    chain: string;
    curve: string;
  };
  /**
   * Capability-invoke context for `capability-intent` policies. Populated ONLY
   * by the capability invoke route (W-1c); absent on ordinary signing requests,
   * so a `capability-intent` policy is "not applicable" (passes) when this is
   * undefined. Symmetry with `typedData`: capability policies cannot interfere
   * with transaction signing, and transaction policies cannot interfere with
   * capability invokes.
   */
  capability?: {
    name: string;
    args: Record<string, unknown>;
    host: string;
    path: string;
    method: string;
  };
  /**
   * Rolling count of capability INVOKES in the trailing hour (distinct from
   * `recentTxCount1h`, which counts transaction signs). Populated ONLY by the
   * capability invoke route (W-1c) alongside `capability`. When a
   * `capability-intent` rule sets `constraints.maxCallsPerHour` but this count
   * is absent, the rule FAILS CLOSED (deny) rather than borrowing the tx
   * counter, so an unwired invoke path can never silently pass a rate cap.
   */
  capabilityInvokeCount1h?: number;
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
 * Returns pass/fail with reason, plus an optional `requiresManualApproval`
 * signal (see `./manual-approval`) that the engine honours to route a
 * non-passing "hard" policy to the manual-approval queue instead of a hard
 * deny. The signal is optional, so the return value is structurally still a
 * `PolicyResult`; evaluators that never set it behave exactly as before.
 *
 * Now async to support USD-based evaluations that need price lookups.
 */
export async function evaluatePolicy(
  rule: PolicyRule,
  ctx: EvaluatorContext,
): Promise<PolicyResult & ManualApprovalSignal> {
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
    case "aggregation":
      return evaluateAggregation(rule, {
        request: ctx.request,
        aggregations: ctx.aggregations,
        priceOracle: ctx.priceOracle,
      });
    case "contract-allowlist":
      return evaluateContractAllowlist(rule, ctx);
    case "typed-data":
      return evaluateTypedData(rule, ctx);
    case "raw-signing-chain":
      return evaluateRawSigningChain(rule, ctx);
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
    default: {
      // FALLTHROUGH FOR NON-CORE RULE TYPES ONLY. Every core type is handled by a
      // `case` above; control reaches here ONLY for a rule type the core does not
      // own. Consult the plugin policy-rule registry (Phase 2b): if a plugin
      // registered an evaluator for this type, run it; otherwise preserve the
      // historical "Unknown policy type" deny. Core decisions are byte-identical
      // because no core type ever reaches this arm.
      const registered = await evaluateRegisteredPolicy(rule, ctx);
      if (registered) return registered;
      return {
        policyId: rule.id,
        type: rule.type,
        passed: false,
        reason: `Unknown policy type: ${rule.type}`,
      };
    }
  }
}

function normalizePolicyString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim().toLowerCase() : null;
}

function evaluateRawSigningChain(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const base = { policyId: rule.id, type: rule.type } as const;
  if (!ctx.rawSigning) {
    return { ...base, passed: true, reason: "Not a raw-digest signing request" };
  }
  const config = rule.config as unknown as RawSigningChainConditionConfig;
  const chain = normalizePolicyString(ctx.rawSigning.chain);
  const curve = normalizePolicyString(ctx.rawSigning.curve);
  if (!chain || !curve) {
    return { ...base, passed: false, reason: "Raw signing chain and curve are required" };
  }
  const support = rawSigningChainSupport(chain);
  const requireSupported = config.requireSupported !== false;
  if (requireSupported && (!support || !support.supported)) {
    return {
      ...base,
      passed: false,
      reason: `Raw signing chain ${chain} is not supported`,
    };
  }
  if (support && support.curve !== curve) {
    return {
      ...base,
      passed: false,
      reason: `Raw signing chain ${chain} requires ${support.curve}, not ${curve}`,
    };
  }
  const allowedChains = (config.allowedChains ?? []).map(normalizePolicyString).filter(Boolean);
  if (allowedChains.length > 0 && !allowedChains.includes(chain)) {
    return {
      ...base,
      passed: false,
      reason: `Raw signing chain ${chain} is not in the allowed list`,
    };
  }
  const blockedChains = (config.blockedChains ?? []).map(normalizePolicyString).filter(Boolean);
  if (blockedChains.includes(chain)) {
    return {
      ...base,
      passed: false,
      reason: `Raw signing chain ${chain} is blocked`,
    };
  }
  const allowedCurves = (config.allowedCurves ?? []).map(normalizePolicyString).filter(Boolean);
  if (allowedCurves.length > 0 && !allowedCurves.includes(curve)) {
    return {
      ...base,
      passed: false,
      reason: `Raw signing curve ${curve} is not in the allowed list`,
    };
  }
  return {
    ...base,
    passed: true,
    reason: `Raw signing chain ${chain} on ${curve} is allowed`,
  };
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
  const targetAddress = getApprovedAddressTarget(ctx.request);
  if (!targetAddress) {
    return {
      ...base,
      passed: false,
      reason: "No destination address found for approved-addresses policy",
    };
  }

  const target = targetAddress.toLowerCase();
  const listed = config.addresses.map((a) => a.toLowerCase());
  const mode = config.mode ?? "whitelist";

  if (mode === "whitelist") {
    if (!listed.includes(target)) {
      return {
        ...base,
        passed: false,
        reason: `Destination address ${targetAddress} not in whitelist`,
      };
    }
  } else {
    if (listed.includes(target)) {
      return {
        ...base,
        passed: false,
        reason: `Destination address ${targetAddress} is blacklisted`,
      };
    }
  }

  return { ...base, passed: true };
}

function getApprovedAddressTarget(request: SignRequest): string | undefined {
  const withdrawalRequest = request as SignRequest & {
    destination?: unknown;
    action?: { destination?: unknown };
    withdraw?: { destination?: unknown };
  };

  if (typeof withdrawalRequest.destination === "string") return withdrawalRequest.destination;
  if (typeof withdrawalRequest.action?.destination === "string") {
    return withdrawalRequest.action.destination;
  }
  if (typeof withdrawalRequest.withdraw?.destination === "string") {
    return withdrawalRequest.withdraw.destination;
  }

  return request.to;
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

function extractConditionSetField(
  config: ConditionSetConfig,
  ctx: EvaluatorContext,
): string | null {
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
      return null;
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

  const operator = config.operator ?? "in_condition_set";
  if (operator !== "in_condition_set" && operator !== "not_in_condition_set") {
    return {
      ...base,
      passed: false,
      reason: `Unsupported condition set operator: ${String(operator)}`,
    };
  }

  const extracted = extractConditionSetField(config, ctx);
  if (extracted === null) {
    return {
      ...base,
      passed: false,
      reason: `Unsupported condition set field: ${String(config.field)}`,
    };
  }

  const target = normalizeConditionValue(extracted, config.caseSensitive);
  const listed = values.map((value) => normalizeConditionValue(value, config.caseSensitive));
  const contains = listed.includes(target);

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

function checkTokenIdConstraint(
  base: { policyId: string; type: PolicyRule["type"] },
  tokenId: bigint | null,
  allowlist: string[] | undefined,
  blocklist: string[] | undefined,
): PolicyResult | null {
  const hasAllow = (allowlist?.length ?? 0) > 0;
  const hasBlock = (blocklist?.length ?? 0) > 0;
  if (!hasAllow && !hasBlock) return null;
  if (tokenId === null) {
    return { ...base, passed: false, reason: "Unable to decode tokenId from calldata" };
  }
  const id = tokenId.toString();
  if (hasAllow) {
    const allowed = (allowlist ?? []).map((value) => value.trim());
    if (!allowed.includes(id)) {
      return {
        ...base,
        passed: false,
        reason: `Token id ${id} is not in the selector tokenId allowlist`,
      };
    }
  }
  if (hasBlock) {
    const blocked = (blocklist ?? []).map((value) => value.trim());
    if (blocked.includes(id)) {
      return {
        ...base,
        passed: false,
        reason: `Token id ${id} is in the selector tokenId blocklist`,
      };
    }
  }
  return null;
}

/**
 * Decode a dynamic `uint256[]` ABI argument whose offset word sits at
 * `headWordIndex` (relative to the start of the argument data, after the
 * 4-byte selector). Returns null on any malformed/out-of-range encoding so
 * callers can fail closed. Length is bounded to avoid pathological inputs.
 */
function decodeAbiUint256Array(data: string, headWordIndex: number): bigint[] | null {
  const offsetWord = calldataWord(data, headWordIndex);
  if (!offsetWord) return null;
  const offset = decodeAbiUint256(offsetWord);
  if (offset === null || offset % 32n !== 0n) return null;
  const offsetWords = Number(offset / 32n);
  const lengthWord = calldataWord(data, offsetWords);
  if (!lengthWord) return null;
  const length = decodeAbiUint256(lengthWord);
  if (length === null || length > 1024n) return null;
  const count = Number(length);
  const out: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const word = calldataWord(data, offsetWords + 1 + i);
    if (!word) return null;
    const value = decodeAbiUint256(word);
    if (value === null) return null;
    out.push(value);
  }
  return out;
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
    // ERC721 safeTransferFrom(address from, address to, uint256 tokenId)
    case "0x42842e0e":
    // ERC721 safeTransferFrom(address from, address to, uint256 tokenId, bytes data)
    case "0xb88d4fde": {
      const from = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const recipient = decodeAbiAddress(calldataWord(data, 1) ?? "");
      const tokenId = decodeAbiUint256(calldataWord(data, 2) ?? "");
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
        checkTokenIdConstraint(
          base,
          tokenId,
          constraint.tokenIdAllowlist,
          constraint.tokenIdBlocklist,
        ) ?? { ...base, passed: true }
      );
    }
    // ERC721/ERC1155 setApprovalForAll(address operator, bool approved)
    case "0xa22cb465": {
      const operator = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const approved = decodeAbiUint256(calldataWord(data, 1) ?? "");
      // Revoking approval (approved == 0) is always safe — allow it regardless
      // of the operator allowlist so agents can always pull back access.
      if (approved !== null && approved === 0n) {
        return { ...base, passed: true };
      }
      // Granting blanket approval: treat the operator as a spender.
      return (
        checkAddressConstraint(
          base,
          "operator",
          operator,
          constraint.spenderAllowlist,
          constraint.spenderBlocklist,
        ) ?? { ...base, passed: true }
      );
    }
    // ERC1155 safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes data)
    case "0xf242432a": {
      const from = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const recipient = decodeAbiAddress(calldataWord(data, 1) ?? "");
      const tokenId = decodeAbiUint256(calldataWord(data, 2) ?? "");
      const amount = decodeAbiUint256(calldataWord(data, 3) ?? "");
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
        checkTokenIdConstraint(
          base,
          tokenId,
          constraint.tokenIdAllowlist,
          constraint.tokenIdBlocklist,
        ) ??
        checkAmountConstraint(base, amount, constraint.maxAmount) ?? { ...base, passed: true }
      );
    }
    // ERC1155 safeBatchTransferFrom(address from, address to, uint256[] ids, uint256[] amounts, bytes data)
    case "0x2eb2c2d6": {
      const from = decodeAbiAddress(calldataWord(data, 0) ?? "");
      const recipient = decodeAbiAddress(calldataWord(data, 1) ?? "");
      const addressCheck =
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
        );
      if (addressCheck) return addressCheck;

      const needTokenIds =
        (constraint.tokenIdAllowlist?.length ?? 0) > 0 ||
        (constraint.tokenIdBlocklist?.length ?? 0) > 0;
      if (needTokenIds) {
        const ids = decodeAbiUint256Array(data, 2);
        if (ids === null) {
          return {
            ...base,
            passed: false,
            reason: "Unable to decode tokenId array from batch calldata",
          };
        }
        for (const id of ids) {
          const result = checkTokenIdConstraint(
            base,
            id,
            constraint.tokenIdAllowlist,
            constraint.tokenIdBlocklist,
          );
          if (result) return result;
        }
      }

      if (constraint.maxAmount !== undefined) {
        const amounts = decodeAbiUint256Array(data, 3);
        if (amounts === null) {
          return {
            ...base,
            passed: false,
            reason: "Unable to decode amount array from batch calldata",
          };
        }
        for (const amount of amounts) {
          const result = checkAmountConstraint(base, amount, constraint.maxAmount);
          if (result) return result;
        }
      }

      return { ...base, passed: true };
    }
    default:
      return { ...base, passed: true };
  }
}

// ─── EIP-712 typed-data condition ───────────────────────────────────────────

const MAX_UINT256_BIGINT = BigInt(MAX_UINT256_DECIMAL);

/** Normalize a plain EVM address string, or null if it is not one. */
function normalizeEvmAddress(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  return /^0x[0-9a-f]{40}$/.test(trimmed) ? trimmed : null;
}

/**
 * Parse an EIP-712 uint field. Accepts a non-negative JS number/bigint, a
 * decimal string, or a `0x`-hex string. Returns null (→ fail closed) for
 * anything else or any value exceeding uint256.
 */
function parseTypedDataUint(raw: unknown): bigint | null {
  let parsed: bigint | null = null;
  if (typeof raw === "bigint") {
    parsed = raw;
  } else if (typeof raw === "number") {
    if (!Number.isInteger(raw) || raw < 0) return null;
    parsed = BigInt(raw);
  } else if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (/^0x[0-9a-fA-F]+$/.test(trimmed)) {
      parsed = BigInt(trimmed);
    } else {
      parsed = parseUint256Decimal(trimmed);
    }
  }
  if (parsed === null || parsed < 0n || parsed > MAX_UINT256_BIGINT) return null;
  return parsed;
}

/** Walk a dot-path (e.g. `"details.token"`) into the decoded message object. */
function getTypedDataField(value: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".");
  let current: unknown = value;
  for (const part of parts) {
    if (current === null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

function evaluateTypedDataMessageCondition(
  base: { policyId: string; type: PolicyRule["type"] },
  condition: TypedDataMessageCondition,
  message: Record<string, unknown>,
): PolicyResult | null {
  const raw = getTypedDataField(message, condition.field);
  const fail = (reason: string): PolicyResult => ({ ...base, passed: false, reason });

  switch (condition.operator) {
    case "address_in":
    case "address_not_in": {
      const addr = normalizeEvmAddress(raw);
      if (!addr) return fail(`Typed-data field ${condition.field} is not a valid address`);
      const list = (condition.values ?? []).map((value) => value.toLowerCase());
      const present = list.includes(addr);
      if (condition.operator === "address_in" && !present) {
        return fail(`Typed-data field ${condition.field} (${addr}) is not in the allowed list`);
      }
      if (condition.operator === "address_not_in" && present) {
        return fail(`Typed-data field ${condition.field} (${addr}) is in the blocked list`);
      }
      return null;
    }
    case "eq": {
      if (raw === undefined || raw === null) {
        return fail(`Typed-data field ${condition.field} is missing`);
      }
      if (String(raw) !== String(condition.value ?? "")) {
        return fail(`Typed-data field ${condition.field} must equal ${String(condition.value)}`);
      }
      return null;
    }
    case "in":
    case "not_in": {
      if (raw === undefined || raw === null) {
        return fail(`Typed-data field ${condition.field} is missing`);
      }
      const target = String(raw);
      const present = (condition.values ?? []).includes(target);
      if (condition.operator === "in" && !present) {
        return fail(`Typed-data field ${condition.field} (${target}) is not in the allowed list`);
      }
      if (condition.operator === "not_in" && present) {
        return fail(`Typed-data field ${condition.field} (${target}) is in the blocked list`);
      }
      return null;
    }
    case "uint_max": {
      const max = parseTypedDataUint(condition.value);
      if (max === null) {
        return fail(`Typed-data condition for ${condition.field} has an invalid uint_max bound`);
      }
      const amount = parseTypedDataUint(raw);
      if (amount === null) {
        return fail(`Typed-data field ${condition.field} is not a uint256 value`);
      }
      if (amount > max) {
        return fail(
          `Typed-data field ${condition.field} (${amount}) exceeds max ${String(condition.value)}`,
        );
      }
      return null;
    }
    default:
      return fail(
        `Unsupported typed-data message operator: ${String(
          (condition as { operator?: unknown }).operator,
        )}`,
      );
  }
}

/**
 * Evaluate a Privy-style EIP-712 `typed-data` condition. Fails closed: any
 * constraint that is configured must hold, or the signature is denied. When
 * the request is not a typed-data sign (no `ctx.typedData`) the policy is not
 * applicable and passes.
 */
function evaluateTypedData(rule: PolicyRule, ctx: EvaluatorContext): PolicyResult {
  const config = rule.config as unknown as TypedDataConditionConfig;
  const base = { policyId: rule.id, type: rule.type } as const;

  if (!ctx.typedData) {
    return { ...base, passed: true, reason: "Not a typed-data signing request" };
  }

  const { domain, primaryType, value } = ctx.typedData;
  const verifyingContract = normalizeEvmAddress(domain.verifyingContract);

  if ((config.verifyingContractAllowlist?.length ?? 0) > 0) {
    const allowed = (config.verifyingContractAllowlist ?? []).map((a) => a.toLowerCase());
    if (!verifyingContract || !allowed.includes(verifyingContract)) {
      return {
        ...base,
        passed: false,
        reason: `Typed-data domain verifyingContract ${String(
          domain.verifyingContract,
        )} is not in the allowlist`,
      };
    }
  }

  if ((config.verifyingContractBlocklist?.length ?? 0) > 0) {
    const blocked = (config.verifyingContractBlocklist ?? []).map((a) => a.toLowerCase());
    if (verifyingContract && blocked.includes(verifyingContract)) {
      return {
        ...base,
        passed: false,
        reason: `Typed-data domain verifyingContract ${String(
          domain.verifyingContract,
        )} is in the blocklist`,
      };
    }
  }

  if ((config.allowedChainIds?.length ?? 0) > 0) {
    if (
      typeof domain.chainId !== "number" ||
      !(config.allowedChainIds ?? []).includes(domain.chainId)
    ) {
      return {
        ...base,
        passed: false,
        reason: `Typed-data domain chainId ${String(domain.chainId)} is not in the allowed list`,
      };
    }
  }

  if ((config.allowedDomainNames?.length ?? 0) > 0) {
    if (
      typeof domain.name !== "string" ||
      !(config.allowedDomainNames ?? []).includes(domain.name)
    ) {
      return {
        ...base,
        passed: false,
        reason: `Typed-data domain name ${String(domain.name)} is not in the allowed list`,
      };
    }
  }

  if ((config.allowedPrimaryTypes?.length ?? 0) > 0) {
    if (!(config.allowedPrimaryTypes ?? []).includes(primaryType)) {
      return {
        ...base,
        passed: false,
        reason: `Typed-data primaryType ${primaryType} is not in the allowed list`,
      };
    }
  }

  for (const condition of config.messageConditions ?? []) {
    const result = evaluateTypedDataMessageCondition(base, condition, value);
    if (result) return result;
  }

  return { ...base, passed: true };
}

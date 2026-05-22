export interface TradePolicySession {
  venue?: string;
  allowedVenues?: readonly string[];
  leverageCap?: number;
  allowedAssets?: readonly string[];
  dailySpendUsd?: number;
  dailyCapUsd?: number;
  perOrderCapUsd?: number;
}

export interface TradeOrderPolicyInput {
  venue?: string;
  asset?: string;
  leverage?: number;
  estimatedOrderUsd?: number;
}

export interface TradeOrderEvaluation {
  allow: boolean;
  reason?: string;
}

export type TradeOrderEvaluator = (
  session: TradePolicySession,
  order: TradeOrderPolicyInput,
) => TradeOrderEvaluation;

const DEFAULT_LEVERAGE_CAP = 2;
const DEFAULT_ALLOWED_ASSETS = ["BTC", "ETH"] as const;
const DEFAULT_PER_ORDER_CAP_USD = 50;

function finiteNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

export const venueAllowlistEvaluator: TradeOrderEvaluator = (session, order) => {
  const allowed = session.allowedVenues ?? (session.venue ? [session.venue] : []);
  if (allowed.length === 0) {
    return { allow: false, reason: "venue-allowlist: no venues are allowed for this session" };
  }
  if (!order.venue) {
    return { allow: false, reason: "venue-allowlist: order venue is missing" };
  }
  if (!allowed.includes(order.venue)) {
    return {
      allow: false,
      reason: `venue-allowlist: venue ${order.venue} is not allowed for this session`,
    };
  }
  return { allow: true };
};

export const leverageCapEvaluator: TradeOrderEvaluator = (session, order) => {
  const cap = finiteNumber(session.leverageCap, DEFAULT_LEVERAGE_CAP);
  const leverage = finiteNumber(order.leverage, 1);
  if (leverage > cap) {
    return { allow: false, reason: `leverage-cap: leverage ${leverage} exceeds cap ${cap}` };
  }
  return { allow: true };
};

export const assetAllowlistEvaluator: TradeOrderEvaluator = (session, order) => {
  const allowed = session.allowedAssets ?? DEFAULT_ALLOWED_ASSETS;
  if (allowed.length === 0) {
    return { allow: false, reason: "asset-allowlist: no assets are allowed for this session" };
  }
  if (!order.asset) {
    return { allow: false, reason: "asset-allowlist: order asset is missing" };
  }
  if (!allowed.includes(order.asset)) {
    return {
      allow: false,
      reason: `asset-allowlist: asset ${order.asset} is not allowed for this session`,
    };
  }
  return { allow: true };
};

export const dailySpendCapEvaluator: TradeOrderEvaluator = (session, order) => {
  const dailyCapUsd = session.dailyCapUsd;
  if (dailyCapUsd === undefined) return { allow: true };
  const spent = finiteNumber(session.dailySpendUsd, 0);
  const estimated = finiteNumber(order.estimatedOrderUsd, 0);
  if (spent + estimated > dailyCapUsd) {
    return {
      allow: false,
      reason: `daily-spend-cap: $${spent + estimated} would exceed daily cap $${dailyCapUsd}`,
    };
  }
  return { allow: true };
};

export const perOrderCapEvaluator: TradeOrderEvaluator = (session, order) => {
  const cap = finiteNumber(session.perOrderCapUsd, DEFAULT_PER_ORDER_CAP_USD);
  const estimated = finiteNumber(order.estimatedOrderUsd, 0);
  if (estimated > cap) {
    return { allow: false, reason: `per-order-cap: order $${estimated} exceeds cap $${cap}` };
  }
  return { allow: true };
};

export const defaultTradeOrderEvaluators: readonly TradeOrderEvaluator[] = [
  venueAllowlistEvaluator,
  assetAllowlistEvaluator,
  leverageCapEvaluator,
  perOrderCapEvaluator,
  dailySpendCapEvaluator,
];

export interface EvaluationResult extends TradeOrderEvaluation {
  failedEvaluator?: string;
}

export function evaluateTradeOrder(
  session: TradePolicySession,
  order: TradeOrderPolicyInput,
  evaluators: readonly TradeOrderEvaluator[] = defaultTradeOrderEvaluators,
): EvaluationResult {
  for (const evaluator of evaluators) {
    const result = evaluator(session, order);
    if (!result.allow) {
      return {
        ...result,
        failedEvaluator: evaluator.name || "anonymous-evaluator",
      };
    }
  }
  return { allow: true };
}

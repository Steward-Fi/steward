/**
 * operator-recovery.ts — Operator fund-recovery endpoints.
 *
 * Core services are injected through `StewardAppContext`, keeping this opt-in
 * plugin decoupled from `@stwd/api` while preserving the operator authentication,
 * policy, audit, idempotency, and durable production rate-limit boundaries.
 *
 * These routes implement the core promise of Steward: a HUMAN OPERATOR must
 * ALWAYS be able to close an agent's positions and withdraw its funds, even
 * when the agent's RS256 trade token is expired or the upstream control plane
 * is down. The Hyperliquid incident proved this capability was missing.
 *
 * ── Auth (deliberate) ────────────────────────────────────────────────────────
 * These are OPERATOR endpoints, NOT agent endpoints. They are gated by
 * `operatorAuth` (installed by the plugin's register()), which accepts EITHER:
 *   - a platform key (header `X-Steward-Platform-Key`, validated by
 *     `isValidPlatformKey`), OR
 *   - a tenant-admin credential (tenant API key `X-Steward-Key` +
 *     `X-Steward-Tenant`, or a user session JWT) via `tenantAuth`.
 *
 * They MUST NOT be gated behind `requireAgentJwt`. That is exactly the broken
 * path that stranded funds when the agent token expired. A human recovering
 * funds has no valid agent JWT — that's the whole point.
 *
 * ── Signing (unchanged invariant) ──────────────────────────────────────────────
 * The raw signing key NEVER touches this route. We build the same
 * `vaultClient` shim used by POST /hyperliquid/order and hand it to the
 * `HyperliquidAdapter`; the vault decrypts in-memory, signs, and zeroes the
 * key internally. We reuse the Wave-1 adapter methods (closeAllPositions,
 * signWithdraw, submitWithdraw) — no signing is reimplemented here.
 */

import { createHash } from "node:crypto";
import {
  auditEvents,
  getDatabaseDriver,
  getDb,
  hasTenantTransactionDatabase,
  operatorTransferReservations,
  policies,
  proxyAuditLog,
  tenantContextFromAuthenticatedPrincipal,
  transactions,
  withTenantRlsTransaction,
  withTenantTransactionDatabase,
} from "@stwd/db";
import { checkRateLimit } from "@stwd/redis";
import {
  type ApiResponse,
  type AppVariables,
  type PolicyRule,
  redactedThrownDiagnostics,
} from "@stwd/shared";
import {
  HyperliquidAdapter,
  hyperliquidAssetSchema,
  isBuilderPerpSymbol,
} from "@stwd/venue-hyperliquid";
import { and, desc, eq, gte, inArray, sql } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import type { StewardAppContext } from "../context";
import { DurableIdempotencyStore } from "./idempotency";
import {
  enforceTradingRateLimit,
  MemoryTradingRateLimiter,
  type TradingRateLimitResult,
} from "./trading-rate-limit";

const closeAllSchema = z.object({
  agentId: z.string().min(1),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const withdrawSchema = z.object({
  agentId: z.string().min(1),
  amount: z.union([z.string(), z.number()]).optional(),
  destination: z.string().min(1),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const transferSchema = z
  .object({
    agentId: z.string().min(1),
    sourceDex: z.string(),
    destinationDex: z.string(),
    amountUsdc: z.union([z.string(), z.number()]),
    token: z.string().min(1).optional(),
    idempotencyKey: z.string().min(1).max(256).optional(),
  })
  .refine((v) => v.sourceDex !== v.destinationDex, "sourceDex and destinationDex must differ");

const leverageSchema = z.object({
  agentId: z.string().min(1),
  coin: hyperliquidAssetSchema,
  leverage: z.number().int().positive().max(100),
  isCross: z.boolean().optional(),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const addMarginSchema = z.object({
  agentId: z.string().min(1),
  coin: hyperliquidAssetSchema,
  amountUsdc: z.union([z.string(), z.number()]),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const approveBuilderSchema = z.object({
  agentId: z.string().min(1),
  builder: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  maxFeeRate: z
    .string()
    .regex(/^(?:0|[1-9]\d*)(?:\.\d{1,6})?%$/, "maxFeeRate must be a decimal percentage")
    .refine((value) => Number(value.slice(0, -1)) <= 0.1, "maxFeeRate cannot exceed 0.1%"),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

const usdSendSchema = z.object({
  agentId: z.string().min(1),
  destination: z.string().regex(/^0x[0-9a-fA-F]{40}$/),
  amount: z
    .string()
    .regex(/^\d+(?:\.\d+)?$/)
    .refine((v) => Number(v) > 0, "amount must be positive"),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

// ── Deposit constants (Hyperliquid on Arbitrum) ────────────────────────────────
// HL credits the SENDING address, so the deposit MUST originate from the agent's
// own venue wallet. We sign an ERC-20 transfer(bridge, amount) from that wallet.
const ARBITRUM_CHAIN_ID = 42161;
// Native USDC on Arbitrum One (6 decimals).
const ARBITRUM_USDC = "0xaf88d065e77c8cC2239327C5EDb3A432268e5831";
// Hyperliquid mainnet deposit bridge on Arbitrum.
const HYPERLIQUID_ARBITRUM_BRIDGE = "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7";
// HL enforces a 5 USDC minimum deposit. Below this, funds are lost.
const HL_MIN_DEPOSIT_USDC = 5;
// Sane upper bound: a single deposit call may not exceed this. Defends against
// a fat-finger/typo moving the whole reserve in one tx. Larger deposits must be
// split into multiple deliberate calls. (Override per-tenant later if needed.)
const HL_MAX_DEPOSIT_USDC = 2000;
// Sane upper bound for a single OPERATOR withdraw. Mirrors HL_MAX_DEPOSIT_USDC:
// defends against a fat-finger/typo (or a compromised operator client) draining
// the whole venue balance in one call. Larger withdraws must be split into
// multiple deliberate calls. (Override per-tenant later if needed.)
const HL_MAX_WITHDRAW_USDC = 2000;
const USDC_DECIMALS = 6;
const HL_MAX_WITHDRAW_BASE_UNITS = BigInt(HL_MAX_WITHDRAW_USDC) * 10n ** BigInt(USDC_DECIMALS);
const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
const USDC_AMOUNT_RE = /^\d+(?:\.(\d+))?$/;

function parseUsdcBaseUnits(amount: string | number): bigint | null {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  if (!USDC_AMOUNT_RE.test(raw)) return null;
  const [, fractional = ""] = raw.match(USDC_AMOUNT_RE) ?? [];
  if (fractional.length > USDC_DECIMALS) return null;
  const [whole, fraction = ""] = raw.split(".");
  return BigInt(whole) * 10n ** BigInt(USDC_DECIMALS) + BigInt(fraction.padEnd(USDC_DECIMALS, "0"));
}

function hasTooManyUsdcDecimals(amount: string | number): boolean {
  const raw = typeof amount === "number" ? String(amount) : amount.trim();
  const [, fractional = ""] = raw.match(USDC_AMOUNT_RE) ?? [];
  return fractional.length > USDC_DECIMALS;
}

/**
 * Encode an ERC-20 `transfer(address,uint256)` call as calldata.
 * selector (4 bytes) + padded address (32) + padded amount (32).
 */
function encodeErc20Transfer(to: string, amountBaseUnits: bigint): string {
  const addr = to.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  const amt = amountBaseUnits.toString(16).padStart(64, "0");
  return `${ERC20_TRANSFER_SELECTOR}${addr}${amt}`;
}

const depositSchema = z.object({
  agentId: z.string().min(1),
  // USDC amount as a decimal string or number (e.g. "10" or 10). Converted to
  // 6-decimal base units. Must be >= HL_MIN_DEPOSIT_USDC.
  amount: z.union([z.string(), z.number()]),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

/**
 * Read the agent's withdrawable USDC balance from the Hyperliquid
 * clearinghouseState. HL exposes a top-level `withdrawable` string. We reach
 * it via the same /info endpoint the adapter uses; if the shape is unexpected
 * we return null so the caller must supply an explicit amount.
 */
async function fetchWithdrawable(walletAddress: string): Promise<string | null> {
  try {
    const r = await fetch("https://api.hyperliquid.xyz/info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: "clearinghouseState", user: walletAddress }),
    });
    if (!r.ok) return null;
    const j = (await r.json()) as { withdrawable?: unknown };
    const w = j?.withdrawable;
    if (typeof w === "string" && w.length > 0) return w;
    if (typeof w === "number") return String(w);
    return null;
  } catch {
    return null;
  }
}

/**
 * Build the operator-recovery router, closing over the injected core context.
 * Every helper + route that used a core service (db, vault, policy engine,
 * price oracle, audit) reads it from `ctx` here instead of importing it from
 * `@stwd/api`.
 */
export function createOperatorRecoveryRoutes(
  ctx: StewardAppContext,
): Hono<{ Variables: AppVariables }> {
  const {
    db,
    vault,
    ensureAgentForTenant,
    getPolicySet,
    isValidAnyAddress,
    policyEngine,
    priceOracle,
    safeJsonParse,
    writeAuditEvent,
    verifyAuditChain,
    getRedisClient,
  } = ctx;

  const operatorRecoveryRoutes = new Hono<{ Variables: AppVariables }>();
  const isDefiniteVenueRejection = (error: unknown) =>
    error instanceof Error && error.name === "HyperliquidExchangeRejectedError";

  // ── Idempotency (mirrors trade.ts store) ─────────────────────────────────────
  // Entries are stored for BOTH successful responses and ambiguous-outcome 502s
  // (a submit that may have landed at the venue), so a retry with the same key
  // REPLAYS the recorded outcome instead of re-executing a possibly-completed
  // fund movement. SEC-043: records are Redis-backed when a client is available
  // (multi-replica dedup survives restarts); without Redis the store falls back
  // to a bounded (1_000 entries, expired-only sweep) process-local map. When
  // that map is full of live records, new claims fail closed rather than
  // evicting replay protection for an earlier fund movement.
  type OperatorIdempotencyRecord = { status: 200 | 409 | 502; body: unknown };
  type OperatorIdempotency = {
    conflict?: boolean;
    inProgress?: boolean;
    entry?: OperatorIdempotencyRecord;
    claim?: () => Promise<OperatorIdempotency>;
    store?: (response: unknown) => Promise<void>;
    storeFailure?: (errorBody: unknown) => Promise<void>;
    release?: () => Promise<void>;
  };
  const operatorIdempotencyStore = new DurableIdempotencyStore<OperatorIdempotencyRecord>({
    namespace: "trade:operator",
    getRedisClient,
  });

  function operatorIdempotency(
    check: Awaited<ReturnType<typeof operatorIdempotencyStore.check>>,
  ): OperatorIdempotency {
    if (check.inProgress) {
      return {
        entry: {
          status: 409,
          body: { ok: false, error: "Request with this idempotency key is in progress" },
        },
      };
    }
    if (check.conflict || check.record) {
      return {
        conflict: check.conflict,
        inProgress: check.inProgress,
        entry: check.record,
      };
    }
    return {
      claim: check.claim ? async () => operatorIdempotency(await check.claim!()) : undefined,
      store: check.store
        ? (response: unknown) => check.store!({ status: 200, body: { ok: true, data: response } })
        : undefined,
      storeFailure: check.store
        ? (errorBody: unknown) => check.store!({ status: 502, body: errorBody })
        : undefined,
      release: check.release,
    };
  }

  async function getOperatorIdempotency(
    scope: string,
    key: string | undefined,
    body: unknown,
  ): Promise<OperatorIdempotency> {
    const check = await operatorIdempotencyStore.check(scope, key, JSON.stringify(body));
    return operatorIdempotency(check);
  }

  function operatorIdempotencyResponse(
    c: Context<{ Variables: AppVariables }>,
    state: OperatorIdempotency,
  ): Response | undefined {
    if (state.conflict) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency key reused with a different body" },
        409,
      );
    }
    if (state.entry) {
      if (state.entry.status === 409) c.header("Retry-After", "1");
      return c.json(state.entry.body, state.entry.status);
    }
    return undefined;
  }

  async function claimOperatorIdempotency(
    state: OperatorIdempotency,
  ): Promise<OperatorIdempotency> {
    return state.claim ? state.claim() : state;
  }

  // ── Operator transfer rate limit (withdraw + usd-send) ────────────────────────
  // The per-call USDC cap bounds one call; this bounds the LOOP. A compromised
  // operator credential cannot drain an arbitrarily large balance by repeating
  // capped calls. Redis is mandatory in multi-instance production; the bounded
  // process-local fallback is reserved for development or an explicitly
  // acknowledged single-instance deployment.
  const OPERATOR_TRANSFER_RATE_WINDOW_MS = 60_000;
  const OPERATOR_TRANSFER_MAX_CALLS = 10;
  const operatorTransferRateLimit = new MemoryTradingRateLimiter();

  async function enforceOperatorTransferRateLimit(
    rail: "withdraw" | "usd-send",
    tenantId: string,
    agentId: string,
  ): Promise<TradingRateLimitResult> {
    const key = `${rail}:${tenantId}:${agentId}`;
    const redis = getRedisClient();
    return enforceTradingRateLimit({
      redisAvailable: redis !== null,
      checkRedis: () =>
        checkRateLimit(
          `ratelimit:trade:operator:${rail}:${tenantId}:${agentId}:${OPERATOR_TRANSFER_RATE_WINDOW_MS}`,
          OPERATOR_TRANSFER_RATE_WINDOW_MS,
          OPERATOR_TRANSFER_MAX_CALLS,
          redis!,
        ),
      memoryKey: key,
      windowMs: OPERATOR_TRANSFER_RATE_WINDOW_MS,
      maxRequests: OPERATOR_TRANSFER_MAX_CALLS,
      memory: operatorTransferRateLimit,
    });
  }

  /**
   * Real spend/tx counters for the operator transfer rails, mirroring the API's
   * getTransactionStats(agentId, chainId): the recent-tx counts feed rate-limit
   * rules, and the spend sums — scoped to Arbitrum so they stay in the same
   * native-wei unit the policy gate denominates `value` in — feed daily/weekly
   * spending-limit rules. These authoritative counters keep the policy gate
   * effective across every operator transfer rail.
   */
  type OperatorQueryDb = Pick<typeof db, "select">;
  async function getOperatorSpendStats(
    tenantId: string,
    agentId: string,
    queryDb: OperatorQueryDb = db,
  ): Promise<{
    recentTxCount1h: number;
    recentTxCount24h: number;
    spentToday: bigint;
    spentThisWeek: bigint;
    operatorSpentTodayBaseUnits: bigint;
    operatorSpentThisWeekBaseUnits: bigint;
    recentOperatorTransferCount1m: number;
  }> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 3600_000).toISOString();
    const oneDayAgo = new Date(now.getTime() - 86400_000).toISOString();
    const oneWeekAgo = new Date(now.getTime() - 604800_000);
    const chainFilter = sql` and ${transactions.chainId} = ${ARBITRUM_CHAIN_ID}`;

    const [stats] = await queryDb
      .select({
        recentTxCount1h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneHourAgo}::timestamptz)`,
        recentTxCount24h: sql<number>`count(*) filter (where ${transactions.createdAt} >= ${oneDayAgo}::timestamptz)`,
        spentToday: sql<string>`
          coalesce(
            sum(
              case
                when ${transactions.createdAt} >= ${oneDayAgo}::timestamptz${chainFilter} then (${transactions.value})::numeric
                else 0
              end
            ),
            0
          )::text
        `,
        spentThisWeek: sql<string>`coalesce(sum((${transactions.value})::numeric) filter (where true${chainFilter}), 0)::text`,
      })
      .from(transactions)
      .where(
        and(
          eq(transactions.agentId, agentId),
          gte(transactions.createdAt, oneWeekAgo),
          // A timed-out broadcast may already have landed. Keep it charged to
          // both rate and spend counters until reconciliation proves otherwise,
          // matching the core vault/intents accounting contract.
          sql`${transactions.status} in ('signed', 'broadcast', 'confirmed', 'outcome_unknown')`,
        ),
      );

    const [operatorStats] = await queryDb
      .select({
        recentTxCount1h: sql<number>`count(*) filter (where ${operatorTransferReservations.createdAt} >= ${oneHourAgo}::timestamptz)`,
        recentTxCount24h: sql<number>`count(*) filter (where ${operatorTransferReservations.createdAt} >= ${oneDayAgo}::timestamptz)`,
        spentToday: sql<string>`coalesce(sum((${operatorTransferReservations.amountBaseUnits})::numeric) filter (where ${operatorTransferReservations.createdAt} >= ${oneDayAgo}::timestamptz), 0)::text`,
        spentThisWeek: sql<string>`coalesce(sum((${operatorTransferReservations.amountBaseUnits})::numeric), 0)::text`,
        recentCount1m: sql<number>`count(*) filter (where ${operatorTransferReservations.createdAt} >= ${new Date(now.getTime() - OPERATOR_TRANSFER_RATE_WINDOW_MS).toISOString()}::timestamptz)`,
      })
      .from(operatorTransferReservations)
      .where(
        and(
          eq(operatorTransferReservations.tenantId, tenantId),
          eq(operatorTransferReservations.agentId, agentId),
          gte(operatorTransferReservations.createdAt, oneWeekAgo),
          sql`${operatorTransferReservations.status} in ('pending', 'final')`,
        ),
      );

    return {
      recentTxCount1h:
        Number(stats?.recentTxCount1h ?? 0) + Number(operatorStats?.recentTxCount1h ?? 0),
      recentTxCount24h:
        Number(stats?.recentTxCount24h ?? 0) + Number(operatorStats?.recentTxCount24h ?? 0),
      spentToday: BigInt(stats?.spentToday ?? "0"),
      spentThisWeek: BigInt(stats?.spentThisWeek ?? "0"),
      operatorSpentTodayBaseUnits: BigInt(operatorStats?.spentToday ?? "0"),
      operatorSpentThisWeekBaseUnits: BigInt(operatorStats?.spentThisWeek ?? "0"),
      recentOperatorTransferCount1m: Number(operatorStats?.recentCount1m ?? 0),
    };
  }

  /**
   * Shared policy gate for the operator TRANSFER rails (withdraw + usd-send).
   * Both move USDC value OUT of the venue to a destination address — one is an
   * HL withdraw to Arbitrum, the other an HL-internal USDC transfer — so both
   * run the same evaluation POST /vault/sign runs: approved-addresses reads
   * `request.to`, spending-limit reads `request.value`, rate-limit reads the
   * recent-tx counters, and daily/weekly caps read the spent counters.
   *
   * Denomination invariant: `request.value` is converted from USDC to the
   * evaluation chain's NATIVE base units (wei on Arbitrum) via the price
   * oracle, because the spending-limit evaluator prices `value` as native wei
   * — passing 6-decimal USDC base units would understate the notional by
   * ~1e12 and silently disable every USD-denominated cap. The conversion is
   * skipped (the oracle never consulted) when the policy set has no enabled
   * spending-limit rule, since no other rule consumes `value` here; when a
   * spending-limit rule IS configured and the oracle cannot quote, the gate
   * FAILS CLOSED. An empty policy set approves nothing (engine default-deny),
   * so a policy-less agent cannot use either rail — set an approved-addresses
   * policy first, exactly as the withdraw route already required.
   */
  async function evaluateOperatorTransferPolicy(input: {
    tenantId: string;
    agentId: string;
    rail: "withdraw" | "usd-send";
    idempotencyKey: string;
    destination: string;
    amountBaseUnits: bigint;
  }): Promise<{ approved: true; reservationId: string } | { approved: false; reason: string }> {
    // Preserve configured tenant defaults when the agent has no stored rows.
    // Stored agent policy rows are re-read under the table lock below.
    const defaultPolicySet = await getPolicySet(input.tenantId, input.agentId);
    return db.transaction(async (tx) => {
      // Cross-replica serialization: use the same per-agent spend lock as the
      // core vault and intent paths. Agent ids are global primary keys, so this
      // serializes operator reservations with both other operator rails and
      // on-chain transaction evaluation/commit for the cumulative cap.
      const pgliteRuntime =
        process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true";
      if (!pgliteRuntime) {
        await tx.execute(sql`select pg_advisory_xact_lock(hashtextextended(${input.agentId}, 0))`);
      }
      // Stabilize the authorization snapshot until the reservation commits.
      // Policy writes take ROW EXCLUSIVE table locks, which conflict with SHARE;
      // this closes the load-policy -> reserve TOCTOU even though policy mutation
      // is implemented by several control-plane routes.
      // Embedded PGLite has one connection and therefore already serializes
      // transactions; its LOCK TABLE implementation deadlocks that connection.
      if (!pgliteRuntime) await tx.execute(sql.raw('lock table "policies" in share mode'));
      const storedPolicies = await tx
        .select()
        .from(policies)
        .where(eq(policies.agentId, input.agentId));
      const policySet: PolicyRule[] =
        storedPolicies.length > 0
          ? storedPolicies.map((rule) => ({
              id: rule.id,
              type: rule.type,
              enabled: rule.enabled,
              config: rule.config,
            }))
          : defaultPolicySet;
      const hasSpendingLimit = policySet.some(
        (rule) => rule.type === "spending-limit" && rule.enabled,
      );
      const stats = await getOperatorSpendStats(input.tenantId, input.agentId, tx);
      // The public 10/minute safety ceiling must survive process restarts and
      // load-balancing even when Redis is unavailable. Count both rails under
      // the same DB lock so parallel requests cannot all pass on stale state.
      if (stats.recentOperatorTransferCount1m >= OPERATOR_TRANSFER_MAX_CALLS) {
        return {
          approved: false as const,
          reason: "Operator transfer rate limit exceeded",
        };
      }

      let value = input.amountBaseUnits.toString();
      if (hasSpendingLimit) {
        const nativeUsd = await priceOracle.getNativeUsdPrice(ARBITRUM_CHAIN_ID);
        if (nativeUsd === null || !Number.isFinite(nativeUsd) || nativeUsd <= 0) {
          return {
            approved: false as const,
            reason:
              "spending-limit policy cannot be evaluated: no USD price available for the destination chain",
          };
        }
        // Pin one quote for the whole evaluation. Keep the durable USDC ledger
        // as integer base units and round conversions upward so float drift or
        // a quote change between calls can never understate spend.
        const priceScale = 100_000_000n;
        const scaledPrice = BigInt(Math.floor(nativeUsd * Number(priceScale)));
        if (scaledPrice <= 0n) {
          return { approved: false as const, reason: "invalid native USD price" };
        }
        const usdcBaseUnitsToWei = (amount: bigint) => {
          const numerator = amount * 10n ** 18n * priceScale;
          const denominator = 10n ** BigInt(USDC_DECIMALS) * scaledPrice;
          return (numerator + denominator - 1n) / denominator;
        };
        value = usdcBaseUnitsToWei(input.amountBaseUnits).toString();
        const pinnedPriceOracle = {
          ...priceOracle,
          async getNativeUsdPrice(chainId: number) {
            return chainId === ARBITRUM_CHAIN_ID
              ? Number(scaledPrice) / Number(priceScale)
              : priceOracle.getNativeUsdPrice(chainId);
          },
          async weiToUsd(weiValue: string, chainId: number, tokenAddress?: string) {
            if (chainId !== ARBITRUM_CHAIN_ID || (tokenAddress && tokenAddress !== "native")) {
              return priceOracle.weiToUsd(weiValue, chainId, tokenAddress);
            }
            return (Number(BigInt(weiValue)) / 1e18) * (Number(scaledPrice) / Number(priceScale));
          },
          async usdToWei(usdValue: number, chainId: number, tokenAddress?: string) {
            if (chainId !== ARBITRUM_CHAIN_ID || (tokenAddress && tokenAddress !== "native")) {
              return priceOracle.usdToWei(usdValue, chainId, tokenAddress);
            }
            const microUsd = BigInt(Math.ceil(usdValue * 10 ** USDC_DECIMALS));
            return usdcBaseUnitsToWei(microUsd).toString();
          },
        };
        const evaluation = await policyEngine.evaluate(policySet, {
          request: {
            agentId: input.agentId,
            tenantId: input.tenantId,
            to: input.destination,
            value,
            chainId: ARBITRUM_CHAIN_ID,
          },
          venue: "hyperliquid" as const,
          recentTxCount1h: stats.recentTxCount1h,
          recentTxCount24h: stats.recentTxCount24h,
          spentToday: stats.spentToday,
          spentThisWeek: stats.spentThisWeek,
          additionalUsdSpentTodayMicros: stats.operatorSpentTodayBaseUnits,
          additionalUsdSpentThisWeekMicros: stats.operatorSpentThisWeekBaseUnits,
          priceOracle: pinnedPriceOracle,
        });
        if (!evaluation.approved) {
          const failed = evaluation.results.find((r) => !r.passed);
          return {
            approved: false as const,
            reason: failed?.reason ?? "transfer destination violates policy",
          };
        }
      } else {
        const evaluation = await policyEngine.evaluate(policySet, {
          request: {
            agentId: input.agentId,
            tenantId: input.tenantId,
            to: input.destination,
            value,
            chainId: ARBITRUM_CHAIN_ID,
          },
          venue: "hyperliquid" as const,
          recentTxCount1h: stats.recentTxCount1h,
          recentTxCount24h: stats.recentTxCount24h,
          spentToday: stats.spentToday,
          spentThisWeek: stats.spentThisWeek,
          priceOracle,
        });
        if (!evaluation.approved) {
          const failed = evaluation.results.find((r) => !r.passed);
          return {
            approved: false as const,
            reason: failed?.reason ?? "transfer destination violates policy",
          };
        }
      }
      const [reservation] = await tx
        .insert(operatorTransferReservations)
        .values({
          tenantId: input.tenantId,
          agentId: input.agentId,
          rail: input.rail,
          idempotencyKey: input.idempotencyKey,
          destination: input.destination,
          amountBaseUnits: input.amountBaseUnits.toString(),
          status: "pending",
        })
        .returning({ id: operatorTransferReservations.id });
      if (!reservation) throw new Error("failed to reserve operator transfer spend");
      return { approved: true as const, reservationId: reservation.id };
    });
  }

  async function finishOperatorReservation(
    tenantId: string,
    agentId: string,
    id: string,
    status: "final" | "released",
  ) {
    const [finished] = await db
      .update(operatorTransferReservations)
      .set({ status, finalizedAt: new Date() })
      .where(
        and(
          eq(operatorTransferReservations.id, id),
          eq(operatorTransferReservations.tenantId, tenantId),
          eq(operatorTransferReservations.agentId, agentId),
          eq(operatorTransferReservations.status, "pending"),
        ),
      )
      .returning({ id: operatorTransferReservations.id });
    return Boolean(finished);
  }

  async function releaseOperatorTransfer(
    tenantId: string,
    agentId: string,
    reservationId: string,
    idempotency: OperatorIdempotency,
  ) {
    // Release the durable reservation before freeing the idempotency claim.
    // If the process stops between these operations, retaining the claim is
    // fail-closed; the reverse order can admit a retry that then collides with
    // the still-pending reservation's partial unique index.
    const released = await finishOperatorReservation(tenantId, agentId, reservationId, "released");
    if (released) await idempotency.release?.();
  }

  function operatorActor(c: Context<{ Variables: AppVariables }>): {
    actorType: "platform" | "user" | "agent";
    actorId: string;
  } {
    // operatorAuth sets authType to "platform" when authenticated via platform key.
    if (c.get("authType") === "platform") {
      return { actorType: "platform", actorId: "platform-operator" };
    }
    const userId = c.get("userId");
    if (userId) return { actorType: "user", actorId: userId };
    return { actorType: "user", actorId: c.get("tenantId") ?? "operator" };
  }

  async function withOperatorTenantDatabase<T>(
    c: Context<{ Variables: AppVariables }>,
    tenantId: string,
    callback: () => Promise<T>,
  ): Promise<T> {
    if (hasTenantTransactionDatabase({ tenantId })) return callback();
    const actor = operatorActor(c);
    const context = tenantContextFromAuthenticatedPrincipal({
      tenantId,
      method: c.req.method,
      subject: actor.actorId,
    });
    const driver =
      process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true"
        ? "pglite"
        : getDatabaseDriver();
    return withTenantRlsTransaction(db as never, driver, context, async (tx) =>
      withTenantTransactionDatabase(tx as never, { tenantId }, callback),
    );
  }

  async function auditRecoveryEvent(
    c: Context<{ Variables: AppVariables }>,
    tenantId: string,
    agentId: string,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    const actor = operatorActor(c);
    await withOperatorTenantDatabase(c, tenantId, () =>
      writeAuditEvent({
        tenantId,
        actorType: actor.actorType,
        actorId: actor.actorId,
        action,
        resourceType: "trade",
        resourceId: agentId,
        metadata,
      }),
    );
    // Keep the best-effort proxy log in its own tenant transaction. A
    // restricted platform role intentionally has only audit-chain privileges;
    // if proxy logging is denied, rolling back this separate transaction must
    // not undo the required chained audit event above.
    await withOperatorTenantDatabase(c, tenantId, () =>
      getDb()
        .insert(proxyAuditLog)
        .values({
          tenantId,
          agentId,
          targetHost: action,
          targetPath: JSON.stringify(metadata),
          method: "AUDIT",
          statusCode: 200,
          latencyMs: 0,
          reason: action,
        }),
    ).catch(() => undefined);
  }

  type DurableTransferState = {
    seq: number;
    action: string;
    metadata: Record<string, unknown>;
  };

  function durableTransferResponse(
    c: Context<{ Variables: AppVariables }>,
    durableState: DurableTransferState | undefined,
    requestFingerprint: string,
  ): Response | undefined {
    if (!durableState) return undefined;
    if (durableState.metadata.requestFingerprint !== requestFingerprint) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency key reused with a different body" },
        409,
      );
    }
    if (durableState.action === "trade.recovery.transfer.submitted") {
      c.header("Idempotency-Replayed", "true");
      return c.json<ApiResponse>({ ok: true, data: durableState.metadata.response });
    }
    if (
      durableState.action === "trade.recovery.transfer.failed" &&
      durableState.metadata.ambiguousOutcome === true
    ) {
      c.header("Idempotency-Replayed", "true");
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Failed to submit collateral transfer",
        },
        502,
      );
    }
    if (durableState.action === "trade.recovery.transfer.requested") {
      c.header("Retry-After", "60");
      return c.json<ApiResponse>(
        {
          ok: false,
          error: "Collateral transfer outcome requires reconciliation",
        },
        409,
      );
    }
    return undefined;
  }

  async function findDurableTransferState(
    c: Context<{ Variables: AppVariables }>,
    tenantId: string,
    agentId: string,
    idempotencyKey: string,
  ): Promise<DurableTransferState | undefined> {
    const query = async (queryDb: typeof db) => {
      const rows = await queryDb
        .select({
          seq: auditEvents.seq,
          action: auditEvents.action,
          metadata: auditEvents.metadata,
        })
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.tenantId, tenantId),
            eq(auditEvents.resourceId, agentId),
            inArray(auditEvents.action, [
              "trade.recovery.transfer.requested",
              "trade.recovery.transfer.failed",
              "trade.recovery.transfer.submitted",
            ]),
            sql`${auditEvents.metadata}->>'idempotencyKey' = ${idempotencyKey}`,
          ),
        )
        .orderBy(desc(auditEvents.seq))
        .limit(1);
      const selected = rows[0];
      if (!selected) {
        const fullVerification = await verifyAuditChain(tenantId, {
          requireHead: true,
          executor: queryDb,
        });
        if (!fullVerification.valid) {
          throw new Error("COLLATERAL_TRANSFER_AUDIT_CHAIN_INVALID");
        }
        return undefined;
      }
      const verification = await verifyAuditChain(tenantId, {
        fromSeq: selected.seq,
        toSeq: selected.seq,
        maxRows: 1,
        executor: queryDb,
      });
      if (!verification.valid || verification.count !== 1) {
        throw new Error("COLLATERAL_TRANSFER_AUDIT_EVIDENCE_INVALID");
      }
      return selected;
    };
    if (hasTenantTransactionDatabase({ tenantId })) return query(getDb());

    // Platform-key operator requests intentionally bypass tenantAuth, so they
    // do not already carry a tenant-bound database capability. Establish one
    // from the authenticated operator identity before reading the RLS-protected
    // durable audit chain. Request body/header values never mint this context.
    const actor = operatorActor(c);
    const context = tenantContextFromAuthenticatedPrincipal({
      tenantId,
      method: "operator-recovery-transfer",
      subject: actor.actorId,
    });
    const driver =
      process.env.STEWARD_DB_MODE === "pglite" || process.env.STEWARD_PGLITE_MEMORY === "true"
        ? "pglite"
        : getDatabaseDriver();
    return withTenantRlsTransaction(
      db as never,
      driver,
      context,
      async (tx) => query(tx as typeof db),
      { isolationLevel: "repeatable read", readOnly: true },
    );
  }

  /**
   * Resolve the agent's Hyperliquid venue wallet address. Prefers the explicit
   * venue-scoped wallet (vault.getWallet) and falls back to the agent's EVM
   * wallet — same resolution priority as POST /sessions in trade.ts.
   */
  async function resolveVenueWallet(
    tenantId: string,
    agentId: string,
    venue: string,
  ): Promise<string | null> {
    try {
      const wallet = await vault.getWallet({ agentId, venue });
      if (wallet?.address) return wallet.address;
    } catch {
      // fall through to agent EVM wallet
    }
    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return null;
    const evm = agent.walletAddresses?.evm;
    if (evm) return evm;
    return agent.walletAddress?.startsWith("0x") ? agent.walletAddress : null;
  }

  function buildAdapter(tenantId: string, agentId: string, walletAddress: string) {
    const vaultClient = {
      signTypedData: (input: Omit<Parameters<typeof vault.signTypedData>[0], "tenantId">) =>
        vault.signTypedData({
          ...input,
          tenantId,
          venue: "hyperliquid" as const,
          expectedWalletAddress: walletAddress,
        }),
    };
    return new HyperliquidAdapter(vaultClient, agentId, walletAddress);
  }

  // ── POST /v1/trade/:venue/deposit ──────────────────────────────────────────────
  // Fund an agent's Hyperliquid account by signing an ERC-20 USDC transfer from
  // the agent's OWN venue wallet to the HL Arbitrum bridge. HL credits the sender,
  // so this correctly credits the policy-scoped venue wallet (NOT the operator).
  // The agent's wallet must already hold USDC + a little ETH for gas on Arbitrum.
  operatorRecoveryRoutes.post("/:venue/deposit", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }

    const raw = await safeJsonParse(c);
    const parsed = depositSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey || body.idempotencyKey.length > 256) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency-Key is required and must be at most 256 characters" },
        400,
      );
    }
    const { agentId } = body;

    // Parse + validate the USDC amount.
    const amountNum = Number(body.amount);
    if (!Number.isFinite(amountNum) || amountNum <= 0) {
      return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
    }
    if (amountNum < HL_MIN_DEPOSIT_USDC) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amount below Hyperliquid minimum deposit of ${HL_MIN_DEPOSIT_USDC} USDC`,
        },
        400,
      );
    }
    if (amountNum > HL_MAX_DEPOSIT_USDC) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amount exceeds the per-deposit maximum of ${HL_MAX_DEPOSIT_USDC} USDC; split into smaller deposits`,
        },
        400,
      );
    }
    // Reject sub-cent precision the 6-decimal conversion can't represent exactly,
    // so the on-chain amount always matches the requested amount.
    const scaled = amountNum * 10 ** USDC_DECIMALS;
    if (!Number.isInteger(scaled)) {
      return c.json<ApiResponse>(
        { ok: false, error: "amount has more than 6 decimal places" },
        400,
      );
    }
    // Convert to 6-decimal base units (exact: `scaled` is an integer here).
    const amountBaseUnits = BigInt(scaled);

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    // Idempotency keyed on (agent, amount). Computed BEFORE broadcast so a retried
    // deposit with the same key returns the original result instead of double-sending.
    let idempotency = await getOperatorIdempotency(`${tenantId}:deposit`, body.idempotencyKey, {
      agentId,
      venue,
      amount: amountBaseUnits.toString(),
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    // Build the ERC-20 transfer(bridge, amount) calldata and have the vault sign +
    // broadcast it FROM the agent's venue wallet on Arbitrum. The raw key never
    // leaves the vault. venue is set so the vault selects the hyperliquid-scoped key.
    const data = encodeErc20Transfer(HYPERLIQUID_ARBITRUM_BRIDGE, amountBaseUnits);
    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;
    let txHash: string;
    try {
      txHash = await vault.signTransaction({
        agentId,
        tenantId,
        to: ARBITRUM_USDC,
        value: "0",
        data,
        chainId: ARBITRUM_CHAIN_ID,
        venue: "hyperliquid",
        broadcast: true,
      });
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.deposit.failed", {
        venue,
        walletAddress,
        bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
        amount: amountBaseUnits.toString(),
        ...redactedThrownDiagnostics(err),
      });
      // The broadcast may have landed — record the ambiguous outcome so a retry
      // replays this 502 instead of double-broadcasting the ERC-20 transfer.
      const errorBody = { ok: false as const, error: "Failed to submit deposit" };
      await idempotency.storeFailure?.(errorBody);
      return c.json<ApiResponse>(errorBody, 502);
    }

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.deposit.submitted", {
      venue,
      walletAddress,
      bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
      amount: amountBaseUnits.toString(),
      txHash,
    });

    const response = {
      venue,
      walletAddress,
      bridge: HYPERLIQUID_ARBITRUM_BRIDGE,
      amountUsdc: amountNum,
      amountBaseUnits: amountBaseUnits.toString(),
      txHash,
    };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/leverage ─────────────────────────────────────────────
  // Platform-key recovery lever for already-open Hyperliquid positions. Builder
  // perps are isolated-only and capped at 3x here, matching the order path.
  operatorRecoveryRoutes.post("/:venue/leverage", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }
    if (c.get("authType") !== "platform") {
      return c.json<ApiResponse>(
        { ok: false, error: "Platform key required for leverage update" },
        403,
      );
    }

    const raw = await safeJsonParse(c);
    const parsed = leverageSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    const { agentId, coin } = body;
    const builderPerp = isBuilderPerpSymbol(coin);
    const effectiveLeverage = builderPerp ? Math.min(body.leverage, 3) : body.leverage;
    const isCross = builderPerp ? false : (body.isCross ?? false);

    let idempotency = await getOperatorIdempotency(`${tenantId}:leverage`, body.idempotencyKey, {
      agentId,
      venue,
      coin,
      leverage: effectiveLeverage,
      requestedLeverage: body.leverage,
      isCross,
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.requested", {
      venue,
      walletAddress,
      coin,
      leverage: effectiveLeverage,
      requestedLeverage: body.leverage,
      isCross,
      builderPerp,
    });

    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;
    let result: unknown;
    try {
      result = await adapter.updateLeverage({ coin, leverage: effectiveLeverage, isCross });
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.failed", {
        venue,
        walletAddress,
        coin,
        leverage: effectiveLeverage,
        requestedLeverage: body.leverage,
        isCross,
        builderPerp,
        ...redactedThrownDiagnostics(err),
      });
      // The venue call may have landed — record the ambiguous outcome so a
      // retry replays this 502 instead of re-executing the leverage update.
      const errorBody = { ok: false as const, error: "Failed to update leverage" };
      await idempotency.storeFailure?.(errorBody);
      return c.json<ApiResponse>(errorBody, 502);
    }

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.leverage.submitted", {
      venue,
      walletAddress,
      coin,
      leverage: effectiveLeverage,
      requestedLeverage: body.leverage,
      isCross,
      builderPerp,
    });

    const response = {
      venue,
      walletAddress,
      coin,
      leverage: effectiveLeverage,
      requestedLeverage: body.leverage,
      isCross,
      builderPerp,
      result,
    };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/add-margin ───────────────────────────────────────────
  // Platform-key recovery lever for adding USDC margin to an existing isolated
  // Hyperliquid position before lowering isolated leverage.
  operatorRecoveryRoutes.post("/:venue/add-margin", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }
    if (c.get("authType") !== "platform") {
      return c.json<ApiResponse>(
        { ok: false, error: "Platform key required for margin update" },
        403,
      );
    }

    const raw = await safeJsonParse(c);
    const parsed = addMarginSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey || body.idempotencyKey.length > 256) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency-Key is required and must be at most 256 characters" },
        400,
      );
    }
    const { agentId, coin } = body;

    if (hasTooManyUsdcDecimals(body.amountUsdc)) {
      return c.json<ApiResponse>(
        { ok: false, error: "amountUsdc has more than 6 decimal places" },
        400,
      );
    }
    const amountBaseUnits = parseUsdcBaseUnits(body.amountUsdc);
    if (amountBaseUnits === null || amountBaseUnits <= 0n) {
      return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
    }
    const amountNum = Number(body.amountUsdc);
    if (!Number.isFinite(amountNum) || amountNum <= 0) {
      return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
    }
    if (amountNum > HL_MAX_WITHDRAW_USDC) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amountUsdc exceeds the per-margin-update maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller updates`,
        },
        400,
      );
    }

    let idempotency = await getOperatorIdempotency(`${tenantId}:add-margin`, body.idempotencyKey, {
      agentId,
      venue,
      coin,
      amount: amountBaseUnits.toString(),
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.requested", {
      venue,
      walletAddress,
      coin,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
    });

    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;
    let result: unknown;
    try {
      result = await adapter.addIsolatedMargin({ coin, amountUsdc: body.amountUsdc });
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.failed", {
        venue,
        walletAddress,
        coin,
        amountUsdc: String(body.amountUsdc),
        amountBaseUnits: amountBaseUnits.toString(),
        ...redactedThrownDiagnostics(err),
      });
      // The venue call may have landed — record the ambiguous outcome so a
      // retry replays this 502 instead of moving margin a second time.
      const errorBody = { ok: false as const, error: "Failed to add isolated margin" };
      await idempotency.storeFailure?.(errorBody);
      return c.json<ApiResponse>(errorBody, 502);
    }

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.add-margin.submitted", {
      venue,
      walletAddress,
      coin,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
    });

    const response = {
      venue,
      walletAddress,
      coin,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
      result,
    };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/usd-send ───────────────────────────────────────────
  // Platform-key only internal USDC transfer between Hyperliquid accounts. This is
  // a user-signed action and must be signed by the sending agent/vault master HL wallet.
  operatorRecoveryRoutes.post("/:venue/usd-send", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }
    if (c.get("authType") !== "platform") {
      return c.json<ApiResponse>({ ok: false, error: "Platform key required for usdSend" }, 403);
    }

    const raw = await safeJsonParse(c);
    const parsed = usdSendSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      destination: parsed.data.destination.toLowerCase(),
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    const { agentId, destination, amount } = body;
    if (!body.idempotencyKey || body.idempotencyKey.length > 256) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency-Key is required and must be at most 256 characters" },
        400,
      );
    }

    // Reject precision the six-decimal conversion cannot represent and enforce
    // the per-call safety ceiling so one compromised operator request cannot
    // move the venue's entire USDC balance.
    if (hasTooManyUsdcDecimals(amount)) {
      return c.json<ApiResponse>(
        { ok: false, error: "amount has more than 6 decimal places" },
        400,
      );
    }
    const amountBaseUnits = parseUsdcBaseUnits(amount);
    if (amountBaseUnits === null || amountBaseUnits <= 0n) {
      return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
    }
    if (amountBaseUnits > HL_MAX_WITHDRAW_BASE_UNITS) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amount exceeds the per-usd-send maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller transfers`,
        },
        400,
      );
    }

    let idempotency = await getOperatorIdempotency(`${tenantId}:usd-send`, body.idempotencyKey, {
      agentId,
      venue,
      destination,
      amount,
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const rate = await enforceOperatorTransferRateLimit("usd-send", tenantId, agentId);
    if (rate.unavailable) {
      return c.json<ApiResponse>(
        { ok: false, error: "Operator transfer rate limit unavailable" },
        503,
      );
    }
    if (!rate.allowed) {
      c.header("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return c.json<ApiResponse>(
        { ok: false, error: "Operator transfer rate limit exceeded" },
        429,
      );
    }

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    // ── Policy gate (BEFORE signing) ─────────────────────────────────────────────
    // usdSend moves USDC to an ARBITRARY Hyperliquid account — functionally a
    // withdrawal rail. It must satisfy the same policy evaluation as /withdraw
    // (approved-addresses + spend/rate caps); before this gate a leaked platform
    // key could drain the full HL balance to any destination in one call.
    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;

    const policy = await evaluateOperatorTransferPolicy({
      tenantId,
      agentId,
      rail: "usd-send",
      idempotencyKey: body.idempotencyKey,
      destination,
      amountBaseUnits,
    });
    if (!policy.approved) {
      await idempotency.release?.();
      await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.policy-rejected", {
        venue,
        walletAddress,
        destination,
        amount,
        reason: policy.reason,
      });
      return c.json({ code: "policy-violation", reason: policy.reason }, 400);
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    let signedUsdSend: Awaited<ReturnType<HyperliquidAdapter["signUsdSend"]>>;
    try {
      signedUsdSend = await adapter.signUsdSend({ destination, amount });
    } catch (err) {
      await releaseOperatorTransfer(tenantId, agentId, policy.reservationId, idempotency);
      try {
        await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.failed", {
          venue,
          walletAddress,
          destination,
          amount,
          ...redactedThrownDiagnostics(err),
        });
      } catch (auditErr) {
        console.error(
          "[operator-recovery] usdSend sign-failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      }
      return c.json<ApiResponse>({ ok: false, error: "Failed to sign usdSend" }, 502);
    }

    try {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.requested", {
        venue,
        walletAddress,
        destination,
        amount,
      });
    } catch (_err) {
      // Nothing has reached the venue yet, so an audit outage is a definite
      // pre-submit failure and must not poison the durable spend reservation.
      await releaseOperatorTransfer(tenantId, agentId, policy.reservationId, idempotency);
      return c.json<ApiResponse>({ ok: false, error: "Failed to audit usdSend request" }, 502);
    }

    let result: unknown;
    try {
      result = await adapter.submitUsdSend(signedUsdSend);
    } catch (err) {
      const definitelyRejected = isDefiniteVenueRejection(err);
      if (definitelyRejected) {
        await releaseOperatorTransfer(tenantId, agentId, policy.reservationId, idempotency);
      } else {
        const errorBody = { ok: false as const, error: "Failed to submit usdSend" };
        await idempotency.storeFailure?.(errorBody);
      }
      try {
        await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.failed", {
          venue,
          walletAddress,
          destination,
          amount,
          definiteRejection: definitelyRejected,
          ...redactedThrownDiagnostics(err),
        });
      } catch (auditErr) {
        console.error(
          "[operator-recovery] usdSend failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      }
      return c.json<ApiResponse>(
        {
          ok: false,
          error: definitelyRejected ? "Hyperliquid rejected usdSend" : "Failed to submit usdSend",
        },
        502,
      );
    }

    await finishOperatorReservation(tenantId, agentId, policy.reservationId, "final");

    const response = { venue, walletAddress, destination, amount, result };
    await idempotency.store?.(response);
    try {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.usdsend.completed", {
        venue,
        walletAddress,
        destination,
        amount,
      });
    } catch (auditErr) {
      console.error(
        "[operator-recovery] usdSend completed audit failed",
        redactedThrownDiagnostics(auditErr),
      );
    }
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/approve-builder ─────────────────────────────────────
  // Platform-key only approval for Hyperliquid builder-code fees. This is a
  // user-signed action and must be signed by the agent/vault master HL wallet.
  operatorRecoveryRoutes.post("/:venue/approve-builder", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }
    if (c.get("authType") !== "platform") {
      return c.json<ApiResponse>(
        { ok: false, error: "Platform key required for builder fee approval" },
        403,
      );
    }

    const raw = await safeJsonParse(c);
    const parsed = approveBuilderSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      builder: parsed.data.builder.toLowerCase(),
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    const { agentId, builder, maxFeeRate } = body;

    let idempotency = await getOperatorIdempotency(
      `${tenantId}:approve-builder`,
      body.idempotencyKey,
      {
        agentId,
        venue,
        builder,
        maxFeeRate,
      },
    );
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approve.requested", {
      venue,
      walletAddress,
      builder,
      maxFeeRate,
    });

    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;
    let result: unknown;
    try {
      result = await adapter.approveBuilderFee({ builder, maxFeeRate });
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approve.failed", {
        venue,
        walletAddress,
        builder,
        maxFeeRate,
        ...redactedThrownDiagnostics(err),
      });
      // The venue call may have landed — record the ambiguous outcome so a
      // retry replays this 502 instead of re-submitting the approval.
      const errorBody = { ok: false as const, error: "Failed to approve builder fee" };
      await idempotency.storeFailure?.(errorBody);
      return c.json<ApiResponse>(errorBody, 502);
    }

    await auditRecoveryEvent(c, tenantId, agentId, "trade.builder.approved", {
      venue,
      walletAddress,
      builder,
      maxFeeRate,
    });

    const response = { venue, walletAddress, builder, maxFeeRate, result };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/transfer ─────────────────────────────────────────────
  // Platform-key only capital movement between Hyperliquid collateral buckets. This
  // does NOT withdraw funds, but it can strand core withdrawable USDC on an
  // isolated HIP-3 builder dex, so it is gated like operator recovery and audited
  // before/after signing. Exit story: close any builder-dex position first, call
  // transferFromBuilderDex (sourceDex "xyz" → destinationDex "") to pull USDC back
  // to core, then use the existing core-only withdraw route.
  operatorRecoveryRoutes.post("/:venue/transfer", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }
    if (c.get("authType") !== "platform") {
      return c.json<ApiResponse>(
        { ok: false, error: "Platform key required for collateral transfer" },
        403,
      );
    }

    const raw = await safeJsonParse(c);
    const parsed = transferSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey || body.idempotencyKey.length > 256) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency-Key is required and must be at most 256 characters" },
        400,
      );
    }
    const transferIdempotencyKey = body.idempotencyKey;
    const { agentId, sourceDex, destinationDex } = body;

    if (hasTooManyUsdcDecimals(body.amountUsdc)) {
      return c.json<ApiResponse>(
        { ok: false, error: "amountUsdc has more than 6 decimal places" },
        400,
      );
    }
    const amountBaseUnits = parseUsdcBaseUnits(body.amountUsdc);
    if (amountBaseUnits === null || amountBaseUnits <= 0n) {
      return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
    }
    const amountNum = Number(body.amountUsdc);
    if (!Number.isFinite(amountNum) || amountNum <= 0) {
      return c.json<ApiResponse>({ ok: false, error: "amountUsdc must be a positive number" }, 400);
    }
    if (amountNum > HL_MAX_WITHDRAW_USDC) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amountUsdc exceeds the per-transfer maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller transfers`,
        },
        400,
      );
    }

    const requestCommitment = {
      agentId,
      venue,
      sourceDex,
      destinationDex,
      amount: amountBaseUnits.toString(),
      token: body.token ?? null,
    };
    const requestFingerprint = createHash("sha256")
      .update(JSON.stringify(requestCommitment))
      .digest("hex");
    let idempotency = await getOperatorIdempotency(
      `${tenantId}:transfer`,
      body.idempotencyKey,
      requestCommitment,
    );
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    // Establish a non-keyed HMAC-chain guard before interpreting absence. If a
    // prior keyed requested/terminal pair was deleted, full-chain verification
    // below observes the missing sequence/high-water count and fails closed.
    const guardActor = operatorActor(c);
    try {
      await withOperatorTenantDatabase(c, tenantId, () =>
        writeAuditEvent({
          tenantId,
          actorType: guardActor.actorType,
          actorId: guardActor.actorId,
          action: "trade.recovery.replay_guard",
          resourceType: "trade",
          resourceId: agentId,
          metadata: { requestFingerprint },
        }),
      );
    } catch (err) {
      console.error(
        "[operator-recovery] collateral transfer replay guard failed",
        redactedThrownDiagnostics(err),
      );
      return c.json<ApiResponse>(
        { ok: false, error: "Collateral transfer replay evidence is unavailable" },
        503,
      );
    }

    // The HMAC-chained audit log is the durable replay backstop when Redis or a
    // process-local idempotency cache is unavailable. A requested event without
    // a terminal event means submission may have happened; fail closed instead
    // of repeating a capital movement.
    let durableState: DurableTransferState | undefined;
    try {
      durableState = await findDurableTransferState(c, tenantId, agentId, body.idempotencyKey);
    } catch (err) {
      console.error(
        "[operator-recovery] collateral transfer audit evidence verification failed",
        redactedThrownDiagnostics(err),
      );
      return c.json<ApiResponse>(
        { ok: false, error: "Collateral transfer replay evidence is unavailable" },
        503,
      );
    }
    const durableResponse = durableTransferResponse(c, durableState, requestFingerprint);
    if (durableResponse) return durableResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    const requestedMetadata = {
      venue,
      walletAddress,
      sourceDex,
      destinationDex,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
      idempotencyKey: body.idempotencyKey,
      requestFingerprint,
      outcome: "submission_pending",
    };

    // Serialize the authoritative absence check and requested append on a
    // database-scoped key. Two fresh workers can both miss the earlier replay
    // lookup, but only one may cross this transaction boundary without seeing
    // the other's durable requested evidence. The lock includes the request
    // identity (tenant + agent + idempotency key) so conflicting fingerprints
    // also serialize; the requested row binds the winning fingerprint and the
    // deterministic loser returns the canonical 409 conflict below.
    let claimState: DurableTransferState | undefined;
    try {
      claimState = await withOperatorTenantDatabase(c, tenantId, async () => {
        if (
          process.env.STEWARD_DB_MODE !== "pglite" &&
          process.env.STEWARD_PGLITE_MEMORY !== "true"
        ) {
          const claimKey = `operator-collateral:${tenantId}:${agentId}:${transferIdempotencyKey}`;
          await getDb().execute(
            sql`SELECT pg_advisory_xact_lock(hashtextextended(${claimKey}, 0))`,
          );
        }
        const existing = await findDurableTransferState(
          c,
          tenantId,
          agentId,
          transferIdempotencyKey,
        );
        // A definite local signing failure is explicitly safe to retry. It is
        // durable evidence, but not a claim that may have reached the venue,
        // so append a new requested marker while still holding this key lock.
        if (
          existing &&
          !(
            existing.action === "trade.recovery.transfer.failed" &&
            existing.metadata.ambiguousOutcome === false
          )
        ) {
          return existing;
        }
        const actor = operatorActor(c);
        await writeAuditEvent({
          tenantId,
          actorType: actor.actorType,
          actorId: actor.actorId,
          action: "trade.recovery.transfer.requested",
          resourceType: "trade",
          resourceId: agentId,
          metadata: requestedMetadata,
        });
        return undefined;
      });
    } catch (err) {
      console.error(
        "[operator-recovery] collateral transfer durable claim failed",
        redactedThrownDiagnostics(err),
      );
      return c.json<ApiResponse>(
        { ok: false, error: "Collateral transfer replay evidence is unavailable" },
        503,
      );
    }
    const claimResponse = durableTransferResponse(c, claimState, requestFingerprint);
    if (claimResponse) return claimResponse;

    // The required requested event committed before this best-effort proxy
    // record. Keep proxy failure isolated from the durable claim transaction.
    await withOperatorTenantDatabase(c, tenantId, () =>
      getDb()
        .insert(proxyAuditLog)
        .values({
          tenantId,
          agentId,
          targetHost: "trade.recovery.transfer.requested",
          targetPath: JSON.stringify(requestedMetadata),
          method: "AUDIT",
          statusCode: 200,
          latencyMs: 0,
          reason: "trade.recovery.transfer.requested",
        }),
    ).catch(() => undefined);

    // Signing is local (nothing reaches the venue), so a sign failure is safe to
    // retry and is NOT stored; a submit failure means the transfer may have
    // landed, so the ambiguous outcome IS stored and retries replay it.
    idempotency = await claimOperatorIdempotency(idempotency);
    const idempotencyClaimResponse = operatorIdempotencyResponse(c, idempotency);
    if (idempotencyClaimResponse) return idempotencyClaimResponse;
    let signed: Awaited<ReturnType<HyperliquidAdapter["signSendAsset"]>>;
    try {
      signed = await adapter.signSendAsset({
        destination: walletAddress,
        sourceDex,
        destinationDex,
        token: body.token,
        amount: body.amountUsdc,
      });
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.failed", {
        venue,
        walletAddress,
        sourceDex,
        destinationDex,
        amountUsdc: String(body.amountUsdc),
        idempotencyKey: body.idempotencyKey,
        requestFingerprint,
        ambiguousOutcome: false,
        phase: "sign",
        ...redactedThrownDiagnostics(err),
      }).catch((auditErr) => {
        console.error(
          "[operator-recovery] collateral transfer sign-failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      });
      await idempotency.release?.();
      return c.json<ApiResponse>({ ok: false, error: "Failed to sign collateral transfer" }, 502);
    }

    let result: unknown;
    const action: unknown = signed.action;
    try {
      result = await adapter.submitSendAsset(signed);
    } catch (err) {
      const definitelyRejected = isDefiniteVenueRejection(err);
      const errorBody = {
        ok: false as const,
        error: definitelyRejected
          ? "Hyperliquid rejected collateral transfer"
          : "Failed to submit collateral transfer",
      };
      if (definitelyRejected) await idempotency.release?.();
      else await idempotency.storeFailure?.(errorBody);
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.failed", {
        venue,
        walletAddress,
        sourceDex,
        destinationDex,
        amountUsdc: String(body.amountUsdc),
        idempotencyKey: body.idempotencyKey,
        requestFingerprint,
        definiteRejection: definitelyRejected,
        ambiguousOutcome: !definitelyRejected,
        phase: "submit",
        ...redactedThrownDiagnostics(err),
      }).catch((auditErr) => {
        console.error(
          "[operator-recovery] collateral transfer submit-failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      });
      return c.json<ApiResponse>(errorBody, 502);
    }

    const response = {
      venue,
      walletAddress,
      sourceDex,
      destinationDex,
      amountUsdc: String(body.amountUsdc),
      result,
    };
    // The venue effect is terminal once submitSendAsset returns. Persist replay
    // evidence before the completion audit so an audit outage cannot make a
    // retry submit the same capital movement again.
    await idempotency.store?.(response).catch((storeErr) => {
      console.error(
        "[operator-recovery] collateral transfer replay persistence failed",
        redactedThrownDiagnostics(storeErr),
      );
    });
    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.transfer.submitted", {
      venue,
      walletAddress,
      sourceDex,
      destinationDex,
      amountUsdc: String(body.amountUsdc),
      amountBaseUnits: amountBaseUnits.toString(),
      idempotencyKey: body.idempotencyKey,
      requestFingerprint,
      response,
      action,
    }).catch((auditErr) => {
      console.error(
        "[operator-recovery] collateral transfer submitted audit failed",
        redactedThrownDiagnostics(auditErr),
      );
    });
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/close-all ────────────────────────────────────────────
  operatorRecoveryRoutes.post("/:venue/close-all", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }

    const raw = await safeJsonParse(c);
    const parsed = closeAllSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    const { agentId } = body;

    let idempotency = await getOperatorIdempotency(`${tenantId}:close-all`, body.idempotencyKey, {
      agentId,
      venue,
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;
    let results: Awaited<ReturnType<HyperliquidAdapter["closeAllPositions"]>>;
    try {
      results = await adapter.closeAllPositions();
    } catch (err) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.close-all.failed", {
        venue,
        walletAddress,
        ...redactedThrownDiagnostics(err),
      });
      // Positions may have been partially closed — record the ambiguous outcome
      // so a retry replays this 502 instead of firing another close batch.
      const errorBody = { ok: false as const, error: "Failed to close positions" };
      await idempotency.storeFailure?.(errorBody);
      return c.json<ApiResponse>(errorBody, 502);
    }

    // Audit every per-coin close so the recovery action is fully traceable.
    for (const r of results) {
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.position-closed", {
        venue,
        walletAddress,
        coin: r.coin,
        status: r.result.status,
        orderId: r.result.orderId ?? null,
      });
    }

    const response = { venue, walletAddress, closed: results };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  // ── POST /v1/trade/:venue/withdraw ─────────────────────────────────────────────
  operatorRecoveryRoutes.post("/:venue/withdraw", async (c) => {
    const tenantId = c.get("tenantId");
    const venue = c.req.param("venue");
    if (venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: `Unsupported venue: ${venue}` }, 400);
    }

    const raw = await safeJsonParse(c);
    const parsed = withdrawSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey || body.idempotencyKey.length > 256) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency-Key is required and must be at most 256 characters" },
        400,
      );
    }
    const { agentId, destination } = body;

    if (!isValidAnyAddress(destination)) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid destination address" }, 400);
    }

    // Validate the EXPLICIT withdraw amount the same way /deposit validates its
    // amount: reject non-finite/NaN/<=0, enforce a per-call max cap, and reject
    // sub-cent/over-precision values the 6-decimal conversion can't represent.
    // (The no-amount path resolves the full withdrawable balance below.)
    let explicitAmountBaseUnits: bigint | null = null;
    if (body.amount !== undefined) {
      if (hasTooManyUsdcDecimals(body.amount)) {
        return c.json<ApiResponse>(
          { ok: false, error: "amount has more than 6 decimal places" },
          400,
        );
      }
      explicitAmountBaseUnits = parseUsdcBaseUnits(body.amount);
      if (explicitAmountBaseUnits === null || explicitAmountBaseUnits <= 0n) {
        return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
      }
      const amountNum = Number(body.amount);
      if (amountNum > HL_MAX_WITHDRAW_USDC) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: `amount exceeds the per-withdraw maximum of ${HL_MAX_WITHDRAW_USDC} USDC; split into smaller withdraws`,
          },
          400,
        );
      }
    }

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const walletAddress = await resolveVenueWallet(tenantId, agentId, venue);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        { ok: false, error: "Hyperliquid venue wallet not found for agent" },
        404,
      );
    }

    const explicitIdempotencyAmount =
      explicitAmountBaseUnits !== null ? explicitAmountBaseUnits.toString() : null;
    let idempotency = await getOperatorIdempotency(`${tenantId}:withdraw`, body.idempotencyKey, {
      agentId,
      venue,
      destination,
      amount: explicitIdempotencyAmount,
    });
    const replayResponse = operatorIdempotencyResponse(c, idempotency);
    if (replayResponse) return replayResponse;

    // Resolve amount after the idempotency cache lookup, so a retry for a
    // previous full-balance withdraw returns the cached success before reading a
    // changed live balance.
    // `amount` stays human-readable for signing; `amountBaseUnits` (USDC 6-decimal
    // base units) is what the policy gate converts to native wei for the spend-cap.
    let amount = body.amount;
    let amountBaseUnits = explicitAmountBaseUnits;
    if (amount === undefined) {
      const withdrawable = await fetchWithdrawable(walletAddress);
      amountBaseUnits = withdrawable ? parseUsdcBaseUnits(withdrawable) : null;
      if (!withdrawable || amountBaseUnits === null || amountBaseUnits <= 0n) {
        return c.json<ApiResponse>(
          { ok: false, error: "No withdrawable balance and no amount specified" },
          400,
        );
      }
      amount = withdrawable;
    }
    if (amountBaseUnits === null) {
      return c.json<ApiResponse>({ ok: false, error: "amount must be a positive number" }, 400);
    }
    // The omitted-amount path resolves a live full balance, so enforce the same
    // per-call safety ceiling after resolution. Otherwise omitting `amount`
    // bypasses the explicit-amount cap and can drain an arbitrarily large venue
    // balance in one request.
    if (amountBaseUnits > HL_MAX_WITHDRAW_BASE_UNITS) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `amount exceeds the per-withdraw maximum of ${HL_MAX_WITHDRAW_USDC} USDC; specify an amount and split into smaller withdraws`,
        },
        400,
      );
    }

    // ── Policy gate (BEFORE signing) ─────────────────────────────────────────────
    // The withdraw destination must be on the agent's approved list AND the amount
    // must satisfy the spend/rate caps. The shared operator-transfer gate
    // denominates `value` in native wei (so USD spending limits see the REAL
    // notional, not 6-decimal USDC misread as wei) and feeds the evaluator the
    // agent's REAL recent-tx counts + chain-scoped spend counters (the previous
    // hardcoded zeroes made rate-limit and daily/weekly rules structurally
    // inert, and the misdenominated `value` disabled even per-tx USD caps).
    const rate = await enforceOperatorTransferRateLimit("withdraw", tenantId, agentId);
    if (rate.unavailable) {
      return c.json<ApiResponse>(
        { ok: false, error: "Operator transfer rate limit unavailable" },
        503,
      );
    }
    if (!rate.allowed) {
      c.header("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return c.json<ApiResponse>(
        { ok: false, error: "Operator transfer rate limit exceeded" },
        429,
      );
    }

    idempotency = await claimOperatorIdempotency(idempotency);
    const claimResponse = operatorIdempotencyResponse(c, idempotency);
    if (claimResponse) return claimResponse;

    const policy = await evaluateOperatorTransferPolicy({
      tenantId,
      agentId,
      rail: "withdraw",
      idempotencyKey: body.idempotencyKey,
      destination,
      amountBaseUnits,
    });
    if (!policy.approved) {
      await idempotency.release?.();
      await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.policy-rejected", {
        venue,
        walletAddress,
        destination,
        reason: policy.reason,
      });
      return c.json({ code: "policy-violation", reason: policy.reason }, 400);
    }

    const adapter = buildAdapter(tenantId, agentId, walletAddress);

    // Signing is local (nothing reaches the venue), so a sign failure is safe to
    // retry and is NOT stored; a submit failure means the withdraw may have
    // landed, so the ambiguous outcome IS stored and retries replay it (mirrors
    // the HL order route's 502 "status unknown" envelope).
    let signedWithdraw: Awaited<ReturnType<HyperliquidAdapter["signWithdraw"]>>;
    try {
      signedWithdraw = await adapter.signWithdraw({ amount, destination });
    } catch (err) {
      await releaseOperatorTransfer(tenantId, agentId, policy.reservationId, idempotency);
      try {
        await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.failed", {
          venue,
          walletAddress,
          destination,
          amount,
          ...redactedThrownDiagnostics(err),
        });
      } catch (auditErr) {
        console.error(
          "[operator-recovery] withdraw sign-failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      }
      return c.json<ApiResponse>({ ok: false, error: "Failed to sign withdraw" }, 502);
    }

    let result: unknown;
    try {
      result = await adapter.submitWithdraw(signedWithdraw);
    } catch (err) {
      const definitelyRejected = isDefiniteVenueRejection(err);
      if (definitelyRejected) {
        await releaseOperatorTransfer(tenantId, agentId, policy.reservationId, idempotency);
      }
      const errorBody = { ok: false as const, error: "Failed to submit withdraw" };
      if (!definitelyRejected) await idempotency.storeFailure?.(errorBody);
      try {
        await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.failed", {
          venue,
          walletAddress,
          destination,
          amount,
          definiteRejection: definitelyRejected,
          ...redactedThrownDiagnostics(err),
        });
      } catch (auditErr) {
        console.error(
          "[operator-recovery] withdraw submit-failure audit failed",
          redactedThrownDiagnostics(auditErr),
        );
      }
      return c.json<ApiResponse>(errorBody, 502);
    }

    await auditRecoveryEvent(c, tenantId, agentId, "trade.recovery.withdraw.submitted", {
      venue,
      walletAddress,
      destination,
      amount,
    });
    await finishOperatorReservation(tenantId, agentId, policy.reservationId, "final");

    const response = { venue, walletAddress, destination, amount, result };
    await idempotency.store?.(response);
    return c.json<ApiResponse>({ ok: true, data: response });
  });

  return operatorRecoveryRoutes;
}

/**
 * trade.ts — trade-session management + venue order routes (Hyperliquid +
 * Polymarket).
 *
 * MOVED from `@stwd/api` (packages/api/src/routes/trade.ts) into the opt-in
 * trading plugin. behavior is IDENTICAL to the pre-move route: every endpoint,
 * auth check, policy evaluation, audit event, idempotency rule, and error
 * response is preserved. the only structural change is that the core services
 * this route used to import from `../services/context`, `../services/audit`,
 * `../services/agent-token-status`, and `../middleware/redis` are now INJECTED
 * via the plugin context (`StewardAppContext`), so this file does not import
 * `@stwd/api` (no circular dependency: the core does not import the plugin and
 * the plugin does not import the core).
 *
 * `createTradeRoutes(ctx)` returns the hono router the plugin mounts at
 * /trade + /v1/trade.
 */

import { agentPolicies, eq, getDb, proxyAuditLog } from "@stwd/db";
import { evaluateTradeOrder } from "@stwd/policy-engine";
import { checkRateLimit } from "@stwd/redis";
import type { ApiResponse, AppVariables } from "@stwd/shared";
import { type TradeSession, TradeSessionManager } from "@stwd/trade-sessions";
import {
  getMarketableLimitPx,
  HyperliquidAdapter,
  type HyperliquidOrder,
  hyperliquidAssetSchema,
  isBuilderPerpSymbol,
} from "@stwd/venue-hyperliquid";
import {
  clobApiCredentialsSchema,
  deriveApiCredentials,
  type EthersSignerLike,
  isPolymarketPostNotAttempted,
  isPolymarketUnauthorized,
  POLY_EOA_SIGNATURE_TYPE,
  POLY_GNOSIS_SAFE_SIGNATURE_TYPE,
  type PolymarketAccount,
  PolymarketExecutionAdapter,
  type PolymarketOrderRequest,
  resolveBuilderConfig,
} from "@stwd/venue-polymarket";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import type { StewardAppContext } from "../context";

// Prediction-market session asset: pm:<tokenId> (a single outcome token) or
// pm:cond:<conditionId> (a whole market). Mirrors @stwd/trade-sessions'
// predictionMarketAssetSchema so a Polymarket session can be created through the
// public route (not just seeded out of band).
const sessionPredictionMarketAssetSchema = z
  .string()
  .regex(/^pm:(cond:0x[0-9a-fA-F]{1,64}|[0-9]{1,128})$/);

const createSessionSchema = z
  .object({
    agentId: z.string().min(1).optional(),
    venue: z.enum(["hyperliquid", "polymarket"]).default("hyperliquid"),
    walletAddress: z.string().min(1).optional(),
    dailyCap: z.number().positive().max(50_000).default(300),
    perOrderCap: z.number().positive().max(10_000).default(100),
    // Leverage is a perp concept; Polymarket has none. It defaults and is
    // ignored for polymarket sessions (kept for HL compatibility).
    leverageCap: z.number().positive().max(50).default(5),
    // HL assets (BTC/ETH/...) OR prediction-market identifiers (pm:<...>). The
    // venue-appropriate subset is validated in the handler. Optional so the
    // per-venue default below applies.
    allowedAssets: z
      .array(z.union([hyperliquidAssetSchema, sessionPredictionMarketAssetSchema]))
      .min(1)
      .optional(),
    ttlSeconds: z.number().int().positive().max(86_400).default(3_600),
  })
  .transform((data) => ({
    ...data,
    // Default allowlist per venue: HL gets the majors; polymarket has no sensible
    // default market, so it must be supplied explicitly (empty -> handler 400).
    allowedAssets:
      data.allowedAssets ?? (data.venue === "hyperliquid" ? ["BTC", "ETH", "BNB"] : []),
  }));

const submitOrderSchema = z
  .object({
    sessionId: z.string().min(1),
    coin: hyperliquidAssetSchema.optional(),
    asset: hyperliquidAssetSchema.optional(),
    side: z.enum(["buy", "sell"]),
    size: z.number().positive(),
    limitPx: z.union([z.string(), z.number()]).optional(),
    limitPrice: z.union([z.string(), z.number()]).optional(),
    // No max here: the policy engine (`evaluateTradeOrder`) is the source of
    // truth for leverage caps. Schema-level rejection would short-circuit the
    // policy audit trail.
    leverage: z.number().positive().default(1),
    reduceOnly: z.boolean().default(false),
    // Time-in-force for limit orders. Default Ioc (immediate-or-cancel) keeps
    // existing marketable-order behavior; Gtc lets callers REST a resting
    // take-profit/limit order (e.g. a reduce-only sell above market that must
    // not cross the book); Alo = post-only.
    orderType: z
      .object({ limit: z.object({ tif: z.enum(["Alo", "Ioc", "Gtc"]) }).optional() })
      .optional(),
    idempotencyKey: z.string().min(1).max(256).optional(),
  })
  .refine((value) => value.coin ?? value.asset, "coin is required");

type SubmitOrderBody = z.infer<typeof submitOrderSchema>;
const hyperliquidOrderSchema = z.object({
  asset: hyperliquidAssetSchema,
  side: z.enum(["buy", "sell"]),
  size: z.number().positive(),
  limitPx: z.union([z.string(), z.number()]),
  leverage: z.number().int().positive().default(1),
  reduceOnly: z.boolean().default(false),
  orderType: z
    .object({ limit: z.object({ tif: z.enum(["Alo", "Ioc", "Gtc"]) }).optional() })
    .optional(),
});

type TradeIdempotencyResponse = {
  status: 200 | 400 | 403 | 409 | 502;
  body: ApiResponse<unknown> | { code: string; reason: string };
  headers?: Record<string, string>;
};

const pmSubmitOrderSchema = z.object({
  sessionId: z.string().min(1),
  // CLOB token id — the executable unit (a long numeric string).
  tokenId: z.string().regex(/^[0-9]{1,128}$/, "tokenId must be a numeric string"),
  // Optional condition id — when allowlisted as pm:cond:<id> it grants the whole
  // market (both YES/NO outcomes) without a per-token entry.
  conditionId: z
    .string()
    .regex(/^0x[0-9a-fA-F]{1,64}$/, "conditionId must be a 0x-hex string")
    .optional(),
  side: z.enum(["buy", "sell"]),
  // BUY: amount is USD notional to spend. SELL: amount is shares.
  amount: z.union([z.string(), z.number()]),
  // Limit price in (0,1).
  price: z.union([z.string(), z.number()]),
  tickSize: z.enum(["0.1", "0.01", "0.001", "0.0001"]).optional(),
  negRisk: z.boolean().optional(),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

type PmSubmitOrderBody = z.infer<typeof pmSubmitOrderSchema>;

/**
 * Build the trade router, closing over the injected core context. Every helper
 * + route that used a core service (db, vault, redis, audit, token status) reads
 * it from `ctx` here instead of importing it from `@stwd/api`.
 */
export function createTradeRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const {
    db,
    vault,
    ensureAgentForTenant,
    safeJsonParse,
    writeAuditEvent,
    getAgentTokenStatus,
    getRedisClient,
  } = ctx;

  const tradeRoutes = new Hono<{ Variables: AppVariables }>();

  const memoryRateLimit = new Map<string, { count: number; resetAt: number }>();
  const memoryIdempotency = new Map<
    string,
    { bodyHash: string; response: TradeIdempotencyResponse; expiresAt: number }
  >();
  const pmMemoryIdempotency = new Map<
    string,
    { bodyHash: string; response: TradeIdempotencyResponse; expiresAt: number }
  >();

  function getSessionManager(): TradeSessionManager {
    return new TradeSessionManager({ redis: getRedisClient() });
  }

  function callerAgentId(c: Context<{ Variables: AppVariables }>): string | null {
    return c.get("agentScope") ?? null;
  }

  function controlPlaneAuditActor(c: Context<{ Variables: AppVariables }>): {
    actorType: "user" | "api-key";
    actorId: string;
  } {
    if (c.get("authType") === "api-key") {
      return { actorType: "api-key", actorId: c.get("tenantId") ?? "api-key" };
    }
    return { actorType: "user", actorId: c.get("userId") ?? c.get("authType") ?? "session-jwt" };
  }

  function canManageTradeSession(c: Context<{ Variables: AppVariables }>): boolean {
    const authType = c.get("authType");
    if (authType === "api-key") return true;
    return (
      authType === "session-jwt" &&
      (c.get("tenantRole") === "owner" || c.get("tenantRole") === "admin")
    );
  }

  // An agent's own bearer (authType "agent-token", carrying agentScope) may
  // open/read/revoke a trade session FOR ITSELF only. This is the autonomous-agent
  // path: the order route already accepts agent-token, and session creation
  // already clamps every requested cap to the agent's stored agent_policies
  // ceilings (reject-if-over, then Math.min, plus asset/venue allowlist), so an
  // agent self-session can never exceed the caps a human set out-of-band in
  // agent_policies. Cross-agent management still requires a human owner/admin
  // session. No withdraw surface is touched here.
  function canAgentSelfManageSession(
    c: Context<{ Variables: AppVariables }>,
    targetAgentId: string | null | undefined,
  ): boolean {
    if (c.get("authType") !== "agent-token") return false;
    const scoped = callerAgentId(c);
    return Boolean(scoped) && scoped === targetAgentId;
  }

  function responseData<T>(data: T): ApiResponse<T> {
    return { ok: true, data };
  }

  function canAccessAgent(c: Context<{ Variables: AppVariables }>, agentId: string): boolean {
    const scopedAgent = callerAgentId(c);
    return !scopedAgent || scopedAgent === agentId;
  }

  function hasOwnBodyValue(body: unknown, key: string): boolean {
    return typeof body === "object" && body !== null && Object.hasOwn(body, key);
  }

  function policyViolation(message: string) {
    return { code: "policy-violation", message };
  }

  async function auditTradeEvent(
    tenantId: string,
    agentId: string,
    event:
      | "trade.session.created"
      | "trade.session.revoked"
      | "trade.order.submitted"
      | "trade.order.submit.authorized"
      | "trade.order.leverage.set"
      | "trade.order.leverage.failed"
      | "trade.order.policy-rejected"
      | "trade.order.builder.stamped"
      | "trade.builder.approved"
      | "trade.order.canceled",
    details: Record<string, unknown>,
    actor: { actorType: "agent" | "user" | "api-key"; actorId: string } = {
      actorType: "agent",
      actorId: agentId,
    },
  ): Promise<void> {
    const correlationId = typeof details.sessionId === "string" ? details.sessionId : undefined;
    await writeAuditEvent({
      tenantId,
      actorType: actor.actorType,
      actorId: actor.actorId,
      action: event,
      resourceType: "trade",
      resourceId: correlationId ?? agentId,
      metadata: { ...details, correlationId },
      requestId: correlationId,
    });
    await db
      .insert(proxyAuditLog)
      .values({
        tenantId,
        agentId,
        targetHost: event,
        targetPath: JSON.stringify(details),
        method: "AUDIT",
        statusCode: 200,
        latencyMs: 0,
        reason: event,
      })
      .catch(() => undefined);
  }

  function hashBody(body: unknown): string {
    return JSON.stringify(body);
  }

  async function enforceOrderRateLimit(
    agentId: string,
  ): Promise<{ allowed: boolean; resetMs: number }> {
    const redis = getRedisClient();
    if (redis) {
      const result = await checkRateLimit(`ratelimit:trade:hyperliquid:${agentId}:1000`, 1000, 10);
      return { allowed: result.allowed, resetMs: result.resetMs };
    }

    const now = Date.now();
    const current = memoryRateLimit.get(agentId);
    if (!current || current.resetAt <= now) {
      memoryRateLimit.set(agentId, { count: 1, resetAt: now + 1000 });
      return { allowed: true, resetMs: 1000 };
    }
    if (current.count >= 10) return { allowed: false, resetMs: current.resetAt - now };
    current.count += 1;
    return { allowed: true, resetMs: current.resetAt - now };
  }

  function getIdempotency(
    tenantId: string,
    agentId: string,
    key: string | undefined,
    body: SubmitOrderBody,
  ): {
    conflict?: boolean;
    response?: TradeIdempotencyResponse;
    store?: (response: TradeIdempotencyResponse) => void;
  } {
    if (!key) return {};
    const now = Date.now();
    const mapKey = `${tenantId}:${agentId}:${key}`;
    const bodyHash = hashBody({ ...body, idempotencyKey: undefined });
    const existing = memoryIdempotency.get(mapKey);
    if (existing && existing.expiresAt > now) {
      if (existing.bodyHash !== bodyHash) return { conflict: true };
      return { response: existing.response };
    }
    return {
      store(response: TradeIdempotencyResponse) {
        memoryIdempotency.set(mapKey, {
          bodyHash,
          response,
          expiresAt: now + 24 * 60 * 60 * 1000,
        });
      },
    };
  }

  async function resolvePolicyLimitPx(
    asset: z.infer<typeof hyperliquidAssetSchema>,
    side: "buy" | "sell",
    limitPx: string | number | undefined,
  ): Promise<string | number> {
    // Respect a caller-supplied limit price for BOTH sides. Previously the sell
    // branch ignored `limitPx` entirely and always returned a MARKETABLE price,
    // so a resting limit-sell ABOVE market (e.g. a breakeven take-profit) executed
    // immediately at the bid instead of resting. A provided limitPx is the caller's
    // intent for the ORDER price — use it; only synthesize a marketable price when
    // none is given. NOTE: this is the ORDER price; policy NOTIONAL sizing must be
    // computed separately via resolveSizingPx (a low sell limit must NOT understate
    // the notional for cap enforcement).
    if (limitPx !== undefined && limitPx !== null && limitPx !== "") return limitPx;
    if (side !== "sell") return getMarketableLimitPx(asset, true);
    try {
      return await getMarketableLimitPx(asset, false);
    } catch (error) {
      const response = await fetch("https://api.hyperliquid.xyz/info");
      const prices = (await response.json()) as Record<string, unknown>;
      const livePx = Number(prices[asset]);
      if (Number.isFinite(livePx) && livePx > 0) return livePx;
      throw error;
    }
  }

  /**
   * Price used for POLICY NOTIONAL sizing (per-order + daily USD caps). Distinct
   * from the order price.
   *
   * SELL: a caller could pass an arbitrarily LOW sell limit (which Hyperliquid
   * treats as marketable and fills near the bid) to understate notional + bypass
   * caps. So a sell's sizing price is max(orderPx, marketPx). If the market price
   * can't be fetched we FAIL CLOSED (throw) rather than trust the caller's limit.
   *
   * BUY: a buy can never fill ABOVE its limit, so the caller's buy limit already
   * bounds the max notional. Use it directly (don't floor at market — that would
   * over-estimate a resting buy below market and could falsely trip caps).
   */
  async function resolveSizingPx(
    asset: z.infer<typeof hyperliquidAssetSchema>,
    side: "buy" | "sell",
    orderPx: string | number,
  ): Promise<number> {
    const orderPxNum = Number(orderPx);
    if (side === "buy") {
      if (Number.isFinite(orderPxNum) && orderPxNum > 0) return orderPxNum;
      // No usable buy limit — fall back to market for sizing.
    }
    let marketPx = Number.NaN;
    try {
      marketPx = Number(await getMarketableLimitPx(asset, side === "buy"));
    } catch {
      try {
        // HL /info requires a POST with a typed body; allMids returns {asset: px}.
        const response = await fetch("https://api.hyperliquid.xyz/info", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: "allMids" }),
        });
        const prices = (await response.json()) as Record<string, unknown>;
        marketPx = Number(prices[asset]);
      } catch {
        marketPx = Number.NaN;
      }
    }
    if (side === "sell" && !(Number.isFinite(marketPx) && marketPx > 0)) {
      // FAIL CLOSED: cannot size a sell without a trusted market price.
      throw new Error("unable to resolve market price for sell notional sizing");
    }
    const candidates = [orderPxNum, marketPx].filter((n) => Number.isFinite(n) && n > 0);
    if (candidates.length === 0) {
      throw new Error("unable to resolve a notional sizing price");
    }
    return Math.max(...candidates);
  }

  function tradeReplayResponse(
    c: Context<{ Variables: AppVariables }>,
    envelope: TradeIdempotencyResponse,
  ) {
    const replay = { headers: { "Idempotency-Replayed": "true" } };
    for (const [name, value] of Object.entries({
      ...envelope.headers,
      ...replay.headers,
    })) {
      c.header(name, value);
    }
    return c.json(envelope.body, envelope.status);
  }

  async function completeTradeIdempotencyBestEffort(
    idempotency: ReturnType<typeof getIdempotency>,
    envelope: TradeIdempotencyResponse,
  ): Promise<void> {
    try {
      idempotency.store?.(envelope);
    } catch {
      // Idempotency replay is best effort for this in-memory fallback path.
    }
  }

  async function resolveHyperliquidWallet(
    agentId: string,
    agent: { walletAddress: string; walletAddresses?: { evm?: string } },
  ): Promise<string | null> {
    if ("getWallet" in vault && typeof vault.getWallet === "function") {
      try {
        const wallet = await vault.getWallet({ agentId, venue: "hyperliquid" });
        return wallet.address;
      } catch {
        return null;
      }
    }
    return (
      agent.walletAddresses?.evm ??
      (agent.walletAddress.startsWith("0x") ? agent.walletAddress : null)
    );
  }

  // Resolve the agent's polymarket venue wallet address for session creation. The
  // session binds to this address (walletId); the per-order route separately
  // resolves the same wallet + its funder Safe + L2 creds at submit time.
  async function resolvePolymarketWallet(agentId: string): Promise<string | null> {
    try {
      const wallet = await vault.getWallet({ agentId, venue: "polymarket" });
      return wallet.address;
    } catch {
      return null;
    }
  }

  tradeRoutes.get("/token-status", async (c) => {
    const agentId = c.req.query("agentId")?.trim();
    if (!agentId) {
      return c.json<ApiResponse>({ ok: false, error: "agentId is required" }, 400);
    }

    const status = await getAgentTokenStatus(agentId);
    if (!status) {
      return c.json(
        responseData({
          agentId,
          status: "unknown" as const,
          exp: null,
          observedAt: null,
          expiresInSeconds: null,
        }),
      );
    }

    return c.json(
      responseData({
        agentId,
        status: "observed" as const,
        exp: status.exp,
        observedAt: status.observedAt,
        expiresInSeconds: status.exp - Math.floor(Date.now() / 1000),
      }),
    );
  });

  tradeRoutes.post("/sessions", async (c) => {
    const tenantId = c.get("tenantId");
    const raw = await safeJsonParse(c);
    const parsed = createSessionSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }

    const scopedAgentId = callerAgentId(c);
    const agentId = parsed.data.agentId ?? scopedAgentId;
    if (!agentId) {
      return c.json<ApiResponse>({ ok: false, error: "Agent id required" }, 400);
    }
    const createByHumanAdmin = canManageTradeSession(c);
    const createByAgentSelf = canAgentSelfManageSession(c, agentId);
    if (!createByHumanAdmin && !createByAgentSelf) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: insufficient access to create a session for this agent" },
        403,
      );
    }
    // MFA recency is a human-session protection. The agent-self path has no human
    // session to MFA; its protection is the agent_policies cap clamp below + the
    // per-order policy evaluation on submission. Only enforce MFA on the human path.
    if (
      c.get("authType") === "session-jwt" &&
      createByHumanAdmin &&
      !c.get("sessionMfaVerifiedAt")
    ) {
      return c.json<ApiResponse>(
        { ok: false, error: "Trade session management requires recent MFA verification" },
        403,
      );
    }
    const { venue, dailyCap, perOrderCap, leverageCap, allowedAssets, ttlSeconds } = parsed.data;
    const isPolymarket = venue === "polymarket";

    if (!canAccessAgent(c, agentId)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: agent token cannot create sessions for another agent" },
        403,
      );
    }
    if (perOrderCap > dailyCap) {
      return c.json<ApiResponse>({ ok: false, error: "perOrderCap cannot exceed dailyCap" }, 400);
    }
    // Polymarket has no default market; the allowlist must be supplied. Also reject
    // a venue/asset namespace mismatch up front (pm: assets on HL or vice versa).
    if (isPolymarket) {
      if (allowedAssets.length === 0) {
        return c.json<ApiResponse>(
          { ok: false, error: "polymarket sessions require an explicit allowedAssets (pm:<...>)" },
          400,
        );
      }
      const nonPmAsset = allowedAssets.find((a) => !a.startsWith("pm:"));
      if (nonPmAsset) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: `polymarket session asset must be a pm: identifier, got ${nonPmAsset}`,
          },
          400,
        );
      }
    } else {
      const pmAsset = allowedAssets.find((a) => a.startsWith("pm:"));
      if (pmAsset) {
        return c.json<ApiResponse>(
          {
            ok: false,
            error: `hyperliquid session cannot allowlist a prediction market ${pmAsset}`,
          },
          400,
        );
      }
    }

    const agent = await ensureAgentForTenant(tenantId, agentId);
    if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

    const [agentPolicy] = await getDb()
      .select()
      .from(agentPolicies)
      .where(eq(agentPolicies.agentId, agentId));

    // Fail-closed for the autonomous agent-self path: an agent may only open a
    // session if a human has set an agent_policies row defining its ceilings.
    // Without a policy there is nothing to clamp against, so a policy-less agent
    // could otherwise self-grant caps up to the schema maximums. A human
    // owner/admin may still create sessions for a policy-less agent (a deliberate
    // human act); an agent cannot self-authorize without an explicit policy.
    if (createByAgentSelf && !createByHumanAdmin && !agentPolicy) {
      return c.json(
        policyViolation(
          "agent has no trade policy; a human must set agent caps before self-service trading",
        ),
        403,
      );
    }

    let sessionDailyCap = dailyCap;
    let sessionPerOrderCap = perOrderCap;
    let sessionLeverageCap = leverageCap;
    let sessionAllowedAssets = allowedAssets;

    if (agentPolicy) {
      if (agentPolicy.tenantId !== tenantId) {
        return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
      }

      const policyDailyCap = Number(agentPolicy.dailyCapUsd);
      const policyPerOrderCap = Number(agentPolicy.perOrderCapUsd);
      const policyLeverageCap = Number(agentPolicy.leverageCap);
      // Builder-perp gating is Hyperliquid-only (isBuilderPerpSymbol matches HL
      // namespaced perps, never pm: assets).
      const requestedBuilderAsset = isPolymarket
        ? undefined
        : allowedAssets.find((asset) => isBuilderPerpSymbol(asset));
      if (requestedBuilderAsset && !agentPolicy.allowBuilderPerps) {
        return c.json(
          policyViolation(
            `builder perp ${requestedBuilderAsset} requires allowBuilderPerps in agent policy`,
          ),
          400,
        );
      }

      if (hasOwnBodyValue(raw, "dailyCap") && dailyCap > policyDailyCap) {
        return c.json(
          policyViolation(`session cap ${dailyCap} exceeds agent policy cap ${policyDailyCap}`),
          400,
        );
      }
      if (hasOwnBodyValue(raw, "perOrderCap") && perOrderCap > policyPerOrderCap) {
        return c.json(
          policyViolation(
            `session cap ${perOrderCap} exceeds agent policy cap ${policyPerOrderCap}`,
          ),
          400,
        );
      }
      if (hasOwnBodyValue(raw, "leverageCap") && leverageCap > policyLeverageCap) {
        return c.json(
          policyViolation(
            `session cap ${leverageCap} exceeds agent policy cap ${policyLeverageCap}`,
          ),
          400,
        );
      }
      if (!agentPolicy.allowedVenues.includes(venue)) {
        return c.json(policyViolation(`venue ${venue} is not allowed by agent policy`), 400);
      }
      // The agent-policy asset allowlist is the human-controlled ceiling and gates
      // EVERY venue's markets — HL symbols (BTC/ETH/...) AND prediction markets
      // (pm:<tokenId>/pm:cond:<id>) live together in the same agent_policies
      // allowedAssets text[]. Apply it to polymarket too: without this, an agent
      // whose policy merely lists `polymarket` in allowedVenues could self-grant a
      // session for ANY pm: market and then pass the per-order session gate (the
      // session allowlist IS the gate). The human must explicitly approve each pm:
      // market in the policy, exactly as they approve HL symbols.
      const disallowedAsset = allowedAssets.find(
        (asset) => !agentPolicy.allowedAssets.includes(asset),
      );
      if (disallowedAsset) {
        return c.json(
          policyViolation(`asset ${disallowedAsset} is not allowed by agent policy`),
          400,
        );
      }

      sessionDailyCap = Math.min(dailyCap, policyDailyCap);
      sessionPerOrderCap = Math.min(perOrderCap, policyPerOrderCap);
      sessionLeverageCap = Math.min(leverageCap, policyLeverageCap);
      sessionAllowedAssets = allowedAssets.filter((asset) =>
        agentPolicy.allowedAssets.includes(asset),
      );
    } else if (!isPolymarket) {
      const requestedBuilderAsset = allowedAssets.find((asset) => isBuilderPerpSymbol(asset));
      if (requestedBuilderAsset) {
        return c.json(
          policyViolation(
            `builder perp ${requestedBuilderAsset} requires an agent policy with allowBuilderPerps`,
          ),
          400,
        );
      }
    }

    const venueWallet = isPolymarket
      ? await resolvePolymarketWallet(agentId)
      : await resolveHyperliquidWallet(agentId, agent);
    // Polymarket order execution resolves creds strictly via the venue-scoped
    // wallet (vault.getWallet({venue:"polymarket"})). Allowing a caller-supplied
    // walletAddress fallback here would mint a session that can never execute
    // (order route would 409 wallet-not-found). Fail closed for polymarket.
    const walletAddress = isPolymarket ? venueWallet : (venueWallet ?? parsed.data.walletAddress);
    if (!walletAddress) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `${venue} venue wallet not found. Create a venue-scoped wallet before trading.`,
        },
        404,
      );
    }

    const auditActor = controlPlaneAuditActor(c);
    await writeAuditEvent({
      tenantId,
      actorType: auditActor.actorType,
      actorId: auditActor.actorId,
      action: "trade.session.create.authorized",
      resourceType: "trade",
      resourceId: agentId,
      metadata: { venue, agentId, walletAddress },
    });

    const sessionManager = getSessionManager();
    const session = await sessionManager.createSession({
      agentId,
      tenantId,
      venue,
      walletId: walletAddress,
      dailyCapUsd: sessionDailyCap,
      perOrderCapUsd: sessionPerOrderCap,
      leverageCap: sessionLeverageCap,
      allowedAssets: sessionAllowedAssets,
      ttlSeconds,
    });

    try {
      await writeAuditEvent({
        tenantId,
        actorType: auditActor.actorType,
        actorId: auditActor.actorId,
        action: "trade.session.created",
        resourceType: "trade",
        resourceId: session.id,
        metadata: {
          sessionId: session.id,
          venue: session.venue,
          walletId: session.walletId,
          dailyCapUsd: session.dailyCapUsd,
          perOrderCapUsd: session.perOrderCapUsd,
          leverageCap: session.leverageCap,
          allowedAssets: session.allowedAssets,
        },
        requestId: session.id,
      });
    } catch (error) {
      await sessionManager.deleteSession({ tenantId, id: session.id });
      throw error;
    }

    return c.json(
      responseData({
        sessionId: session.id,
        expiresAt: session.expiresAt.toISOString(),
      }),
      201,
    );
  });

  tradeRoutes.get("/sessions/:id", async (c) => {
    const tenantId = c.get("tenantId");
    const session = await getSessionManager().getSession({ tenantId, id: c.req.param("id") });
    if (!session) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);
    const readByHumanAdmin = canManageTradeSession(c);
    const readByAgentSelf = canAgentSelfManageSession(c, session.agentId);
    if (!readByHumanAdmin && !readByAgentSelf) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: insufficient access to this session" },
        403,
      );
    }
    if (c.get("authType") === "session-jwt" && readByHumanAdmin && !c.get("sessionMfaVerifiedAt")) {
      return c.json<ApiResponse>(
        { ok: false, error: "Trade session management requires recent MFA verification" },
        403,
      );
    }
    if (!canAccessAgent(c, session.agentId)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: session belongs to another agent" },
        403,
      );
    }

    return c.json(
      responseData({
        ...session,
        createdAt: session.createdAt.toISOString(),
        expiresAt: session.expiresAt.toISOString(),
        revokedAt: session.revokedAt?.toISOString() ?? null,
        remainingCapUsd: Math.max(0, session.dailyCapUsd - session.dailySpendUsd),
      }),
    );
  });

  tradeRoutes.post("/sessions/:id/revoke", async (c) => {
    const tenantId = c.get("tenantId");
    const existing = await getSessionManager().getSession({ tenantId, id: c.req.param("id") });
    const revokeByHumanAdmin = canManageTradeSession(c);
    // Agent-self may revoke only its OWN existing session. If the session is
    // missing we fall through to the human-admin requirement (no agent-self bypass
    // on a non-existent/again-another-agent session).
    const revokeByAgentSelf = Boolean(existing) && canAgentSelfManageSession(c, existing?.agentId);
    if (!revokeByHumanAdmin && !revokeByAgentSelf) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: insufficient access to revoke this session" },
        403,
      );
    }
    if (
      c.get("authType") === "session-jwt" &&
      revokeByHumanAdmin &&
      !c.get("sessionMfaVerifiedAt")
    ) {
      return c.json<ApiResponse>(
        { ok: false, error: "Trade session management requires recent MFA verification" },
        403,
      );
    }
    if (existing && !canAccessAgent(c, existing.agentId)) {
      return c.json<ApiResponse>(
        { ok: false, error: "Forbidden: session belongs to another agent" },
        403,
      );
    }

    const revoked = await getSessionManager().revokeSession({
      id: c.req.param("id"),
      tenantId,
      revokedBy: callerAgentId(c) ?? c.get("userId") ?? c.get("authType") ?? "api-key",
    });
    if (!revoked) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);

    const scopedAgentId = callerAgentId(c);
    const revokeActor = scopedAgentId
      ? { actorType: "agent" as const, actorId: scopedAgentId }
      : controlPlaneAuditActor(c);
    await auditTradeEvent(
      tenantId,
      revoked.agentId,
      "trade.session.revoked",
      {
        sessionId: revoked.id,
        revokedBy: scopedAgentId ?? revokeActor.actorId,
      },
      revokeActor,
    );
    return c.json(
      responseData({
        sessionId: revoked.id,
        revokedAt: (revoked.revokedAt ?? new Date()).toISOString(),
      }),
    );
  });

  tradeRoutes.post("/hyperliquid/order", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = callerAgentId(c);
    if (!agentId) {
      return c.json<ApiResponse>({ ok: false, error: "Agent JWT required for trading" }, 403);
    }

    const rate = await enforceOrderRateLimit(agentId);
    if (!rate.allowed) {
      c.header("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return c.json<ApiResponse>({ ok: false, error: "Trade order rate limit exceeded" }, 429);
    }

    const raw = await safeJsonParse(c);
    const parsed = submitOrderSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey) {
      return c.json<ApiResponse>({ ok: false, error: "Idempotency-Key is required" }, 400);
    }

    const idempotency = getIdempotency(tenantId, agentId, body.idempotencyKey, body);
    if (idempotency.conflict) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency key reused with a different body" },
        409,
      );
    }
    if (idempotency.response) {
      return tradeReplayResponse(c, idempotency.response);
    }

    const session = await getSessionManager().getActive(tenantId, body.sessionId);
    if (!session || session.agentId !== agentId || session.venue !== "hyperliquid") {
      return c.json<ApiResponse>({ ok: false, error: "Active Hyperliquid session required" }, 403);
    }
    const coin = body.coin ?? body.asset;

    // Re-validate against the Hyperliquid adapter's strict asset enum. The
    // session-level allowlist is covered by evaluateTradeOrder; this second check
    // defends the adapter contract if the session ever permits a coin the adapter
    // does not implement.
    const parsedAsset = hyperliquidAssetSchema.safeParse(coin);
    if (!parsedAsset.success) {
      const reason = `asset-allowlist: asset ${coin} is not supported by Hyperliquid adapter`;
      await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
        sessionId: session.id,
        venue: "hyperliquid",
        asset: coin,
        reason,
      });
      return c.json({ code: "policy-violation", reason }, 400);
    }

    const builderPerp = isBuilderPerpSymbol(parsedAsset.data);
    const effectiveLeverage = builderPerp ? Math.min(body.leverage, 3) : body.leverage;

    const sessionPolicy = {
      venue: session.venue,
      allowedVenues: [session.venue],
      leverageCap: session.leverageCap,
      allowedAssets: session.allowedAssets,
      allowBuilderPerps: session.allowedAssets.some((asset) => isBuilderPerpSymbol(asset)),
      dailySpendUsd: session.dailySpendUsd,
      dailyCapUsd: session.dailyCapUsd,
      perOrderCapUsd: session.perOrderCapUsd,
    };
    const orderPolicy = (estimatedOrderUsd: number) =>
      evaluateTradeOrder(sessionPolicy, {
        venue: "hyperliquid",
        asset: coin,
        leverage: effectiveLeverage,
        estimatedOrderUsd,
      });
    const rejectPolicy = async (reason: string, sizeUsd: number, limitPx?: string | number) => {
      await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
        sessionId: session.id,
        venue: "hyperliquid",
        asset: coin,
        leverage: effectiveLeverage,
        requestedLeverage: body.leverage,
        builderPerp,
        size: body.size,
        limitPx,
        sizeUsd,
        dailySpendUsd: session.dailySpendUsd,
        reason,
      });
      return c.json({ code: "policy-violation", reason }, 400);
    };

    const limitPx = body.limitPx ?? body.limitPrice;
    if (
      limitPx !== undefined &&
      (typeof limitPx === "string"
        ? !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(limitPx) || Number(limitPx) <= 0
        : !Number.isFinite(limitPx) || limitPx <= 0)
    ) {
      return c.json<ApiResponse>(
        { ok: false, error: "limitPx must be a positive finite price" },
        400,
      );
    }
    if (limitPx === undefined) {
      const preliminaryPolicy = orderPolicy(0);
      if (!preliminaryPolicy.allow) {
        return rejectPolicy(preliminaryPolicy.reason ?? "order violates trading policy", 0);
      }
    }
    const policyLimitPx = await resolvePolicyLimitPx(parsedAsset.data, body.side, limitPx);
    // Notional for cap enforcement uses a market-floored price so a low sell limit
    // (marketable, fills near the bid) cannot understate notional and bypass caps.
    // resolveSizingPx FAILS CLOSED for sells when no market price is available —
    // map that to a clean policy rejection (not a 500).
    let sizingPx: number;
    try {
      sizingPx = await resolveSizingPx(parsedAsset.data, body.side, policyLimitPx);
    } catch (err) {
      return rejectPolicy(
        err instanceof Error ? err.message : "unable to size order notional",
        0,
        policyLimitPx,
      );
    }
    const sizeUsd = body.size * sizingPx;
    const policy = orderPolicy(sizeUsd);
    if (!policy.allow) {
      return rejectPolicy(policy.reason ?? "order violates trading policy", sizeUsd, policyLimitPx);
    }

    const walletAddress = session.walletId;
    const manager = getSessionManager();
    const fenced = await manager.withActiveSubmissionFence(
      { tenantId, id: session.id },
      async (sessionFromFence?: TradeSession) => {
        const activeSession =
          sessionFromFence ?? (await getSessionManager().getActive(tenantId, session.id));
        if (!activeSession) {
          const envelope: TradeIdempotencyResponse = {
            status: 409,
            body: {
              ok: false,
              error: "Trade session was revoked before order submission",
            },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        const reserved = await getSessionManager().incrementSpend({
          tenantId,
          id: session.id,
          amountUsd: sizeUsd,
        });
        if (!reserved) {
          const envelope: TradeIdempotencyResponse = {
            status: 400,
            body: { ok: false, error: "Trade session cap exceeded" },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        await auditTradeEvent(tenantId, agentId, "trade.order.submit.authorized", {
          sessionId: session.id,
          venue: "hyperliquid",
          asset: parsedAsset.data,
          leverage: effectiveLeverage,
          requestedLeverage: body.leverage,
          builderPerp,
          size: body.size,
          sizeUsd,
        });

        const vaultClient = {
          signTypedData: (input: Omit<Parameters<typeof vault.signTypedData>[0], "tenantId">) =>
            vault.signTypedData({ ...input, tenantId, venue: "hyperliquid" }),
        };
        const adapter = new HyperliquidAdapter(vaultClient, agentId, walletAddress);
        const order: HyperliquidOrder = {
          asset: parsedAsset.data,
          side: body.side,
          size: body.size,
          limitPx: policyLimitPx,
          leverage: effectiveLeverage,
          reduceOnly: body.reduceOnly,
          ...(body.orderType ? { orderType: body.orderType } : {}),
        };
        hyperliquidOrderSchema.safeParse(order);
        if (builderPerp) {
          try {
            await adapter.updateLeverage({
              coin: parsedAsset.data,
              leverage: effectiveLeverage,
              isCross: false,
            });
          } catch (err) {
            // Leverage must be set BEFORE the order or the position opens at the
            // dex default (e.g. 10x). If updateLeverage fails, abort the order and
            // release the reserved session spend so the daily cap isn't consumed
            // for an order that never signed/submitted.
            await getSessionManager().releaseSpend({
              tenantId,
              id: session.id,
              amountUsd: sizeUsd,
            });
            await auditTradeEvent(tenantId, agentId, "trade.order.leverage.failed", {
              sessionId: session.id,
              venue: "hyperliquid",
              asset: parsedAsset.data,
              leverage: effectiveLeverage,
              requestedLeverage: body.leverage,
              isCross: false,
              builderPerp,
              error: err instanceof Error ? err.message : String(err),
            });
            const envelope: TradeIdempotencyResponse = {
              status: 502,
              body: {
                ok: false,
                error: "Failed to set leverage before order; order not submitted",
              },
            };
            idempotency.store?.(envelope);
            return envelope;
          }
          await auditTradeEvent(tenantId, agentId, "trade.order.leverage.set", {
            sessionId: session.id,
            venue: "hyperliquid",
            asset: parsedAsset.data,
            leverage: effectiveLeverage,
            requestedLeverage: body.leverage,
            isCross: false,
            builderPerp,
          });
        }
        const signed = await adapter.signOrder(order);
        const activeAfterSign = await getSessionManager().getActive(tenantId, session.id);
        if (!activeAfterSign) {
          await getSessionManager().releaseSpend({
            tenantId,
            id: session.id,
            amountUsd: sizeUsd,
          });
          const envelope: TradeIdempotencyResponse = {
            status: 409,
            body: {
              ok: false,
              error: "Trade session was revoked before order submission",
            },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        let result: Awaited<ReturnType<HyperliquidAdapter["submitOrder"]>>;
        try {
          result = await adapter.submitOrder(signed);
        } catch {
          const envelope: TradeIdempotencyResponse = {
            status: 502,
            body: { ok: false, error: "Trade submission status unknown" },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        if (result.status === "rejected") {
          await getSessionManager().releaseSpend({
            tenantId,
            id: session.id,
            amountUsd: sizeUsd,
          });
          const envelope: TradeIdempotencyResponse = {
            status: 400,
            body: {
              ok: false,
              error: result.error ?? "Trade order rejected",
              data: { status: result.status },
            },
          };
          await auditTradeEvent(tenantId, agentId, "trade.order.canceled", {
            sessionId: session.id,
            venue: "hyperliquid",
            asset: parsedAsset.data,
            leverage: effectiveLeverage,
            requestedLeverage: body.leverage,
            builderPerp,
            size: body.size,
            sizeUsd,
            orderId: result.orderId ?? null,
            reason: result.error ?? "Trade order rejected",
          });
          idempotency.store?.(envelope);
          return envelope;
        }

        const response = {
          orderId: result.orderId ?? crypto.randomUUID(),
          status: result.status,
          filledQty: result.filledQty ?? 0,
          avgPrice: result.avgPrice ?? 0,
          txHash: result.txHash ?? null,
          builderPerp,
        };
        const envelope: TradeIdempotencyResponse = {
          status: 200,
          body: responseData(response),
        };
        try {
          await auditTradeEvent(tenantId, agentId, "trade.order.submitted", {
            sessionId: session.id,
            venue: "hyperliquid",
            asset: parsedAsset.data,
            leverage: effectiveLeverage,
            requestedLeverage: body.leverage,
            builderPerp,
            size: body.size,
            sizeUsd,
            orderId: response.orderId,
          });
          await completeTradeIdempotencyBestEffort(idempotency, envelope);
          return c.json(responseData(response));
        } catch {
          await completeTradeIdempotencyBestEffort(idempotency, envelope);
          return c.json(responseData(response));
        }
      },
    );

    if (!fenced) {
      const envelope: TradeIdempotencyResponse = {
        status: 409,
        body: { ok: false, error: "Trade session was revoked before order submission" },
      };
      idempotency.store?.(envelope);
      return c.json(envelope.body, envelope.status);
    }
    if (fenced instanceof Response) return fenced;
    return c.json(fenced.body, fenced.status);
  });

  // ===========================================================================
  // POST /v1/trade/polymarket/order
  //
  // Place a Polymarket CLOB order through the rail. Mirrors the Hyperliquid order
  // handler above: agent-JWT guard, order rate-limit, Idempotency-Key (required,
  // conflict 409 + replay), active session fetch + ownership + venue check, the
  // prediction-market policy gate (checkActiveOrder), spend reserve→release-on-
  // failure, the vault→ethers-signer bridge, the venue adapter call, audit events.
  //
  // Phase C creds-provisioning is NOT wired yet: the L2 CLOB apiCredentials +
  // funder Safe are resolved from the agent's polymarket venue wallet. Until
  // provisioning writes them, resolvePolymarketAccount returns null and the route
  // FAILS CLOSED with a typed 409 ("polymarket creds not provisioned"). We never
  // invent credentials.
  // ===========================================================================

  // Idempotency for the Polymarket body shape. Mirrors getIdempotency() but keyed
  // for PmSubmitOrderBody so the two routes never collide on a shared map type.
  function getPmIdempotency(
    tenantId: string,
    agentId: string,
    key: string | undefined,
    body: PmSubmitOrderBody,
  ): {
    conflict?: boolean;
    response?: TradeIdempotencyResponse;
    store?: (response: TradeIdempotencyResponse) => void;
  } {
    if (!key) return {};
    const now = Date.now();
    const mapKey = `${tenantId}:${agentId}:pm:${key}`;
    const bodyHash = hashBody({ ...body, idempotencyKey: undefined });
    const existing = pmMemoryIdempotency.get(mapKey);
    if (existing && existing.expiresAt > now) {
      if (existing.bodyHash !== bodyHash) return { conflict: true };
      return { response: existing.response };
    }
    return {
      store(response: TradeIdempotencyResponse) {
        pmMemoryIdempotency.set(mapKey, {
          bodyHash,
          response,
          expiresAt: now + 24 * 60 * 60 * 1000,
        });
      },
    };
  }

  async function enforcePolymarketOrderRateLimit(
    agentId: string,
  ): Promise<{ allowed: boolean; resetMs: number }> {
    const redis = getRedisClient();
    if (redis) {
      const result = await checkRateLimit(`ratelimit:trade:polymarket:${agentId}:1000`, 1000, 10);
      return { allowed: result.allowed, resetMs: result.resetMs };
    }
    const now = Date.now();
    const current = memoryRateLimit.get(`pm:${agentId}`);
    if (!current || current.resetAt <= now) {
      memoryRateLimit.set(`pm:${agentId}`, { count: 1, resetAt: now + 1000 });
      return { allowed: true, resetMs: 1000 };
    }
    if (current.count >= 10) return { allowed: false, resetMs: current.resetAt - now };
    current.count += 1;
    return { allowed: true, resetMs: current.resetAt - now };
  }

  // Notional USD of a Polymarket order. BUY: amount IS the USD spent. SELL: amount
  // is shares, so notional = shares * price. The policy gate caps on this value.
  function polymarketNotionalUsd(side: "buy" | "sell", amount: number, price: number): number {
    return side === "buy" ? amount : amount * price;
  }

  // Map a structured checkOrderAllowed reason to its HTTP status. Allowlist/cap
  // rejections are client errors (400); a non-active session is a 403 (mirrors the
  // HL "Active session required" 403).
  function pmPolicyRejectStatus(reason: string): 400 | 403 {
    return reason === "session-not-active" ? 403 : 400;
  }

  /**
   * Resolved Polymarket credentials for an agent, or a typed reason why they could
   * not be resolved. The route FAILS CLOSED on any non-ok result.
   */
  type PolymarketCredsResolution =
    | {
        ok: true;
        apiCredentials: PolymarketAccount["apiCredentials"];
        funderAddress: string;
        walletAddress: string;
        signatureType: number;
      }
    | { ok: false; reason: "wallet-not-found" | "creds-not-provisioned" | "derive-failed" };

  // L2 CLOB creds are derived from the L1 delegate signer and cached. They are
  // SECRET; cache them only in Redis with a TTL (never in the DB here). The same
  // signer deterministically yields the same creds, so a cache miss safely
  // re-derives. TTL bounds exposure + tolerates a CLOB key rotation.
  const PM_CREDS_CACHE_TTL_SECONDS = 6 * 60 * 60; // 6h
  function pmCredsCacheKey(tenantId: string, agentId: string, walletAddress: string): string {
    return `pm:clob-l2:${tenantId}:${agentId}:${walletAddress.toLowerCase()}`;
  }

  /**
   * Invalidate cached L2 CLOB creds so the NEXT order re-derives from L1. Called
   * when the venue returns 401 (the cached creds were rotated/revoked CLOB-side).
   * Best-effort; the current request still fails, the next self-heals.
   */
  async function invalidatePolymarketCredsCache(
    tenantId: string,
    agentId: string,
    walletAddress: string,
  ): Promise<void> {
    const redis = getRedisClient();
    if (!redis) return;
    await redis.del(pmCredsCacheKey(tenantId, agentId, walletAddress)).catch(() => 0);
  }

  async function resolvePolymarketCreds(
    tenantId: string,
    agentId: string,
  ): Promise<PolymarketCredsResolution> {
    // 1) Venue wallet (the L1 delegate signer address + optional funder Safe).
    let walletAddress: string;
    let funderMeta: string | undefined;
    try {
      const wallet = await vault.getWallet({ agentId, venue: "polymarket" });
      walletAddress = wallet.address;
      const meta = wallet.metadata as { funderAddress?: unknown } | undefined;
      funderMeta = typeof meta?.funderAddress === "string" ? meta.funderAddress : undefined;
    } catch {
      return { ok: false, reason: "wallet-not-found" };
    }

    // Funder + signatureType:
    //  - If a funder Safe is recorded in wallet metadata → sigType 2 (Safe funder).
    //  - Else (v1) the delegate EOA is its own funder → sigType 0 (EOA holds USDC).
    const funderAddress = funderMeta ?? walletAddress;
    const signatureType = funderMeta ? POLY_GNOSIS_SAFE_SIGNATURE_TYPE : POLY_EOA_SIGNATURE_TYPE;

    // 2) L2 CLOB apiCredentials. Test-only deterministic seam first (inert in prod).
    if (process.env.STEWARD_PM_TEST_CREDS === "1") {
      return {
        ok: true,
        apiCredentials: { key: "test-key", secret: "test-secret", passphrase: "test-pass" },
        funderAddress,
        walletAddress,
        signatureType,
      };
    }

    // 2a) Redis cache.
    const redis = getRedisClient();
    const cacheKey = pmCredsCacheKey(tenantId, agentId, walletAddress);
    if (redis) {
      try {
        const cached = await redis.get(cacheKey);
        if (cached) {
          const parsed = clobApiCredentialsSchema.safeParse(JSON.parse(cached));
          if (parsed.success) {
            return {
              ok: true,
              apiCredentials: parsed.data,
              funderAddress,
              walletAddress,
              signatureType,
            };
          }
        }
      } catch {
        // cache read failure is non-fatal — fall through to derive.
      }
    }

    // 2b) Derive L2 creds from the L1 delegate signer (idempotent), then cache.
    let apiCredentials: PolymarketAccount["apiCredentials"];
    try {
      const signer = buildPolymarketVaultSigner(tenantId, agentId, walletAddress);
      apiCredentials = await deriveApiCredentials(signer);
    } catch {
      return { ok: false, reason: "derive-failed" };
    }
    if (redis) {
      await redis
        .setex(cacheKey, PM_CREDS_CACHE_TTL_SECONDS, JSON.stringify(apiCredentials))
        .catch(() => undefined);
    }

    return { ok: true, apiCredentials, funderAddress, walletAddress, signatureType };
  }

  /**
   * The vault→ethers-signer bridge.
   *
   * @stwd/venue-polymarket's clob-client needs an `EthersSignerLike` delegate that
   * exposes `_signTypedData(domain, types, value)` (ethers v5) + `getAddress()`.
   * The steward vault signs EIP-712 typed data via
   * `vault.signTypedData({ tenantId, venue, agentId, domain, types, primaryType,
   * value })` and returns a hex signature string — a different method shape.
   *
   * This wraps the vault into the EthersSignerLike the venue package expects:
   *   - `_signTypedData(domain, types, value)` derives the EIP-712 primaryType
   *     from the types map (the single non-`EIP712Domain` key — Polymarket's CTF
   *     exchange order is a single-struct payload) and delegates to
   *     vault.signTypedData with the polymarket venue scope, so the key never
   *     leaves the vault.
   *   - `getAddress()` / `.address` returns the agent's resolved polymarket wallet
   *     address.
   */
  function buildPolymarketVaultSigner(
    tenantId: string,
    agentId: string,
    walletAddress: string,
  ): EthersSignerLike {
    const _signTypedData = async (...args: unknown[]): Promise<string> => {
      const [domain, types, value] = args as [
        Record<string, unknown>,
        Record<string, Array<{ name: string; type: string }>>,
        Record<string, unknown>,
      ];
      // ethers' _signTypedData omits the EIP712Domain entry from `types`; the
      // single remaining struct is the primaryType (the order). Pick it out so we
      // can hand vault.signTypedData a fully-specified EIP-712 request.
      const primaryType =
        Object.keys(types).find((name) => name !== "EIP712Domain") ?? Object.keys(types)[0];
      return vault.signTypedData({
        tenantId,
        venue: "polymarket",
        agentId,
        domain: domain as Parameters<typeof vault.signTypedData>[0]["domain"],
        types: types as Parameters<typeof vault.signTypedData>[0]["types"],
        primaryType,
        value: value as Record<string, unknown>,
      });
    };

    // createOrDeriveApiKey's L1 auth + order signing both use _signTypedData
    // (ClobAuth / order EIP-712), which we scope to venue:"polymarket" so the
    // signature recovers to walletAddress. We intentionally do NOT expose
    // signMessage: vault.signMessage signs with the agent's DEFAULT (null-venue)
    // EVM key, which would NOT recover to the venue-scoped polymarket wallet and
    // would silently break derivation/submission for agents whose polymarket
    // wallet differs from their default. If a clob-client path ever requires
    // personal-sign, add a venue-scoped vault.signMessage overload first.
    return {
      address: walletAddress,
      async getAddress() {
        return walletAddress;
      },
      _signTypedData,
    };
  }

  tradeRoutes.post("/polymarket/order", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = callerAgentId(c);
    if (!agentId) {
      return c.json<ApiResponse>({ ok: false, error: "Agent JWT required for trading" }, 403);
    }

    const rate = await enforcePolymarketOrderRateLimit(agentId);
    if (!rate.allowed) {
      c.header("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
      return c.json<ApiResponse>({ ok: false, error: "Trade order rate limit exceeded" }, 429);
    }

    const raw = await safeJsonParse(c);
    const parsed = pmSubmitOrderSchema.safeParse(raw);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
    }
    const body = {
      ...parsed.data,
      idempotencyKey: c.req.header("Idempotency-Key") ?? parsed.data.idempotencyKey,
    };
    if (!body.idempotencyKey) {
      return c.json<ApiResponse>({ ok: false, error: "Idempotency-Key is required" }, 400);
    }

    const idempotency = getPmIdempotency(tenantId, agentId, body.idempotencyKey, body);
    if (idempotency.conflict) {
      return c.json<ApiResponse>(
        { ok: false, error: "Idempotency key reused with a different body" },
        409,
      );
    }
    if (idempotency.response) {
      return tradeReplayResponse(c, idempotency.response);
    }

    // Validate price + amount as positive finite numbers up front (the policy gate
    // needs the notional; the adapter re-validates the (0,1) price range).
    const amount = Number(body.amount);
    const price = Number(body.price);
    if (!Number.isFinite(amount) || amount <= 0) {
      return c.json<ApiResponse>(
        { ok: false, error: "amount must be a positive finite number" },
        400,
      );
    }
    if (!Number.isFinite(price) || price <= 0 || price >= 1) {
      return c.json<ApiResponse>(
        { ok: false, error: "price must be in the open interval (0,1)" },
        400,
      );
    }
    const notionalUsd = polymarketNotionalUsd(body.side, amount, price);

    // Session fetch + ownership + venue check + the prediction-market policy gate,
    // all in one pass. checkActiveOrder loads the session and runs checkOrderAllowed
    // against the allowlist + per-order/daily caps.
    //
    // SECURITY: we deliberately do NOT forward the caller-supplied `conditionId` to
    // the allowlist check. The order is submitted for `tokenId` only, so trusting an
    // UNVERIFIED conditionId would let an agent pair any non-allowlisted token with
    // an allowlisted `pm:cond:<id>` and bypass the market allowlist. Until the
    // token->condition mapping is resolved from VERIFIED Polymarket metadata, the
    // order route honors ONLY exact `pm:<tokenId>` entries. A `pm:cond:<id>`
    // session grant therefore requires the per-token entry to also be present to
    // trade (or a future Phase C resolver that derives + verifies the condition).
    // TODO(phase-c): resolve the token's true conditionId from venue metadata and
    // pass it here so market-wide grants can be honored safely.
    const { session, check } = await getSessionManager().checkActiveOrder({
      tenantId,
      id: body.sessionId,
      order: {
        tokenId: body.tokenId,
        // conditionId intentionally omitted — see SECURITY note above.
        notionalUsd,
      },
    });

    // Ownership + venue binding: the session must belong to THIS agent and be a
    // polymarket session. A mismatch is treated as "no active session" (403) — we
    // never leak another agent's session existence.
    if (session.agentId !== agentId || session.venue !== "polymarket") {
      return c.json<ApiResponse>({ ok: false, error: "Active Polymarket session required" }, 403);
    }

    if (!check.allowed) {
      const status = pmPolicyRejectStatus(check.reason);
      await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
        sessionId: session.id,
        venue: "polymarket",
        tokenId: body.tokenId,
        conditionId: body.conditionId ?? null,
        side: body.side,
        amount,
        price,
        notionalUsd,
        reason: check.reason,
      });
      if (status === 403) {
        // 403s are not stored for idempotent replay (session state can change to
        // active and a retry should re-evaluate) — mirrors HL's session-required 403.
        return c.json<ApiResponse>({ ok: false, error: "Active Polymarket session required" }, 403);
      }
      const envelope: TradeIdempotencyResponse = {
        status: 400,
        body: { code: "policy-violation", reason: check.reason },
      };
      idempotency.store?.(envelope);
      return c.json(envelope.body, envelope.status);
    }

    // Resolve creds BEFORE reserving spend so a fail-closed creds gap never
    // consumes the daily cap. FAIL CLOSED: no creds → 409, no order.
    const creds = await resolvePolymarketCreds(tenantId, agentId);
    if (!creds.ok) {
      const reason =
        creds.reason === "wallet-not-found"
          ? "Polymarket venue wallet not found. Provision a polymarket wallet before trading."
          : "Polymarket credentials are not provisioned for this agent.";
      await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
        sessionId: session.id,
        venue: "polymarket",
        tokenId: body.tokenId,
        conditionId: body.conditionId ?? null,
        reason: creds.reason,
      });
      return c.json<ApiResponse>({ ok: false, error: reason }, 409);
    }

    // Session binding: the session was approved against a specific wallet
    // (session.walletId). If the venue wallet was rotated/reprovisioned after the
    // session was created, the freshly-resolved creds.walletAddress will differ —
    // reject rather than let a stale session authorize a DIFFERENT wallet/funder.
    if (creds.walletAddress.toLowerCase() !== session.walletId.toLowerCase()) {
      await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
        sessionId: session.id,
        venue: "polymarket",
        tokenId: body.tokenId,
        conditionId: body.conditionId ?? null,
        reason: "wallet-binding-mismatch",
        sessionWallet: session.walletId,
        resolvedWallet: creds.walletAddress,
      });
      return c.json<ApiResponse>(
        {
          ok: false,
          error:
            "Session wallet binding no longer matches the provisioned wallet. Re-create the session.",
        },
        409,
      );
    }

    // Build the vault→ethers-signer bridge + the Polymarket account + adapter
    // BEFORE entering the fence. Builder attribution is resolved from env
    // (default OFF) — never hardcoded.
    const signer = buildPolymarketVaultSigner(tenantId, agentId, creds.walletAddress);
    const account: PolymarketAccount = {
      apiCredentials: creds.apiCredentials,
      funderAddress: creds.funderAddress,
      signer,
      signatureType: creds.signatureType,
    };
    const adapter = new PolymarketExecutionAdapter(account, { builder: resolveBuilderConfig() });

    const orderRequest: PolymarketOrderRequest = {
      tokenId: body.tokenId,
      side: body.side,
      amount,
      price,
      orderType: "market",
      ...(body.tickSize ? { tickSize: body.tickSize } : {}),
      ...(typeof body.negRisk === "boolean" ? { negRisk: body.negRisk } : {}),
    };

    const manager = getSessionManager();
    // Fence reserve→submit against concurrent revocation (mirrors HL's
    // withActiveSubmissionFence): the spend reservation and the venue submit run
    // under an advisory lock that the revoke path also takes, so a revoke that
    // commits before this block cannot interleave with an in-flight submit.
    const fenced = await manager.withActiveSubmissionFence(
      { tenantId, id: session.id },
      async () => {
        // Re-confirm active inside the fence, then reserve spend (atomic; also
        // re-checks active + cap).
        const reserved = await getSessionManager().reserveSpend({
          tenantId,
          id: session.id,
          amountUsd: notionalUsd,
        });
        if (!reserved) {
          const envelope: TradeIdempotencyResponse = {
            status: 400,
            body: { ok: false, error: "Trade session cap exceeded" },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        await auditTradeEvent(tenantId, agentId, "trade.order.submit.authorized", {
          sessionId: session.id,
          venue: "polymarket",
          tokenId: body.tokenId,
          conditionId: body.conditionId ?? null,
          side: body.side,
          amount,
          price,
          notionalUsd,
        });

        // PRE-SUBMIT phase: build + sign the order (resolves tickSize/negRisk +
        // applies CLOB rounding). Any throw here means NOTHING reached the venue,
        // so the reserved spend MUST be released — these never burn the daily cap.
        let signedOrder: unknown;
        try {
          signedOrder = await adapter.buildSignedOrder(orderRequest);
        } catch (err) {
          await getSessionManager().releaseSpend({
            tenantId,
            id: session.id,
            amountUsd: notionalUsd,
          });
          // A 401 here means the cached L2 creds were rotated/revoked CLOB-side.
          // Drop them so the NEXT order re-derives from L1 (self-healing).
          if (isPolymarketUnauthorized(err)) {
            await invalidatePolymarketCredsCache(tenantId, agentId, creds.walletAddress);
          }
          await auditTradeEvent(tenantId, agentId, "trade.order.canceled", {
            sessionId: session.id,
            venue: "polymarket",
            tokenId: body.tokenId,
            conditionId: body.conditionId ?? null,
            notionalUsd,
            reason: "pre-submit-build-failed",
            error: err instanceof Error ? err.message : String(err),
          });
          const envelope: TradeIdempotencyResponse = {
            status: 400,
            body: { ok: false, error: "Order could not be built; not submitted" },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        // SUBMIT phase: post the ALREADY-built signed order. submitSignedOrder does
        // NOT rebuild/re-sign (no second CLOB metadata or signer round-trip), so a
        // throw HERE genuinely means the POST was attempted and the order may have
        // landed — status unknown, so we do NOT release spend (mirrors HL's 502).
        let result: Awaited<ReturnType<PolymarketExecutionAdapter["submitSignedOrder"]>>;
        try {
          result = await adapter.submitSignedOrder(signedOrder, orderRequest);
        } catch (err) {
          // A 401 anywhere in submit (client construction or the POST) means the
          // cached L2 creds were rotated/revoked — drop them so the next order
          // re-derives from L1 (self-healing), regardless of attempted-vs-not.
          if (isPolymarketUnauthorized(err)) {
            await invalidatePolymarketCredsCache(tenantId, agentId, creds.walletAddress);
          }
          // A not-attempted failure (CLOB client/builder construction threw before
          // any POST) means nothing reached the venue → RELEASE spend, return 400.
          if (isPolymarketPostNotAttempted(err)) {
            await getSessionManager().releaseSpend({
              tenantId,
              id: session.id,
              amountUsd: notionalUsd,
            });
            await auditTradeEvent(tenantId, agentId, "trade.order.canceled", {
              sessionId: session.id,
              venue: "polymarket",
              tokenId: body.tokenId,
              conditionId: body.conditionId ?? null,
              notionalUsd,
              reason: "pre-submit-build-failed",
              error: err.message,
            });
            const envelope: TradeIdempotencyResponse = {
              status: 400,
              body: { ok: false, error: "Trade submission could not be built" },
            };
            idempotency.store?.(envelope);
            return envelope;
          }
          // Otherwise the POST was attempted and the order may have landed —
          // status unknown, KEEP spend (mirrors HL's 502).
          await auditTradeEvent(tenantId, agentId, "trade.order.canceled", {
            sessionId: session.id,
            venue: "polymarket",
            tokenId: body.tokenId,
            conditionId: body.conditionId ?? null,
            notionalUsd,
            reason: "submit-status-unknown",
            error: err instanceof Error ? err.message : String(err),
          });
          const envelope: TradeIdempotencyResponse = {
            status: 502,
            body: { ok: false, error: "Trade submission status unknown" },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        // The adapter reports rejection as success:false / errorMsg / actualAmount 0.
        const rejected =
          result.success === false ||
          Boolean(result.errorMsg) ||
          (result.actualAmount !== undefined && result.actualAmount <= 0);
        if (rejected) {
          // The order was NOT accepted → release the reserved spend.
          await getSessionManager().releaseSpend({
            tenantId,
            id: session.id,
            amountUsd: notionalUsd,
          });
          // If the venue rejected with an auth error (returned, not thrown), the
          // cached L2 creds are stale → drop them so the next order re-derives.
          if (
            isPolymarketUnauthorized(result) ||
            /\b401\b|unauthor|invalid api|invalid.*key|api key/i.test(result.errorMsg ?? "")
          ) {
            await invalidatePolymarketCredsCache(tenantId, agentId, creds.walletAddress);
          }
          await auditTradeEvent(tenantId, agentId, "trade.order.canceled", {
            sessionId: session.id,
            venue: "polymarket",
            tokenId: body.tokenId,
            conditionId: body.conditionId ?? null,
            side: body.side,
            amount,
            price,
            notionalUsd,
            orderId: result.orderId ?? null,
            reason: result.errorMsg ?? "Trade order rejected",
          });
          const envelope: TradeIdempotencyResponse = {
            status: 400,
            body: {
              ok: false,
              error: result.errorMsg ?? "Trade order rejected",
              data: { status: result.status ?? "rejected" },
            },
          };
          idempotency.store?.(envelope);
          return envelope;
        }

        const response = {
          orderId: result.orderId ?? crypto.randomUUID(),
          status: result.status ?? "filled",
          filledQty: result.actualAmount ?? 0,
          avgPrice: result.actualPrice ?? Number(price),
          notionalUsd,
        };
        const envelope: TradeIdempotencyResponse = {
          status: 200,
          body: responseData(response),
        };
        // The order HAS landed at the venue. Persist the idempotency record BEFORE
        // the audit write so a retry after an audit failure replays this response
        // instead of re-submitting a duplicate order.
        idempotency.store?.(envelope);
        // The audit write is best-effort here: the order is final + the response is
        // recorded, so an audit failure must NOT turn a successful fill into an
        // error to the client (which could prompt a duplicate retry). Log + proceed.
        try {
          await auditTradeEvent(tenantId, agentId, "trade.order.submitted", {
            sessionId: session.id,
            venue: "polymarket",
            tokenId: body.tokenId,
            conditionId: body.conditionId ?? null,
            side: body.side,
            amount,
            price,
            notionalUsd,
            orderId: response.orderId,
          });
        } catch (auditErr) {
          console.error(
            "[polymarket/order] submitted-audit write failed (order already final)",
            auditErr,
          );
        }
        return envelope;
      },
    );

    // The fence returns null when the session is no longer active (revoked/expired
    // before the lock was taken) — fail closed without submitting.
    if (!fenced) {
      const envelope: TradeIdempotencyResponse = {
        status: 409,
        body: { ok: false, error: "Trade session was revoked before order submission" },
      };
      idempotency.store?.(envelope);
      return c.json(envelope.body, envelope.status);
    }
    return c.json(fenced.body, fenced.status);
  });

  return tradeRoutes;
}

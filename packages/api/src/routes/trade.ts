import { proxyAuditLog } from "@stwd/db";
import { evaluateTradeOrder } from "@stwd/policy-engine";
import { checkRateLimit } from "@stwd/redis";
import { TradeSessionManager } from "@stwd/trade-sessions";
import {
  HyperliquidAdapter,
  type HyperliquidOrder,
  hyperliquidAssetSchema,
  hyperliquidOrderSchema,
} from "@stwd/venue-hyperliquid";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import { getRedisClient } from "../middleware/redis";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  ensureAgentForTenant,
  safeJsonParse,
  vault,
} from "../services/context";

export const tradeRoutes = new Hono<{ Variables: AppVariables }>();

const createSessionSchema = z.object({
  agentId: z.string().min(1).optional(),
  venue: z.literal("hyperliquid"),
  walletAddress: z.string().min(1).optional(),
  dailyCap: z.number().positive().max(50_000).default(300),
  perOrderCap: z.number().positive().max(10_000).default(100),
  leverageCap: z.number().positive().max(50).default(5),
  allowedAssets: z
    .array(z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP", "NEAR", "HYPE", "ZEC", "XMR"]))
    .min(1)
    .default(["BTC", "ETH", "BNB"]),
  ttlSeconds: z.number().int().positive().max(86_400).default(3_600),
});

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
    leverage: z.number().int().positive().default(1),
    reduceOnly: z.boolean().default(false),
    idempotencyKey: z.string().min(1).max(256).optional(),
  })
  .refine((value) => value.coin ?? value.asset, "coin is required");

type SubmitOrderBody = z.infer<typeof submitOrderSchema>;

const memoryRateLimit = new Map<string, { count: number; resetAt: number }>();
type TradeIdempotencyEntry =
  | { bodyHash: string; status: "processing"; expiresAt: number }
  | {
      bodyHash: string;
      status: "completed";
      response: TradeIdempotencyResponse;
      expiresAt: number;
    };

type TradeIdempotencyResponse = {
  status: number;
  body: unknown;
};

type TradeIdempotencyClaim =
  | { status: "none" }
  | {
      status: "claimed";
      complete(response: TradeIdempotencyResponse): Promise<void>;
      release(): Promise<void>;
    }
  | { status: "processing" }
  | { status: "completed"; response: TradeIdempotencyResponse }
  | { status: "conflict" };

const memoryIdempotency = new Map<string, TradeIdempotencyEntry>();

class TradeSessionRevokedBeforeSubmitError extends Error {
  constructor() {
    super("Trade session was revoked before order submission");
  }
}

const HYPERLIQUID_BASE_URL = process.env.HYPERLIQUID_BASE_URL || "https://api.hyperliquid.xyz";
const DECIMAL_PRICE_RE = /^(?:0|[1-9]\d*)(?:\.\d+)?$/;

function getSessionManager(): TradeSessionManager {
  return new TradeSessionManager({ redis: getRedisClient() });
}

function callerAgentId(c: Context<{ Variables: AppVariables }>): string | null {
  return c.get("agentScope") ?? null;
}

function canManageTradeSession(c: Context<{ Variables: AppVariables }>, agentId: string): boolean {
  void agentId;
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function hasRecentSessionMfa(c: Context<{ Variables: AppVariables }>, maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function requireRecentTradeSessionMfa(c: Context<{ Variables: AppVariables }>): Response | null {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: "Trade session management requires recent MFA verification" },
    403,
  );
}

function responseData<T>(data: T): ApiResponse<T> {
  return { ok: true, data };
}

async function auditTradeEvent(
  tenantId: string,
  agentId: string,
  actor: { actorType: "agent" | "user" | "api-key"; actorId: string },
  event:
    | "trade.session.create.authorized"
    | "trade.session.created"
    | "trade.session.revoke.authorized"
    | "trade.session.revoked"
    | "trade.order.submit.authorized"
    | "trade.order.submitted"
    | "trade.order.policy-rejected"
    | "trade.order.canceled",
  details: Record<string, unknown>,
): Promise<void> {
  const correlationId = typeof details.sessionId === "string" ? details.sessionId : undefined;
  await writeAuditEvent({
    tenantId,
    actorType: actor.actorType,
    actorId: actor.actorId,
    action: event,
    resourceType: "trade",
    resourceId: correlationId ?? agentId,
    metadata: { ...details, agentId, correlationId },
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

async function completeTradeIdempotencyBestEffort(
  idempotency: TradeIdempotencyClaim,
  envelope: TradeIdempotencyResponse,
): Promise<void> {
  if (idempotency.status !== "claimed") return;
  try {
    await idempotency.complete(envelope);
  } catch (error) {
    console.error("[trade] Failed to complete idempotency record after venue result:", error);
  }
}

function tradeAuditActor(
  c: Context<{ Variables: AppVariables }>,
  fallbackAgentId: string,
): { actorType: "agent" | "user" | "api-key"; actorId: string } {
  const authType = c.get("authType");
  const userId = c.get("userId");
  if (authType === "session-jwt" && userId) return { actorType: "user", actorId: userId };
  const agentId = callerAgentId(c) ?? fallbackAgentId;
  return { actorType: "agent", actorId: agentId };
}

function hashBody(body: unknown): string {
  return JSON.stringify(body);
}

function tradeReplayResponse(response: TradeIdempotencyResponse): Response {
  return Response.json(response.body, {
    status: response.status as 200 | 400 | 403 | 409 | 429 | 502 | 503,
    headers: { "Idempotency-Replayed": "true" },
  });
}

function normalizeTradeIdempotencyResponse(response: unknown): TradeIdempotencyResponse {
  if (
    response &&
    typeof response === "object" &&
    "status" in response &&
    "body" in response &&
    typeof (response as { status?: unknown }).status === "number"
  ) {
    return response as TradeIdempotencyResponse;
  }
  return { status: 200, body: responseData(response) };
}

async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function allowLocalTradeControls(): boolean {
  return (
    process.env.NODE_ENV !== "production" ||
    process.env.STEWARD_ALLOW_IN_MEMORY_TRADE_CONTROLS === "true"
  );
}

function positiveFiniteNumber(value: unknown): number | null {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!DECIMAL_PRICE_RE.test(trimmed)) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  }
  const parsed = value;
  return typeof parsed === "number" && Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

async function fetchHyperliquidMidPrice(asset: string): Promise<number | null> {
  const response = await fetch(`${HYPERLIQUID_BASE_URL}/info`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "allMids" }),
  });
  if (!response.ok) return null;

  const mids = (await response.json().catch(() => null)) as Record<string, unknown> | null;
  return positiveFiniteNumber(mids?.[asset]);
}

async function estimateHyperliquidOrderUsd(
  body: SubmitOrderBody,
  asset: string,
): Promise<{
  ok: true;
  limitPrice: number;
  priceUsd: number;
  sizeUsd: number;
}> {
  const limitPrice = positiveFiniteNumber(body.limitPx ?? body.limitPrice);
  if (!limitPrice) {
    throw new Error("limitPx must be a positive finite price");
  }

  if (body.side === "buy") {
    return { ok: true, limitPrice, priceUsd: limitPrice, sizeUsd: body.size * limitPrice };
  }

  const midPrice = await fetchHyperliquidMidPrice(asset);
  if (!midPrice) {
    throw new Error("Unable to verify Hyperliquid market price for sell order");
  }
  const priceUsd = Math.max(limitPrice, midPrice);
  return { ok: true, limitPrice, priceUsd, sizeUsd: body.size * priceUsd };
}

async function enforceOrderRateLimit(
  agentId: string,
): Promise<{ allowed: boolean; resetMs: number }> {
  const redis = getRedisClient();
  if (redis) {
    const result = await checkRateLimit(`ratelimit:trade:hyperliquid:${agentId}:1000`, 1000, 10);
    return { allowed: result.allowed, resetMs: result.resetMs };
  }

  if (!allowLocalTradeControls()) {
    throw new Error("Shared trade rate limiter unavailable");
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

async function claimIdempotency(
  tenantId: string,
  agentId: string,
  key: string | undefined,
  body: SubmitOrderBody,
): Promise<TradeIdempotencyClaim> {
  if (!key) return { status: "none" };
  const now = Date.now();
  const ttlMs = 24 * 60 * 60 * 1000;
  const bodyHash = hashBody({ ...body, idempotencyKey: undefined });

  const redis = getRedisClient();
  if (redis) {
    const redisKey = `trade:idempotency:${await sha256Hex(`${tenantId}\n${agentId}\n${key}`)}`;
    const entry: TradeIdempotencyEntry = {
      bodyHash,
      status: "processing",
      expiresAt: now + ttlMs,
    };
    const claimed = await redis.set(redisKey, JSON.stringify(entry), "PX", ttlMs, "NX");
    if (claimed) {
      return {
        status: "claimed",
        async complete(response: TradeIdempotencyResponse) {
          const completed: TradeIdempotencyEntry = {
            bodyHash,
            status: "completed",
            response,
            expiresAt: Date.now() + ttlMs,
          };
          await redis.set(redisKey, JSON.stringify(completed), "PX", ttlMs);
        },
        async release() {
          await redis.del(redisKey);
        },
      };
    }

    const rawExisting = await redis.get(redisKey);
    if (!rawExisting) return claimIdempotency(tenantId, agentId, key, body);
    const existing = safeJsonParseString<TradeIdempotencyEntry>(rawExisting);
    if (!existing || existing.expiresAt <= now) {
      await redis.del(redisKey);
      return claimIdempotency(tenantId, agentId, key, body);
    }
    if (existing.bodyHash !== bodyHash) return { status: "conflict" };
    if (existing.status === "completed") {
      return {
        status: "completed",
        response: normalizeTradeIdempotencyResponse(existing.response),
      };
    }
    return { status: "processing" };
  }

  if (!allowLocalTradeControls()) {
    throw new Error("Shared trade idempotency store unavailable");
  }

  const mapKey = `${tenantId}:${agentId}:${key}`;
  const existing = memoryIdempotency.get(mapKey);
  if (existing && existing.expiresAt > now) {
    if (existing.bodyHash !== bodyHash) return { status: "conflict" };
    if (existing.status === "completed") {
      return {
        status: "completed",
        response: normalizeTradeIdempotencyResponse(existing.response),
      };
    }
    return { status: "processing" };
  }
  memoryIdempotency.set(mapKey, {
    bodyHash,
    status: "processing",
    expiresAt: now + ttlMs,
  });
  return {
    status: "claimed",
    async complete(response: TradeIdempotencyResponse) {
      memoryIdempotency.set(mapKey, {
        bodyHash,
        status: "completed",
        response,
        expiresAt: Date.now() + ttlMs,
      });
    },
    async release() {
      memoryIdempotency.delete(mapKey);
    },
  };
}

function safeJsonParseString<T>(value: string): T | null {
  try {
    return JSON.parse(value) as T;
  } catch {
    return null;
  }
}

async function releaseIdempotency(claim: TradeIdempotencyClaim): Promise<void> {
  if (claim.status === "claimed") await claim.release();
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
  const { venue, dailyCap, perOrderCap, leverageCap, allowedAssets, ttlSeconds } = parsed.data;

  if (!canManageTradeSession(c, agentId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: insufficient access to create a session for this agent" },
      403,
    );
  }
  const mfaResponse = requireRecentTradeSessionMfa(c);
  if (mfaResponse) return mfaResponse;
  if (perOrderCap > dailyCap) {
    return c.json<ApiResponse>({ ok: false, error: "perOrderCap cannot exceed dailyCap" }, 400);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  // Bind the session to the agent's own resolved venue wallet. Caller-supplied
  // walletAddress is intentionally ignored — honoring it would let an owner bind
  // a trade session to an arbitrary wallet (funds-routing spoof).
  const walletAddress = await resolveHyperliquidWallet(agentId, agent);
  if (!walletAddress) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Hyperliquid venue wallet not found. Create a venue-scoped wallet before trading.",
      },
      404,
    );
  }

  const actor = tradeAuditActor(c, agentId);
  await auditTradeEvent(tenantId, agentId, actor, "trade.session.create.authorized", {
    venue,
    walletId: walletAddress,
    dailyCapUsd: dailyCap,
    perOrderCapUsd: perOrderCap,
    leverageCap,
    allowedAssets,
    ttlSeconds,
  });

  const sessionManager = getSessionManager();
  const session = await sessionManager.createSession({
    agentId,
    tenantId,
    venue,
    walletId: walletAddress,
    dailyCapUsd: dailyCap,
    perOrderCapUsd: perOrderCap,
    leverageCap,
    allowedAssets,
    ttlSeconds,
  });

  try {
    await auditTradeEvent(tenantId, agentId, actor, "trade.session.created", {
      sessionId: session.id,
      venue: session.venue,
      walletId: session.walletId,
      dailyCapUsd: session.dailyCapUsd,
      perOrderCapUsd: session.perOrderCapUsd,
      leverageCap: session.leverageCap,
      allowedAssets: session.allowedAssets,
    });
  } catch (err) {
    await sessionManager.deleteSession({ tenantId, id: session.id });
    throw err;
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
  if (!canManageTradeSession(c, session.agentId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: insufficient access to this session" },
      403,
    );
  }
  const mfaResponse = requireRecentTradeSessionMfa(c);
  if (mfaResponse) return mfaResponse;

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
  if (existing && !canManageTradeSession(c, existing.agentId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: insufficient access to revoke this session" },
      403,
    );
  }
  if (existing) {
    const mfaResponse = requireRecentTradeSessionMfa(c);
    if (mfaResponse) return mfaResponse;
  }

  if (existing) {
    await auditTradeEvent(
      tenantId,
      existing.agentId,
      tradeAuditActor(c, existing.agentId),
      "trade.session.revoke.authorized",
      {
        sessionId: existing.id,
        revokedBy: callerAgentId(c) ?? c.get("userId") ?? c.get("authType") ?? "api-key",
      },
    );
  }

  const revoked = await getSessionManager().revokeSession({
    id: c.req.param("id"),
    tenantId,
    revokedBy: callerAgentId(c) ?? c.get("userId") ?? c.get("authType") ?? "api-key",
  });
  if (!revoked) return c.json<ApiResponse>({ ok: false, error: "Session not found" }, 404);

  await auditTradeEvent(
    tenantId,
    revoked.agentId,
    tradeAuditActor(c, revoked.agentId),
    "trade.session.revoked",
    {
      sessionId: revoked.id,
      revokedBy: callerAgentId(c) ?? c.get("authType") ?? "api-key",
    },
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
  const agentActor = { actorType: "agent" as const, actorId: agentId };

  let rate: { allowed: boolean; resetMs: number };
  try {
    rate = await enforceOrderRateLimit(agentId);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Trade rate limiter unavailable" },
      503,
    );
  }
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
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency-Key header is required for trade orders" },
      400,
    );
  }

  let idempotency: TradeIdempotencyClaim;
  try {
    idempotency = await claimIdempotency(tenantId, agentId, body.idempotencyKey, body);
  } catch (err) {
    return c.json<ApiResponse>(
      { ok: false, error: err instanceof Error ? err.message : "Trade idempotency unavailable" },
      503,
    );
  }
  if (idempotency.status === "conflict") {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.status === "processing") {
    c.header("Retry-After", "1");
    return c.json<ApiResponse>({ ok: false, error: "Idempotency key is already processing" }, 409);
  }
  if (idempotency.status === "completed") {
    return tradeReplayResponse(idempotency.response);
  }

  const coin = body.coin ?? body.asset;
  if (!coin) {
    await releaseIdempotency(idempotency);
    return c.json<ApiResponse>({ ok: false, error: "coin is required" }, 400);
  }

  const session = await getSessionManager().getActive(tenantId, body.sessionId);
  if (!session || session.agentId !== agentId || session.venue !== "hyperliquid") {
    await releaseIdempotency(idempotency);
    return c.json<ApiResponse>({ ok: false, error: "Active Hyperliquid session required" }, 403);
  }
  let notional: Awaited<ReturnType<typeof estimateHyperliquidOrderUsd>>;
  try {
    notional = await estimateHyperliquidOrderUsd(body, coin);
  } catch (err) {
    await releaseIdempotency(idempotency);
    return c.json<ApiResponse>(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Unable to verify order notional",
      },
      400,
    );
  }
  const sizeUsd = notional.sizeUsd;
  const policy = evaluateTradeOrder(
    {
      venue: session.venue,
      allowedVenues: [session.venue],
      leverageCap: session.leverageCap,
      allowedAssets: session.allowedAssets,
      dailySpendUsd: session.dailySpendUsd,
      dailyCapUsd: session.dailyCapUsd,
      perOrderCapUsd: session.perOrderCapUsd,
    },
    {
      venue: "hyperliquid",
      asset: coin,
      leverage: body.leverage,
      estimatedOrderUsd: sizeUsd,
    },
  );
  if (!policy.allow) {
    const reason = policy.reason ?? "order violates trading policy";
    await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.policy-rejected", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: coin,
      leverage: body.leverage,
      size: body.size,
      limitPx: body.limitPx ?? body.limitPrice,
      sizeUsd,
      dailySpendUsd: session.dailySpendUsd,
      reason,
    });
    await releaseIdempotency(idempotency);
    return c.json({ code: "policy-violation", reason }, 400);
  }

  // Re-validate against the Hyperliquid adapter's strict asset enum. The
  // session-level allowlist (BTC/ETH) is covered by evaluateTradeOrder; this
  // second check defends the adapter contract if the session ever permits
  // a coin the adapter does not implement.
  const parsedAsset = hyperliquidAssetSchema.safeParse(coin);
  if (!parsedAsset.success) {
    const reason = `asset-allowlist: asset ${coin} is not supported by Hyperliquid adapter`;
    await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.policy-rejected", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: coin,
      reason,
    });
    await releaseIdempotency(idempotency);
    return c.json({ code: "policy-violation", reason }, 400);
  }

  const order: HyperliquidOrder = {
    asset: parsedAsset.data,
    side: body.side,
    size: body.size,
    limitPx: String(notional.limitPrice),
    leverage: body.leverage,
    reduceOnly: body.reduceOnly,
  };
  const orderValidation = hyperliquidOrderSchema.safeParse(order);
  if (!orderValidation.success) {
    const reason = `adapter-validation: ${orderValidation.error.issues
      .map((issue) => issue.message)
      .join("; ")}`;
    await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.policy-rejected", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: parsedAsset.data,
      leverage: body.leverage,
      size: body.size,
      priceUsd: notional.priceUsd,
      sizeUsd,
      reason,
    });
    await releaseIdempotency(idempotency);
    return c.json({ code: "policy-violation", reason }, 400);
  }

  const walletAddress = session.walletId;
  const reserved = await getSessionManager().reserveSpend({
    tenantId,
    id: session.id,
    amountUsd: sizeUsd,
  });
  if (!reserved) {
    const reason = "daily-cap: session daily cap exhausted";
    await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.policy-rejected", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: coin,
      sizeUsd,
      dailySpendUsd: session.dailySpendUsd,
      reason,
    });
    await releaseIdempotency(idempotency);
    return c.json({ code: "policy-violation", reason }, 400);
  }

  const vaultClient = {
    signTypedData: (input: Omit<Parameters<typeof vault.signTypedData>[0], "tenantId">) =>
      vault.signTypedData({ ...input, tenantId, venue: "hyperliquid" }),
  };
  const adapter = new HyperliquidAdapter(vaultClient, agentId, walletAddress);
  let result: Awaited<ReturnType<typeof adapter.submitOrder>>;
  let submitAttempted = false;
  try {
    const submission = await getSessionManager().withActiveSubmissionFence(
      { tenantId, id: session.id },
      async () => {
        await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.submit.authorized", {
          sessionId: session.id,
          venue: "hyperliquid",
          asset: parsedAsset.data,
          leverage: body.leverage,
          size: body.size,
          priceUsd: notional.priceUsd,
          sizeUsd,
        });
        const signed = await adapter.signOrder(order);
        if (!(await getSessionManager().getActive(tenantId, session.id))) {
          throw new TradeSessionRevokedBeforeSubmitError();
        }
        submitAttempted = true;
        return adapter.submitOrder(signed);
      },
    );
    if (!submission) {
      await getSessionManager()
        .releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })
        .catch(() => null);
      await releaseIdempotency(idempotency);
      return c.json<ApiResponse>(
        { ok: false, error: "Trade session was revoked before order submission" },
        403,
      );
    }
    result = submission;
  } catch (err) {
    if (err instanceof TradeSessionRevokedBeforeSubmitError) {
      await getSessionManager()
        .releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })
        .catch(() => null);
      await releaseIdempotency(idempotency);
      return c.json<ApiResponse>({ ok: false, error: err.message }, 403);
    }
    if (submitAttempted) {
      const unknownResponse = {
        orderId: crypto.randomUUID(),
        status: "submit_unknown",
        error: "Trade submission status unknown after venue submit attempt",
      };
      const envelope: TradeIdempotencyResponse = {
        status: 502,
        body: {
          ok: false,
          error:
            err instanceof Error
              ? `Trade submission status unknown: ${err.message}`
              : "Trade submission status unknown",
          data: unknownResponse,
        },
      };
      if (idempotency.status === "claimed") await idempotency.complete(envelope);
      return c.json<ApiResponse>(envelope.body as ApiResponse, 502);
    }
    await getSessionManager()
      .releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })
      .catch(() => null);
    await releaseIdempotency(idempotency);
    throw err;
  }
  const response = {
    orderId: result.orderId ?? crypto.randomUUID(),
    status: result.status,
    filledQty: result.filledQty ?? 0,
    avgPrice: result.avgPrice ?? 0,
    txHash: result.txHash ?? null,
  };

  if (result.status === "rejected") {
    await getSessionManager()
      .releaseSpend({ tenantId, id: session.id, amountUsd: sizeUsd })
      .catch(() => null);
    const rejectedResponse = {
      ...response,
      error: result.error ?? "Hyperliquid rejected order",
    };
    const envelope: TradeIdempotencyResponse = {
      status: 400,
      body: { ok: false, error: rejectedResponse.error, data: rejectedResponse },
    };
    try {
      await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.canceled", {
        sessionId: session.id,
        venue: "hyperliquid",
        asset: parsedAsset.data,
        leverage: body.leverage,
        size: body.size,
        priceUsd: notional.priceUsd,
        sizeUsd,
        orderId: rejectedResponse.orderId,
        reason: rejectedResponse.error,
      });
    } catch (error) {
      console.error("[trade] Post-submit rejection audit failed:", error);
    }
    await completeTradeIdempotencyBestEffort(idempotency, envelope);
    return c.json<ApiResponse>(envelope.body as ApiResponse, 400);
  }

  const envelope: TradeIdempotencyResponse = { status: 200, body: responseData(response) };
  try {
    await auditTradeEvent(tenantId, agentId, agentActor, "trade.order.submitted", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: parsedAsset.data,
      leverage: body.leverage,
      size: body.size,
      priceUsd: notional.priceUsd,
      sizeUsd,
      orderId: response.orderId,
    });
  } catch (error) {
    console.error("[trade] Post-submit success audit failed:", error);
  }
  await completeTradeIdempotencyBestEffort(idempotency, envelope);
  return c.json(responseData(response));
});

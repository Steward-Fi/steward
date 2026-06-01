import { agentPolicies, eq, getDb, proxyAuditLog } from "@stwd/db";
import { evaluateTradeOrder } from "@stwd/policy-engine";
import { checkRateLimit } from "@stwd/redis";
import { TradeSessionManager } from "@stwd/trade-sessions";
import {
  getMarketableLimitPx,
  HyperliquidAdapter,
  type HyperliquidOrder,
  hyperliquidAssetSchema,
} from "@stwd/venue-hyperliquid";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import { getRedisClient } from "../middleware/redis";
import { getAgentTokenStatus } from "../services/agent-token-status";
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
    leverage: z.number().positive().default(1),
    reduceOnly: z.boolean().default(false),
    idempotencyKey: z.string().min(1).max(256).optional(),
  })
  .refine((value) => value.coin ?? value.asset, "coin is required");

type SubmitOrderBody = z.infer<typeof submitOrderSchema>;

const memoryRateLimit = new Map<string, { count: number; resetAt: number }>();
const memoryIdempotency = new Map<
  string,
  { bodyHash: string; response: unknown; expiresAt: number }
>();

function getSessionManager(): TradeSessionManager {
  return new TradeSessionManager({ redis: getRedisClient() });
}

function callerAgentId(c: Context<{ Variables: AppVariables }>): string | null {
  return c.get("agentScope") ?? null;
}

function canAccessAgent(c: Context<{ Variables: AppVariables }>, agentId: string): boolean {
  const scopedAgent = callerAgentId(c);
  return !scopedAgent || scopedAgent === agentId;
}

function responseData<T>(data: T): ApiResponse<T> {
  return { ok: true, data };
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
    | "trade.order.policy-rejected"
    | "trade.order.canceled",
  details: Record<string, unknown>,
): Promise<void> {
  const correlationId = typeof details.sessionId === "string" ? details.sessionId : undefined;
  await writeAuditEvent({
    tenantId,
    actorType: "agent",
    actorId: agentId,
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
): { conflict?: boolean; response?: unknown; store?: (response: unknown) => void } {
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
    store(response: unknown) {
      memoryIdempotency.set(mapKey, {
        bodyHash,
        response,
        expiresAt: now + 24 * 60 * 60 * 1000,
      });
    },
  };
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

  if (!canAccessAgent(c, agentId)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: agent token cannot create sessions for another agent" },
      403,
    );
  }
  if (perOrderCap > dailyCap) {
    return c.json<ApiResponse>({ ok: false, error: "perOrderCap cannot exceed dailyCap" }, 400);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);

  const [agentPolicy] = await getDb()
    .select()
    .from(agentPolicies)
    .where(eq(agentPolicies.agentId, agentId));

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

    if (hasOwnBodyValue(raw, "dailyCap") && dailyCap > policyDailyCap) {
      return c.json(
        policyViolation(`session cap ${dailyCap} exceeds agent policy cap ${policyDailyCap}`),
        400,
      );
    }
    if (hasOwnBodyValue(raw, "perOrderCap") && perOrderCap > policyPerOrderCap) {
      return c.json(
        policyViolation(`session cap ${perOrderCap} exceeds agent policy cap ${policyPerOrderCap}`),
        400,
      );
    }
    if (hasOwnBodyValue(raw, "leverageCap") && leverageCap > policyLeverageCap) {
      return c.json(
        policyViolation(`session cap ${leverageCap} exceeds agent policy cap ${policyLeverageCap}`),
        400,
      );
    }
    if (!agentPolicy.allowedVenues.includes(venue)) {
      return c.json(policyViolation(`venue ${venue} is not allowed by agent policy`), 400);
    }
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
  }

  const walletAddress =
    parsed.data.walletAddress ?? (await resolveHyperliquidWallet(agentId, agent));
  if (!walletAddress) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Hyperliquid venue wallet not found. Create a venue-scoped wallet before trading.",
      },
      404,
    );
  }

  const session = await getSessionManager().createSession({
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

  await auditTradeEvent(tenantId, agentId, "trade.session.created", {
    sessionId: session.id,
    venue: session.venue,
    walletId: session.walletId,
    dailyCapUsd: session.dailyCapUsd,
    perOrderCapUsd: session.perOrderCapUsd,
    leverageCap: session.leverageCap,
    allowedAssets: session.allowedAssets,
  });

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

  await auditTradeEvent(tenantId, revoked.agentId, "trade.session.revoked", {
    sessionId: revoked.id,
    revokedBy: callerAgentId(c) ?? c.get("authType") ?? "api-key",
  });
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

  const idempotency = getIdempotency(tenantId, agentId, body.idempotencyKey, body);
  if (idempotency.conflict) {
    return c.json<ApiResponse>(
      { ok: false, error: "Idempotency key reused with a different body" },
      409,
    );
  }
  if (idempotency.response) {
    return c.json(responseData(idempotency.response));
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

  const sessionPolicy = {
    venue: session.venue,
    allowedVenues: [session.venue],
    leverageCap: session.leverageCap,
    allowedAssets: session.allowedAssets,
    dailySpendUsd: session.dailySpendUsd,
    dailyCapUsd: session.dailyCapUsd,
    perOrderCapUsd: session.perOrderCapUsd,
  };
  const orderPolicy = (estimatedOrderUsd: number) =>
    evaluateTradeOrder(sessionPolicy, {
      venue: "hyperliquid",
      asset: coin,
      leverage: body.leverage,
      estimatedOrderUsd,
    });
  const rejectPolicy = async (reason: string, sizeUsd: number, limitPx?: string | number) => {
    await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
      sessionId: session.id,
      venue: "hyperliquid",
      asset: coin,
      leverage: body.leverage,
      size: body.size,
      limitPx,
      sizeUsd,
      dailySpendUsd: session.dailySpendUsd,
      reason,
    });
    return c.json({ code: "policy-violation", reason }, 400);
  };

  const limitPx = body.limitPx ?? body.limitPrice;
  if (limitPx === undefined) {
    const preliminaryPolicy = orderPolicy(0);
    if (!preliminaryPolicy.allow) {
      return rejectPolicy(preliminaryPolicy.reason ?? "order violates trading policy", 0);
    }
  }
  const policyLimitPx =
    limitPx ?? (await getMarketableLimitPx(parsedAsset.data, body.side === "buy"));
  const sizeUsd = body.size * Number(policyLimitPx);
  const policy = orderPolicy(sizeUsd);
  if (!policy.allow) {
    return rejectPolicy(policy.reason ?? "order violates trading policy", sizeUsd, policyLimitPx);
  }

  const walletAddress = session.walletId;

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
    leverage: body.leverage,
    reduceOnly: body.reduceOnly,
  };
  const signed = await adapter.signOrder(order);
  const result = await adapter.submitOrder(signed);
  const response = {
    orderId: result.orderId ?? crypto.randomUUID(),
    status: result.status,
    filledQty: result.filledQty ?? 0,
    avgPrice: result.avgPrice ?? 0,
    txHash: result.txHash ?? null,
  };

  await getSessionManager().incrementSpend({ tenantId, id: session.id, amountUsd: sizeUsd });

  await auditTradeEvent(tenantId, agentId, "trade.order.submitted", {
    sessionId: session.id,
    venue: "hyperliquid",
    asset: parsedAsset.data,
    leverage: body.leverage,
    size: body.size,
    sizeUsd,
    orderId: response.orderId,
  });
  idempotency.store?.(response);
  return c.json(responseData(response));
});

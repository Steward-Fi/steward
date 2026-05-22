import { proxyAuditLog } from "@stwd/db";
import { evaluateTradeOrder } from "@stwd/policy-engine";
import { checkRateLimit } from "@stwd/redis";
import { TradeSessionManager } from "@stwd/trade-sessions";
import {
  HyperliquidAdapter,
  type HyperliquidOrder,
  hyperliquidAssetSchema,
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
  dailyCap: z.number().positive().max(100).default(100),
  perOrderCap: z.number().positive().max(100).default(50),
  leverageCap: z.number().positive().max(2).default(2),
  allowedAssets: z
    .array(z.enum(["BTC", "ETH"]))
    .min(1)
    .default(["BTC", "ETH"]),
  ttlSeconds: z.number().int().positive().max(86_400).default(900),
});

const submitOrderSchema = z
  .object({
    sessionId: z.string().min(1),
    coin: z.string().min(1).optional(),
    asset: z.string().min(1).optional(),
    side: z.enum(["buy", "sell"]),
    size: z.number().positive(),
    leverage: z.number().positive(),
    limitPx: z.union([z.string(), z.number()]).optional(),
    limitPrice: z.union([z.string(), z.number()]).optional(),
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
    dailyCapUsd: dailyCap,
    perOrderCapUsd: perOrderCap,
    leverageCap,
    allowedAssets,
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
  const sizeUsd = body.size * Number(body.limitPx ?? body.limitPrice ?? 1);
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
    await auditTradeEvent(tenantId, agentId, "trade.order.policy-rejected", {
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
    return c.json({ code: "policy-violation", reason }, 400);
  }

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

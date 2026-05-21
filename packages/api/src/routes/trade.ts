import { signAgentToken } from "@stwd/auth";
import { proxyAuditLog } from "@stwd/db";
import { checkRateLimit } from "@stwd/redis";
import { TradeSessionManager, tradeSessionScopeSchema } from "@stwd/trade-sessions";
import {
  HyperliquidAdapter,
  type HyperliquidOrder,
  hyperliquidAssetSchema,
} from "@stwd/venue-hyperliquid";
import { sql } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { z } from "zod";
import { getRedisClient } from "../middleware/redis";
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
  venue: z.literal("hyperliquid"),
  scopes: z.array(tradeSessionScopeSchema).min(1),
  ttlSeconds: z.number().int().positive().max(3600).default(900),
});

const submitOrderSchema = z.object({
  sessionId: z.string().min(1),
  asset: hyperliquidAssetSchema,
  side: z.enum(["buy", "sell"]),
  size: z.number().positive(),
  leverage: z.number().positive().max(2),
  reduceOnly: z.boolean().default(false),
  idempotencyKey: z.string().min(1).max(256).optional(),
});

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

function responseData<T>(data: T): ApiResponse<T> {
  return { ok: true, data };
}

async function auditTradeEvent(
  tenantId: string,
  agentId: string,
  event: "trade.session.created" | "trade.session.revoked" | "trade.order.submitted",
  details: Record<string, unknown>,
): Promise<void> {
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

async function checkDailyCap(agentId: string, sizeUsd: number): Promise<boolean> {
  const since = new Date();
  since.setUTCHours(0, 0, 0, 0);
  const [row] = await db
    .select({
      total: sql<string>`coalesce(sum((${proxyAuditLog.targetPath}::jsonb ->> 'sizeUsd')::numeric), 0)::text`,
    })
    .from(proxyAuditLog)
    .where(
      sql`${proxyAuditLog.agentId} = ${agentId} and ${proxyAuditLog.reason} = 'trade.order.submitted' and ${proxyAuditLog.createdAt} >= ${since}`,
    );
  const spent = Number(row?.total ?? 0);
  return spent + sizeUsd <= 100;
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
  const agentId = callerAgentId(c);
  if (!agentId) {
    return c.json<ApiResponse>({ ok: false, error: "Agent JWT required for trade sessions" }, 403);
  }
  const raw = await safeJsonParse(c);
  const parsed = createSessionSchema.safeParse(raw);
  if (!parsed.success) {
    return c.json<ApiResponse>({ ok: false, error: parsed.error.message }, 400);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
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

  const session = await getSessionManager().create({
    agentId,
    tenantId,
    venue: parsed.data.venue,
    scopes: parsed.data.scopes,
    ttlSeconds: parsed.data.ttlSeconds,
  });
  const jwt = await signAgentToken(
    {
      agentId,
      tenantId,
      scopes: ["agent", "trade:read", "trade:hyperliquid:write"],
      ses: session.id,
    },
    `${parsed.data.ttlSeconds}s`,
  );
  await auditTradeEvent(tenantId, agentId, "trade.session.created", {
    sessionId: session.id,
    venue: session.venue,
    scopes: session.scopes,
  });

  return c.json(
    responseData({
      sessionId: session.id,
      jwt,
      expiresAt: session.expiresAt.toISOString(),
    }),
    201,
  );
});

tradeRoutes.post("/sessions/:id/revoke", async (c) => {
  const tenantId = c.get("tenantId");
  const agentId = callerAgentId(c);
  if (!agentId) return c.body(null, 204);
  const existing = await getSessionManager().getActive(tenantId, c.req.param("id"));
  if (existing && existing.agentId !== agentId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Forbidden: session belongs to another agent" },
      403,
    );
  }
  const revoked = await getSessionManager().revoke({
    id: c.req.param("id"),
    tenantId,
    revokedBy: agentId,
  });
  if (revoked) {
    await auditTradeEvent(tenantId, revoked.agentId, "trade.session.revoked", {
      sessionId: revoked.id,
      revokedBy: agentId,
    });
  }
  return c.body(null, 204);
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
  if (!session.scopes.includes("write")) {
    return c.json<ApiResponse>({ ok: false, error: "Trade session missing write scope" }, 403);
  }

  if (body.leverage > 2 || !["BTC", "ETH"].includes(body.asset)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy rejected: BTC/ETH only and leverage <= 2" },
      412,
    );
  }
  const sizeUsd = body.size;
  if (!(await checkDailyCap(agentId, sizeUsd))) {
    return c.json<ApiResponse>(
      { ok: false, error: "Policy rejected: daily cap $100 exceeded" },
      412,
    );
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
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

  const vaultClient = {
    signTypedData: (input: Omit<Parameters<typeof vault.signTypedData>[0], "tenantId">) =>
      vault.signTypedData({ ...input, tenantId, venue: "hyperliquid" }),
  };
  const adapter = new HyperliquidAdapter(vaultClient, agentId, walletAddress);
  const order: HyperliquidOrder = {
    asset: body.asset,
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

  await auditTradeEvent(tenantId, agentId, "trade.order.submitted", {
    sessionId: session.id,
    venue: "hyperliquid",
    asset: body.asset,
    leverage: body.leverage,
    size: body.size,
    sizeUsd,
    orderId: response.orderId,
  });
  idempotency.store?.(response);
  return c.json(responseData(response));
});

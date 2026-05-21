import { getDb, tradeSessions } from "@stwd/db";
import type { VenueId } from "@stwd/shared";
import type { InferInsertModel } from "drizzle-orm";
import { and, eq } from "drizzle-orm";
import { z } from "zod";

export const tradeSessionScopeSchema = z.enum(["read", "write"]);
export type TradeSessionScope = z.infer<typeof tradeSessionScopeSchema>;

export const tradeSessionStatusSchema = z.enum(["active", "revoked", "expired"]);
export type TradeSessionStatus = z.infer<typeof tradeSessionStatusSchema>;

export const tradeSessionSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  tenantId: z.string(),
  venue: z.literal("hyperliquid"),
  scopes: z.array(tradeSessionScopeSchema),
  status: tradeSessionStatusSchema,
  createdAt: z.date(),
  expiresAt: z.date(),
  revokedAt: z.date().nullable().optional(),
  revokedBy: z.string().nullable().optional(),
});

export type TradeSession = z.infer<typeof tradeSessionSchema>;

export interface TradeSessionRedisLike {
  get(key: string): Promise<string | null>;
  setex(key: string, ttlSeconds: number, value: string): Promise<string>;
  del(...keys: string[]): Promise<number>;
}

export interface TradeSessionManagerOptions {
  redis?: TradeSessionRedisLike | null;
  now?: () => Date;
}

export interface CreateTradeSessionInput {
  agentId: string;
  tenantId: string;
  venue: VenueId;
  scopes: TradeSessionScope[];
  ttlSeconds: number;
}

export interface RevokeTradeSessionInput {
  id: string;
  tenantId: string;
  revokedBy?: string;
}

const DEFAULT_TTL_SECONDS = 900;
const MAX_TTL_SECONDS = 3600;

function sessionKey(tenantId: string, id: string): string {
  return `trade:session:${tenantId}:${id}`;
}

function serializeSession(session: TradeSession): string {
  return JSON.stringify({
    ...session,
    createdAt: session.createdAt.toISOString(),
    expiresAt: session.expiresAt.toISOString(),
    revokedAt: session.revokedAt?.toISOString() ?? null,
  });
}

function parseSession(raw: string): TradeSession | null {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return tradeSessionSchema.parse({
      ...parsed,
      createdAt: new Date(String(parsed.createdAt)),
      expiresAt: new Date(String(parsed.expiresAt)),
      revokedAt: parsed.revokedAt ? new Date(String(parsed.revokedAt)) : null,
    });
  } catch {
    return null;
  }
}

function normalizeTtl(ttlSeconds: number): number {
  if (!Number.isFinite(ttlSeconds)) return DEFAULT_TTL_SECONDS;
  return Math.max(60, Math.min(MAX_TTL_SECONDS, Math.floor(ttlSeconds)));
}

export class TradeSessionManager {
  private readonly redis: TradeSessionRedisLike | null;
  private readonly now: () => Date;

  constructor(options: TradeSessionManagerOptions = {}) {
    this.redis = options.redis ?? null;
    this.now = options.now ?? (() => new Date());
  }

  async create(input: CreateTradeSessionInput): Promise<TradeSession> {
    const ttlSeconds = normalizeTtl(input.ttlSeconds);
    const createdAt = this.now();
    const expiresAt = new Date(createdAt.getTime() + ttlSeconds * 1000);
    const session: TradeSession = {
      id: `ses_${crypto.randomUUID()}`,
      agentId: input.agentId,
      tenantId: input.tenantId,
      venue: input.venue,
      scopes: [...new Set(input.scopes)],
      status: "active",
      createdAt,
      expiresAt,
      revokedAt: null,
      revokedBy: null,
    };

    const db = getDb();
    const values: InferInsertModel<typeof tradeSessions> = {
      id: session.id,
      agentId: session.agentId,
      tenantId: session.tenantId,
      venue: session.venue,
      scopes: session.scopes,
      status: session.status,
      createdAt,
      expiresAt,
    };
    await db.insert(tradeSessions).values(values);
    await this.writeRedis(session);
    return session;
  }

  async getActive(tenantId: string, id: string): Promise<TradeSession | null> {
    const cached = await this.readRedis(tenantId, id);
    const session = cached ?? (await this.readDb(tenantId, id));
    if (!session) return null;

    const now = this.now();
    if (session.status !== "active" || session.expiresAt <= now) {
      if (session.status === "active") {
        await this.markExpired(session);
      }
      return null;
    }
    return session;
  }

  async revoke(input: RevokeTradeSessionInput): Promise<TradeSession | null> {
    const existing = await this.readDb(input.tenantId, input.id);
    if (!existing) return null;
    if (existing.status === "revoked") return existing;

    const revokedAt = this.now();
    const revoked: TradeSession = {
      ...existing,
      status: "revoked",
      revokedAt,
      revokedBy: input.revokedBy ?? null,
    };

    await getDb()
      .update(tradeSessions)
      .set({ status: "revoked", revokedAt, revokedBy: revoked.revokedBy })
      .where(and(eq(tradeSessions.id, input.id), eq(tradeSessions.tenantId, input.tenantId)));
    await this.redis?.del(sessionKey(input.tenantId, input.id)).catch(() => 0);
    return revoked;
  }

  private async readRedis(tenantId: string, id: string): Promise<TradeSession | null> {
    if (!this.redis) return null;
    try {
      const raw = await this.redis.get(sessionKey(tenantId, id));
      return raw ? parseSession(raw) : null;
    } catch {
      return null;
    }
  }

  private async writeRedis(session: TradeSession): Promise<void> {
    if (!this.redis) return;
    const ttlSeconds = Math.max(1, Math.floor((session.expiresAt.getTime() - Date.now()) / 1000));
    await this.redis
      .setex(sessionKey(session.tenantId, session.id), ttlSeconds, serializeSession(session))
      .catch(() => undefined);
  }

  private async readDb(tenantId: string, id: string): Promise<TradeSession | null> {
    const [row] = await getDb()
      .select()
      .from(tradeSessions)
      .where(and(eq(tradeSessions.id, id), eq(tradeSessions.tenantId, tenantId)));
    if (!row) return null;
    return tradeSessionSchema.parse(row);
  }

  private async markExpired(session: TradeSession): Promise<void> {
    await getDb()
      .update(tradeSessions)
      .set({ status: "expired" })
      .where(and(eq(tradeSessions.id, session.id), eq(tradeSessions.tenantId, session.tenantId)));
    await this.redis?.del(sessionKey(session.tenantId, session.id)).catch(() => 0);
  }
}

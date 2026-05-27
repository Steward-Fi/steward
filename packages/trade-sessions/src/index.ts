import { getDb, tradeSessions } from "@stwd/db";
import type { InferInsertModel } from "drizzle-orm";
import { and, asc, eq, sql } from "drizzle-orm";
import { z } from "zod";

export const tradeSessionStatusSchema = z.enum(["active", "revoked", "expired"]);
export type TradeSessionStatus = z.infer<typeof tradeSessionStatusSchema>;

export const allowedAssetSchema = z.enum(["BTC", "ETH", "BNB", "SOL", "AVAX", "ARB", "OP"]);
export type AllowedAsset = z.infer<typeof allowedAssetSchema>;

export const tradeSessionSchema = z.object({
  id: z.string(),
  agentId: z.string(),
  tenantId: z.string(),
  venue: z.string(),
  walletId: z.string(),
  expiresAt: z.date(),
  status: tradeSessionStatusSchema,
  dailySpendUsd: z.number().nonnegative(),
  dailyCapUsd: z.number().positive(),
  perOrderCapUsd: z.number().positive(),
  leverageCap: z.number().positive(),
  allowedAssets: z.array(allowedAssetSchema),
  createdAt: z.date(),
  revokedAt: z.date().nullable().optional(),
  revokedBy: z.string().nullable().optional(),
});

export type TradeSession = z.infer<typeof tradeSessionSchema>;

export interface TradeSessionRedisLike {
  get(key: string): Promise<string | null>;
  setex(key: string, ttlSeconds: number, value: string): Promise<unknown>;
  del(...keys: string[]): Promise<number>;
}

export interface TradeSessionManagerOptions {
  redis?: TradeSessionRedisLike | null;
  now?: () => Date;
}

export interface CreateSessionInput {
  agentId: string;
  tenantId: string;
  venue: string;
  walletId: string;
  expiresAt?: Date;
  ttlSeconds?: number;
  dailyCapUsd: number;
  perOrderCapUsd: number;
  leverageCap: number;
  allowedAssets: AllowedAsset[];
}

export interface GetSessionInput {
  id: string;
  tenantId: string;
}

export interface RevokeSessionInput extends GetSessionInput {
  revokedBy?: string;
}

export interface IncrementSpendInput extends GetSessionInput {
  amountUsd: number;
}

export interface ListForAgentInput {
  agentId: string;
  tenantId: string;
  includeExpired?: boolean;
}

const DEFAULT_TTL_SECONDS = 900;
const MAX_TTL_SECONDS = 24 * 60 * 60;

function sessionKey(tenantId: string, id: string): string {
  return `trade:session:${tenantId}:${id}`;
}

function agentIndexKey(tenantId: string, agentId: string): string {
  return `trade:session:index:${tenantId}:${agentId}`;
}

function asNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string") return Number(value);
  return Number(value ?? 0);
}

function rowToSession(row: typeof tradeSessions.$inferSelect): TradeSession {
  return tradeSessionSchema.parse({
    id: row.id,
    agentId: row.agentId,
    tenantId: row.tenantId,
    venue: row.venue,
    walletId: row.walletId,
    expiresAt: row.expiresAt,
    status: row.status,
    dailySpendUsd: asNumber(row.dailySpendUsd),
    dailyCapUsd: asNumber(row.dailyCapUsd),
    perOrderCapUsd: asNumber(row.perOrderCapUsd),
    leverageCap: asNumber(row.leverageCap),
    allowedAssets: row.allowedAssets,
    createdAt: row.createdAt,
    revokedAt: row.revokedAt,
    revokedBy: row.revokedBy,
  });
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

function normalizeTtl(ttlSeconds?: number): number {
  if (!Number.isFinite(ttlSeconds)) return DEFAULT_TTL_SECONDS;
  return Math.max(60, Math.min(MAX_TTL_SECONDS, Math.floor(ttlSeconds ?? DEFAULT_TTL_SECONDS)));
}

function validateCaps(input: CreateSessionInput): void {
  if (input.dailyCapUsd <= 0) throw new Error("dailyCapUsd must be positive");
  if (input.perOrderCapUsd <= 0) throw new Error("perOrderCapUsd must be positive");
  if (input.perOrderCapUsd > input.dailyCapUsd) {
    throw new Error("perOrderCapUsd cannot exceed dailyCapUsd");
  }
  if (input.leverageCap <= 0) throw new Error("leverageCap must be positive");
  if (input.allowedAssets.length === 0) throw new Error("allowedAssets cannot be empty");
}

export class TradeSessionManager {
  private readonly redis: TradeSessionRedisLike | null;
  private readonly now: () => Date;

  constructor(options: TradeSessionManagerOptions = {}) {
    this.redis = options.redis ?? null;
    this.now = options.now ?? (() => new Date());
  }

  async createSession(input: CreateSessionInput): Promise<TradeSession> {
    validateCaps(input);
    const createdAt = this.now();
    const expiresAt =
      input.expiresAt ?? new Date(createdAt.getTime() + normalizeTtl(input.ttlSeconds) * 1000);
    const session: TradeSession = {
      id: `ses_${crypto.randomUUID()}`,
      agentId: input.agentId,
      tenantId: input.tenantId,
      venue: input.venue,
      walletId: input.walletId,
      status: "active",
      dailySpendUsd: 0,
      dailyCapUsd: input.dailyCapUsd,
      perOrderCapUsd: input.perOrderCapUsd,
      leverageCap: input.leverageCap,
      allowedAssets: [...new Set(input.allowedAssets)],
      createdAt,
      expiresAt,
      revokedAt: null,
      revokedBy: null,
    };

    const values: InferInsertModel<typeof tradeSessions> = {
      id: session.id,
      agentId: session.agentId,
      tenantId: session.tenantId,
      venue: session.venue,
      walletId: session.walletId,
      status: session.status,
      dailySpendUsd: String(session.dailySpendUsd),
      dailyCapUsd: String(session.dailyCapUsd),
      perOrderCapUsd: String(session.perOrderCapUsd),
      leverageCap: String(session.leverageCap),
      allowedAssets: session.allowedAssets,
      createdAt,
      expiresAt,
    };
    await getDb().insert(tradeSessions).values(values);
    await this.writeRedis(session);
    return session;
  }

  // Backward-compatible alias for the earlier skeleton.
  async create(input: CreateSessionInput): Promise<TradeSession> {
    return this.createSession(input);
  }

  async getSession(
    inputOrTenantId: GetSessionInput | string,
    maybeId?: string,
  ): Promise<TradeSession | null> {
    const input =
      typeof inputOrTenantId === "string"
        ? { tenantId: inputOrTenantId, id: String(maybeId) }
        : inputOrTenantId;
    const cached = await this.readRedis(input.tenantId, input.id);
    const session = cached ?? (await this.readDb(input.tenantId, input.id));
    if (!session) return null;
    return this.refreshExpiry(session);
  }

  async getActive(tenantId: string, id: string): Promise<TradeSession | null> {
    const session = await this.getSession({ tenantId, id });
    return session?.status === "active" ? session : null;
  }

  async revokeSession(input: RevokeSessionInput): Promise<TradeSession | null> {
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
    await this.deleteRedis(input.tenantId, input.id);
    return revoked;
  }

  async revoke(input: RevokeSessionInput): Promise<TradeSession | null> {
    return this.revokeSession(input);
  }

  async incrementSpend(input: IncrementSpendInput): Promise<TradeSession | null> {
    if (!Number.isFinite(input.amountUsd) || input.amountUsd <= 0) {
      throw new Error("amountUsd must be positive");
    }

    const existing = await this.getSession(input);
    if (!existing) return null;
    if (existing.status !== "active") return existing;

    const [row] = await getDb()
      .update(tradeSessions)
      .set({
        dailySpendUsd: sql`${tradeSessions.dailySpendUsd} + ${String(input.amountUsd)}::numeric`,
      })
      .where(and(eq(tradeSessions.id, input.id), eq(tradeSessions.tenantId, input.tenantId)))
      .returning();
    if (!row) return null;
    const updated = await this.refreshExpiry(rowToSession(row));
    await this.writeRedis(updated);
    return updated;
  }

  async listForAgent(input: ListForAgentInput): Promise<TradeSession[]> {
    const rows = await getDb()
      .select()
      .from(tradeSessions)
      .where(
        and(eq(tradeSessions.tenantId, input.tenantId), eq(tradeSessions.agentId, input.agentId)),
      )
      .orderBy(asc(tradeSessions.createdAt));

    const sessions: TradeSession[] = [];
    for (const row of rows) {
      const session = await this.refreshExpiry(rowToSession(row));
      if (input.includeExpired || session.status !== "expired") sessions.push(session);
    }
    return sessions;
  }

  private async refreshExpiry(session: TradeSession): Promise<TradeSession> {
    if (session.status === "active" && session.expiresAt <= this.now()) {
      const expired = { ...session, status: "expired" as const };
      await getDb()
        .update(tradeSessions)
        .set({ status: "expired" })
        .where(and(eq(tradeSessions.id, session.id), eq(tradeSessions.tenantId, session.tenantId)));
      await this.deleteRedis(session.tenantId, session.id);
      return expired;
    }
    return session;
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
    if (!this.redis || session.status !== "active") return;
    const ttlSeconds = Math.max(
      1,
      Math.floor((session.expiresAt.getTime() - this.now().getTime()) / 1000),
    );
    await this.redis
      .setex(sessionKey(session.tenantId, session.id), ttlSeconds, serializeSession(session))
      .catch(() => undefined);
    await this.redis
      .setex(agentIndexKey(session.tenantId, session.agentId), ttlSeconds, session.id)
      .catch(() => undefined);
  }

  private async deleteRedis(tenantId: string, id: string): Promise<void> {
    await this.redis?.del(sessionKey(tenantId, id)).catch(() => 0);
  }

  private async readDb(tenantId: string, id: string): Promise<TradeSession | null> {
    const [row] = await getDb()
      .select()
      .from(tradeSessions)
      .where(and(eq(tradeSessions.id, id), eq(tradeSessions.tenantId, tenantId)));
    return row ? rowToSession(row) : null;
  }
}

import { getDb, tradeSessions } from "@stwd/db";
import type { InferInsertModel } from "drizzle-orm";
import { and, asc, eq, sql } from "drizzle-orm";
import { z } from "zod";

export const tradeSessionStatusSchema = z.enum(["active", "revoked", "expired"]);
export type TradeSessionStatus = z.infer<typeof tradeSessionStatusSchema>;

const coreAllowedAssetSchema = z.enum([
  "BTC",
  "ETH",
  "BNB",
  "SOL",
  "AVAX",
  "ARB",
  "OP",
  "NEAR",
  "HYPE",
  "ZEC",
  "XMR",
]);
// Builder-dex / namespaced perp symbol, e.g. `xyz:SPCX`.
const namespacedAssetSchema = z.string().regex(/^[a-z0-9]+:[A-Z0-9]+$/);
// Prediction-market identifier. Polymarket markets are keyed by CLOB token id
// (a long numeric string), not a ticker. We allow:
//   `pm:<tokenId>`  — a single outcome token (the executable unit)
//   `pm:cond:<conditionId>` — a whole market (both outcomes) by condition id
// Stored alongside crypto assets in the same `allowedAssets` text[] so no schema
// migration is needed; the venue layer interprets the `pm:` namespace.
const predictionMarketAssetSchema = z
  .string()
  .regex(/^pm:(cond:0x[0-9a-fA-F]{1,64}|[0-9]{1,128})$/);
export const allowedAssetSchema = z.union([
  coreAllowedAssetSchema,
  predictionMarketAssetSchema,
  namespacedAssetSchema,
]);
export type AllowedAsset = z.infer<typeof allowedAssetSchema>;

// ---------------------------------------------------------------------------
// Prediction-market allowlist helpers (pure, no IO).
// ---------------------------------------------------------------------------

export function predictionMarketTokenAsset(tokenId: string): string {
  return `pm:${tokenId}`;
}

export function predictionMarketConditionAsset(conditionId: string): string {
  return `pm:cond:${conditionId}`;
}

export function isPredictionMarketAsset(asset: string): boolean {
  return predictionMarketAssetSchema.safeParse(asset).success;
}

/**
 * Is a Polymarket order's market permitted by an allowlist? A token id is allowed
 * when EITHER its own `pm:<tokenId>` entry OR its market's `pm:cond:<conditionId>`
 * entry is present. Passing the conditionId lets a session grant a whole market
 * (both YES/NO outcomes) with one allowlist entry.
 */
export function isPredictionMarketAllowed(
  allowedAssets: readonly string[],
  tokenId: string,
  conditionId?: string,
): boolean {
  const set = new Set(allowedAssets);
  if (set.has(predictionMarketTokenAsset(tokenId))) return true;
  if (conditionId && set.has(predictionMarketConditionAsset(conditionId))) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Pre-venue policy check (pure). The venue route calls this BEFORE placing an
// order so the session's allowlist + per-order cap are enforced regardless of
// venue. Crypto perps match by symbol; prediction markets by pm: token/condition.
// ---------------------------------------------------------------------------

export interface OrderCheckInput {
  /** Symbol for crypto perps (e.g. "NEAR", "xyz:SPCX"). */
  asset?: string;
  /** Polymarket CLOB token id (the executable unit). */
  tokenId?: string;
  /** Polymarket market condition id (grants both outcomes when allowlisted). */
  conditionId?: string;
  /** Notional USD of THIS order; checked against perOrderCapUsd. */
  notionalUsd: number;
}

export type OrderCheckResult =
  | { allowed: true }
  | {
      allowed: false;
      reason:
        | "session-not-active"
        | "asset-not-allowed"
        | "market-not-allowed"
        | "missing-asset-identifier"
        | "invalid-notional"
        | "per-order-cap-exceeded"
        | "daily-cap-exceeded";
    };

/**
 * Validate an order against a session WITHOUT touching IO. Checks, in order:
 * session active, the market/asset is allowlisted, notional is sane, notional
 * <= perOrderCap, and (spend + notional) <= dailyCap. Returns a structured
 * reason on rejection so the caller can map it to an HTTP error + audit event.
 * Spend RESERVATION still happens via reserveSpend() (atomic) — this is the
 * fail-fast gate before the venue call.
 */
export function checkOrderAllowed(
  session: Pick<
    TradeSession,
    "status" | "allowedAssets" | "perOrderCapUsd" | "dailyCapUsd" | "dailySpendUsd"
  >,
  input: OrderCheckInput,
): OrderCheckResult {
  if (session.status !== "active") return { allowed: false, reason: "session-not-active" };

  if (input.tokenId !== undefined) {
    if (!isPredictionMarketAllowed(session.allowedAssets, input.tokenId, input.conditionId)) {
      return { allowed: false, reason: "market-not-allowed" };
    }
  } else if (input.asset !== undefined) {
    if (!session.allowedAssets.includes(input.asset)) {
      return { allowed: false, reason: "asset-not-allowed" };
    }
  } else {
    return { allowed: false, reason: "missing-asset-identifier" };
  }

  if (!Number.isFinite(input.notionalUsd) || input.notionalUsd <= 0) {
    return { allowed: false, reason: "invalid-notional" };
  }
  if (input.notionalUsd > session.perOrderCapUsd) {
    return { allowed: false, reason: "per-order-cap-exceeded" };
  }
  if (session.dailySpendUsd + input.notionalUsd > session.dailyCapUsd) {
    return { allowed: false, reason: "daily-cap-exceeded" };
  }
  return { allowed: true };
}

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

export interface SessionFenceInput extends GetSessionInput {}

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

function sessionFenceKey(tenantId: string, id: string): string {
  return `trade_session_fence_${tenantId}:${id}`;
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

  /**
   * Fetch the active session and run the pre-venue order check against it. The
   * venue route calls this BEFORE placing an order. Returns the loaded session
   * on success so the caller can chain reserveSpend()/withActiveSubmissionFence().
   * `session-not-active` covers both a missing and an inactive/expired session.
   */
  async checkActiveOrder(
    input: GetSessionInput & { order: OrderCheckInput },
  ): Promise<{ session: TradeSession; check: OrderCheckResult }> {
    const session = await this.getSession({ tenantId: input.tenantId, id: input.id });
    if (!session) {
      return {
        session: {
          // synthetic shell so the caller always gets the same shape; status
          // drives the rejection. Not persisted.
          id: input.id,
          agentId: "",
          tenantId: input.tenantId,
          venue: "",
          walletId: "",
          status: "expired",
          dailySpendUsd: 0,
          dailyCapUsd: 1,
          perOrderCapUsd: 1,
          leverageCap: 1,
          allowedAssets: [],
          createdAt: this.now(),
          expiresAt: this.now(),
          revokedAt: null,
          revokedBy: null,
        },
        check: { allowed: false, reason: "session-not-active" },
      };
    }
    return { session, check: checkOrderAllowed(session, input.order) };
  }

  async revokeSession(input: RevokeSessionInput): Promise<TradeSession | null> {
    const revoked = await getDb().transaction(async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtextextended(${sessionFenceKey(input.tenantId, input.id)}, 0))`,
      );
      const [row] = await tx
        .select()
        .from(tradeSessions)
        .where(and(eq(tradeSessions.id, input.id), eq(tradeSessions.tenantId, input.tenantId)));
      if (!row) return null;
      const existing = rowToSession(row);
      if (existing.status === "revoked") return existing;

      const revokedAt = this.now();
      const revokedBy = input.revokedBy ?? null;
      const [revokedRow] = await tx
        .update(tradeSessions)
        .set({ status: "revoked", revokedAt, revokedBy })
        .where(and(eq(tradeSessions.id, input.id), eq(tradeSessions.tenantId, input.tenantId)))
        .returning();
      return revokedRow
        ? rowToSession(revokedRow)
        : { ...existing, status: "revoked" as const, revokedAt, revokedBy };
    });
    if (!revoked) return null;
    await this.deleteRedis(input.tenantId, input.id);
    return revoked;
  }

  async revoke(input: RevokeSessionInput): Promise<TradeSession | null> {
    return this.revokeSession(input);
  }

  async deleteSession(input: GetSessionInput): Promise<void> {
    await getDb()
      .delete(tradeSessions)
      .where(and(eq(tradeSessions.id, input.id), eq(tradeSessions.tenantId, input.tenantId)));
    await this.deleteRedis(input.tenantId, input.id);
  }

  async incrementSpend(input: IncrementSpendInput): Promise<TradeSession | null> {
    return this.reserveSpend(input);
  }

  async reserveSpend(input: IncrementSpendInput): Promise<TradeSession | null> {
    if (!Number.isFinite(input.amountUsd) || input.amountUsd <= 0) {
      throw new Error("amountUsd must be positive");
    }

    const [row] = await getDb()
      .update(tradeSessions)
      .set({
        dailySpendUsd: sql`${tradeSessions.dailySpendUsd} + ${String(input.amountUsd)}::numeric`,
      })
      .where(
        and(
          eq(tradeSessions.id, input.id),
          eq(tradeSessions.tenantId, input.tenantId),
          eq(tradeSessions.status, "active"),
          sql`${tradeSessions.expiresAt} > ${this.now().toISOString()}`,
          sql`${tradeSessions.dailySpendUsd} + ${String(input.amountUsd)}::numeric <= ${tradeSessions.dailyCapUsd}`,
        ),
      )
      .returning();
    if (!row) return null;
    const updated = await this.refreshExpiry(rowToSession(row));
    await this.writeRedis(updated);
    return updated;
  }

  async withActiveSubmissionFence<T>(
    input: SessionFenceInput,
    callback: (session: TradeSession) => Promise<T>,
  ): Promise<T | null> {
    return getDb().transaction(async (tx) => {
      await tx.execute(
        sql`select pg_advisory_xact_lock(hashtextextended(${sessionFenceKey(input.tenantId, input.id)}, 0))`,
      );
      const [row] = await tx
        .select()
        .from(tradeSessions)
        .where(
          and(
            eq(tradeSessions.id, input.id),
            eq(tradeSessions.tenantId, input.tenantId),
            eq(tradeSessions.status, "active"),
            sql`${tradeSessions.expiresAt} > ${this.now().toISOString()}`,
          ),
        );
      if (!row) return null;
      return callback(rowToSession(row));
    });
  }

  async releaseSpend(input: IncrementSpendInput): Promise<TradeSession | null> {
    if (!Number.isFinite(input.amountUsd) || input.amountUsd <= 0) {
      throw new Error("amountUsd must be positive");
    }

    const [row] = await getDb()
      .update(tradeSessions)
      .set({
        dailySpendUsd: sql`greatest(${tradeSessions.dailySpendUsd} - ${String(input.amountUsd)}::numeric, 0)`,
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

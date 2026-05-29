/**
 * Access-token revocation store.
 *
 * Design: user access tokens are short-lived (15m) so logout revocation is
 * mostly defense-in-depth; high-value agent tokens keep their existing longer
 * TTL and use a server-side revocation line. Multi-instance deployments should
 * set REDIS_URL so revocation state is shared. Outside production, this falls
 * back to in-memory state suitable only for single-instance/embedded mode.
 */

import { Redis } from "ioredis";

export class TokenRevokedError extends Error {
  constructor(message = "Token has been revoked") {
    super(message);
    this.name = "TokenRevokedError";
  }
}

type ExpiresAt = Date | number;

export interface RevocationStore {
  revokeToken(jti: string, expiresAt: ExpiresAt): Promise<void>;
  isRevoked(jti: string): Promise<boolean>;
  revokeAgentTokens(agentId: string, issuedBefore?: number, expiresAt?: ExpiresAt): Promise<number>;
  getAgentRevokedBefore(agentId: string): Promise<number | null>;
  revokeUserTokens(userId: string, issuedBefore?: number, expiresAt?: ExpiresAt): Promise<number>;
  getUserRevokedBefore(userId: string): Promise<number | null>;
}

function toMillis(value: ExpiresAt): number {
  return value instanceof Date ? value.getTime() : value > 10_000_000_000 ? value : value * 1000;
}

function ttlMs(expiresAt: ExpiresAt, now = Date.now()): number {
  return Math.max(0, toMillis(expiresAt) - now);
}

const DEFAULT_AGENT_REVOCATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MONOTONIC_REVOCATION_SCRIPT = `
local markerKey = KEYS[1]
local latestKey = KEYS[2]
local issuedBefore = tonumber(ARGV[1])
local ttlMs = tonumber(ARGV[2])
local existing = tonumber(redis.call("GET", latestKey) or "-1")
redis.call("SET", markerKey, "1", "PX", ttlMs)
if existing == nil or issuedBefore > existing then
  redis.call("SET", latestKey, ARGV[1], "PX", ttlMs)
  return issuedBefore
end
redis.call("PEXPIRE", latestKey, ttlMs)
return existing
`;

class InMemoryRevocationStore implements RevocationStore {
  private readonly revokedJtis = new Map<string, number>();
  private readonly agentIssuedBefore = new Map<
    string,
    { issuedBefore: number; expiresAtMs: number }
  >();
  private readonly userIssuedBefore = new Map<
    string,
    { issuedBefore: number; expiresAtMs: number }
  >();

  async revokeToken(jti: string, expiresAt: ExpiresAt): Promise<void> {
    const expiresAtMs = toMillis(expiresAt);
    if (expiresAtMs <= Date.now()) return;
    this.revokedJtis.set(jti, expiresAtMs);
  }

  async isRevoked(jti: string): Promise<boolean> {
    const expiresAtMs = this.revokedJtis.get(jti);
    if (!expiresAtMs) return false;
    if (expiresAtMs <= Date.now()) {
      this.revokedJtis.delete(jti);
      return false;
    }
    return true;
  }

  async revokeAgentTokens(
    agentId: string,
    issuedBefore = Math.floor(Date.now() / 1000),
    expiresAt: ExpiresAt = Date.now() + DEFAULT_AGENT_REVOCATION_TTL_MS,
  ): Promise<number> {
    const expiresAtMs = toMillis(expiresAt);
    const existing = this.agentIssuedBefore.get(agentId);
    if (!existing || issuedBefore > existing.issuedBefore) {
      this.agentIssuedBefore.set(agentId, { issuedBefore, expiresAtMs });
    }
    return issuedBefore;
  }

  async getAgentRevokedBefore(agentId: string): Promise<number | null> {
    const entry = this.agentIssuedBefore.get(agentId);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.agentIssuedBefore.delete(agentId);
      return null;
    }
    return entry.issuedBefore;
  }

  async revokeUserTokens(
    userId: string,
    issuedBefore = Math.floor(Date.now() / 1000),
    expiresAt: ExpiresAt = Date.now() + DEFAULT_AGENT_REVOCATION_TTL_MS,
  ): Promise<number> {
    const expiresAtMs = toMillis(expiresAt);
    const existing = this.userIssuedBefore.get(userId);
    if (!existing || issuedBefore > existing.issuedBefore) {
      this.userIssuedBefore.set(userId, { issuedBefore, expiresAtMs });
    }
    return issuedBefore;
  }

  async getUserRevokedBefore(userId: string): Promise<number | null> {
    const entry = this.userIssuedBefore.get(userId);
    if (!entry) return null;
    if (entry.expiresAtMs <= Date.now()) {
      this.userIssuedBefore.delete(userId);
      return null;
    }
    return entry.issuedBefore;
  }
}

class RedisRevocationStore implements RevocationStore {
  private redis: Redis | null = null;
  private readonly fallback = new InMemoryRevocationStore();

  private getRedis(): Redis | null {
    if (!process.env.REDIS_URL) {
      if (process.env.NODE_ENV === "production") {
        throw new Error("Shared token revocation store unavailable");
      }
      return null;
    }
    if (!this.redis) {
      this.redis = new Redis(process.env.REDIS_URL, {
        maxRetriesPerRequest: 1,
        lazyConnect: false,
        enableReadyCheck: true,
      });
      this.redis.on("error", (err) => {
        console.warn("[steward:auth] Redis revocation unavailable:", err.message);
      });
    }
    return this.redis;
  }

  private fallbackAgentRevokedBefore(agentId: string): Promise<number | null> {
    return this.fallback.getAgentRevokedBefore(agentId);
  }

  private fallbackUserRevokedBefore(userId: string): Promise<number | null> {
    return this.fallback.getUserRevokedBefore(userId);
  }

  async revokeToken(jti: string, expiresAt: ExpiresAt): Promise<void> {
    const ms = ttlMs(expiresAt);
    if (ms <= 0) return;
    const redis = this.getRedis();
    if (!redis) return this.fallback.revokeToken(jti, expiresAt);
    try {
      await redis.set(`revoked:${jti}`, "1", "PX", ms);
    } catch (error) {
      throw new Error("Shared token revocation store unavailable", { cause: error });
    }
  }

  async isRevoked(jti: string): Promise<boolean> {
    const redis = this.getRedis();
    if (!redis) return this.fallback.isRevoked(jti);
    try {
      return (await redis.exists(`revoked:${jti}`)) === 1;
    } catch (error) {
      throw new Error("Shared token revocation store unavailable", { cause: error });
    }
  }

  async revokeAgentTokens(
    agentId: string,
    issuedBefore = Math.floor(Date.now() / 1000),
    expiresAt: ExpiresAt = Date.now() + DEFAULT_AGENT_REVOCATION_TTL_MS,
  ): Promise<number> {
    const ms = ttlMs(expiresAt);
    if (ms <= 0) return issuedBefore;
    const redis = this.getRedis();
    if (!redis) return this.fallback.revokeAgentTokens(agentId, issuedBefore, expiresAt);

    try {
      const markerKey = `revoked-agent:${agentId}:${issuedBefore}`;
      const latestKey = `revoked-agent:${agentId}:issued-before`;
      await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey, latestKey, issuedBefore, ms);
    } catch (error) {
      throw new Error("Shared agent revocation store unavailable", { cause: error });
    }
    return issuedBefore;
  }

  async getAgentRevokedBefore(agentId: string): Promise<number | null> {
    const redis = this.getRedis();
    if (!redis) return this.fallbackAgentRevokedBefore(agentId);
    try {
      const value = await redis.get(`revoked-agent:${agentId}:issued-before`);
      if (!value) return null;
      const issuedBefore = Number(value);
      return Number.isFinite(issuedBefore) ? issuedBefore : null;
    } catch (error) {
      throw new Error("Shared agent revocation store unavailable", { cause: error });
    }
  }

  async revokeUserTokens(
    userId: string,
    issuedBefore = Math.floor(Date.now() / 1000),
    expiresAt: ExpiresAt = Date.now() + DEFAULT_AGENT_REVOCATION_TTL_MS,
  ): Promise<number> {
    const ms = ttlMs(expiresAt);
    if (ms <= 0) return issuedBefore;
    const redis = this.getRedis();
    if (!redis) return this.fallback.revokeUserTokens(userId, issuedBefore, expiresAt);

    try {
      const markerKey = `revoked-user:${userId}:${issuedBefore}`;
      const latestKey = `revoked-user:${userId}:issued-before`;
      await redis.eval(MONOTONIC_REVOCATION_SCRIPT, 2, markerKey, latestKey, issuedBefore, ms);
    } catch (error) {
      throw new Error("Shared user revocation store unavailable", { cause: error });
    }
    return issuedBefore;
  }

  async getUserRevokedBefore(userId: string): Promise<number | null> {
    const redis = this.getRedis();
    if (!redis) return this.fallbackUserRevokedBefore(userId);
    try {
      const value = await redis.get(`revoked-user:${userId}:issued-before`);
      if (!value) return null;
      const issuedBefore = Number(value);
      return Number.isFinite(issuedBefore) ? issuedBefore : null;
    } catch (error) {
      throw new Error("Shared user revocation store unavailable", { cause: error });
    }
  }
}

export const revocationStore: RevocationStore = new RedisRevocationStore();

export async function assertTokenNotRevoked(payload: {
  jti?: string;
  exp?: number;
  iat?: number;
  agentId?: unknown;
  userId?: unknown;
  scope?: unknown;
}): Promise<void> {
  if (payload.jti && (await revocationStore.isRevoked(payload.jti))) {
    throw new TokenRevokedError();
  }

  if (payload.scope === "agent" && typeof payload.agentId === "string" && payload.iat) {
    const issuedBefore = await revocationStore.getAgentRevokedBefore(payload.agentId);
    if (issuedBefore !== null && payload.iat <= issuedBefore) {
      throw new TokenRevokedError(
        "Agent tokens issued at or before the revocation line have been revoked",
      );
    }
  }

  if (typeof payload.userId === "string" && payload.iat) {
    const issuedBefore = await revocationStore.getUserRevokedBefore(payload.userId);
    if (issuedBefore !== null && payload.iat <= issuedBefore) {
      throw new TokenRevokedError(
        "User tokens issued at or before the revocation line have been revoked",
      );
    }
  }
}

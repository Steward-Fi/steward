/**
 * Access-token revocation store.
 *
 * Design: user access tokens are short-lived (15m) so logout revocation is
 * mostly defense-in-depth; high-value agent tokens keep their existing longer
 * TTL and use a server-side revocation line. Multi-instance deployments should
 * set REDIS_URL so revocation state is shared. Without Redis, this falls back
 * to in-memory state suitable only for single-instance/embedded mode.
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
}

function toMillis(value: ExpiresAt): number {
  return value instanceof Date ? value.getTime() : value > 10_000_000_000 ? value : value * 1000;
}

function ttlMs(expiresAt: ExpiresAt, now = Date.now()): number {
  return Math.max(0, toMillis(expiresAt) - now);
}

const DEFAULT_AGENT_REVOCATION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

class InMemoryRevocationStore implements RevocationStore {
  private readonly revokedJtis = new Map<string, number>();
  private readonly agentIssuedBefore = new Map<
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
}

class RedisRevocationStore implements RevocationStore {
  private redis: Redis | null = null;
  private readonly fallback = new InMemoryRevocationStore();

  private getRedis(): Redis | null {
    if (!process.env.REDIS_URL) return null;
    if (!this.redis) {
      this.redis = new Redis(process.env.REDIS_URL, {
        maxRetriesPerRequest: 1,
        lazyConnect: false,
        enableReadyCheck: true,
      });
      this.redis.on("error", (err) => {
        console.warn(
          "[steward:auth] Redis revocation unavailable, using in-memory fallback:",
          err.message,
        );
      });
    }
    return this.redis;
  }

  async revokeToken(jti: string, expiresAt: ExpiresAt): Promise<void> {
    const ms = ttlMs(expiresAt);
    if (ms <= 0) return;
    const redis = this.getRedis();
    if (!redis) return this.fallback.revokeToken(jti, expiresAt);
    try {
      await redis.set(`revoked:${jti}`, "1", "PX", ms);
    } catch {
      await this.fallback.revokeToken(jti, expiresAt);
    }
  }

  async isRevoked(jti: string): Promise<boolean> {
    const redis = this.getRedis();
    if (!redis) return this.fallback.isRevoked(jti);
    try {
      return (await redis.exists(`revoked:${jti}`)) === 1;
    } catch {
      return this.fallback.isRevoked(jti);
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
      await redis
        .multi()
        .set(markerKey, "1", "PX", ms)
        .set(latestKey, String(issuedBefore), "PX", ms)
        .exec();
    } catch {
      await this.fallback.revokeAgentTokens(agentId, issuedBefore, expiresAt);
    }
    return issuedBefore;
  }

  async getAgentRevokedBefore(agentId: string): Promise<number | null> {
    const redis = this.getRedis();
    if (!redis) return this.fallback.getAgentRevokedBefore(agentId);
    try {
      const value = await redis.get(`revoked-agent:${agentId}:issued-before`);
      if (!value) return null;
      const issuedBefore = Number(value);
      return Number.isFinite(issuedBefore) ? issuedBefore : null;
    } catch {
      return this.fallback.getAgentRevokedBefore(agentId);
    }
  }
}

export const revocationStore: RevocationStore = new RedisRevocationStore();

export async function assertTokenNotRevoked(payload: {
  jti?: string;
  exp?: number;
  iat?: number;
  agentId?: unknown;
  scope?: unknown;
}): Promise<void> {
  if (payload.jti && (await revocationStore.isRevoked(payload.jti))) {
    throw new TokenRevokedError();
  }

  if (payload.scope === "agent" && typeof payload.agentId === "string" && payload.iat) {
    const issuedBefore = await revocationStore.getAgentRevokedBefore(payload.agentId);
    if (issuedBefore !== null && payload.iat < issuedBefore) {
      throw new TokenRevokedError(
        "Agent tokens issued before the revocation line have been revoked",
      );
    }
  }
}

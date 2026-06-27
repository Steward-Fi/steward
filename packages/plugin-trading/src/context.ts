/**
 * context.ts — the injected service context the lean core hands the trading
 * plugin at registration.
 *
 * the plugin's routes need shared singletons (db, vault, policy engine, audit
 * writer, redis client, ...) and the auth middleware that gate trade endpoints.
 * those all live in the CORE (`@stwd/api`). to avoid a circular dependency
 * (core must not import plugin; plugin must not import core), the core does NOT
 * export them to the plugin via an import. instead the core BUILDS this context
 * object and passes it to `register(app, ctx)`. the plugin codes against this
 * interface only.
 *
 * everything here is typed against the underlying `@stwd/*` package types (which
 * the plugin may freely depend on), never against `@stwd/api`.
 */

import type { getDb } from "@stwd/db";
import type { PolicyEngine } from "@stwd/policy-engine";
import type { IoredisLike } from "@stwd/redis";
import type { AgentIdentity, AppVariables, PolicyRule, PriceOracle } from "@stwd/shared";
import type { Vault } from "@stwd/vault";
import type { Context, Next } from "hono";

/** the live drizzle db handle (same shape the core's `db` proxy resolves to). */
export type DbHandle = ReturnType<typeof getDb>;

/** the audit event shape the core's `writeAuditEvent` accepts. mirrors @stwd/api's AuditEventInput. */
export interface AuditEventInput {
  tenantId: string;
  actorType: "user" | "agent" | "platform" | "system" | "api-key";
  actorId?: string | null;
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  metadata?: Record<string, unknown>;
  ipAddress?: string | null;
  userAgent?: string | null;
  requestId?: string | null;
}

/** last-observed agent trade-token expiry (read by GET /trade/token-status). */
export interface AgentTokenStatus {
  agentId: string;
  exp: number;
  observedAt: number;
}

/** a hono middleware over the steward app's per-request variables. */
export type StewardMiddleware = (
  c: Context<{ Variables: AppVariables }>,
  next: Next,
) => Promise<void | Response>;

/**
 * the context the core injects into the trading plugin. every member is a core
 * singleton/helper the trade + operator-recovery routes already used by importing
 * `../services/context`, `../services/audit`, `../services/agent-token-status`,
 * and `../middleware/*`. injecting them keeps the plugin decoupled from the core.
 */
export interface StewardAppContext {
  // ── shared singletons ─────────────────────────────────────────────────────
  db: DbHandle;
  vault: Vault;
  policyEngine: PolicyEngine;
  priceOracle: PriceOracle;

  // ── core helpers (from @stwd/api services/context) ────────────────────────
  ensureAgentForTenant(tenantId: string, agentId: string): Promise<AgentIdentity | undefined>;
  getPolicySet(tenantId: string, agentId: string): Promise<PolicyRule[]>;
  safeJsonParse<T>(c: Context): Promise<T | null>;
  isValidAnyAddress(value: unknown): boolean;

  // ── audit + token status (from @stwd/api services) ────────────────────────
  writeAuditEvent(ev: AuditEventInput): Promise<void>;
  getAgentTokenStatus(agentId: string): Promise<AgentTokenStatus | null>;

  // ── redis (from @stwd/api middleware/redis) ───────────────────────────────
  getRedisClient(): IoredisLike | null;

  // ── auth middleware the plugin installs on its own routes ─────────────────
  // requireAgentJwt: agent RS256 trade-token gate for the order endpoints.
  // operatorAuth: platform-key OR tenant-admin gate for fund-recovery endpoints.
  // tenantAuth: the default tenant gate for session-management endpoints.
  requireAgentJwt: StewardMiddleware;
  operatorAuth: StewardMiddleware;
  tenantAuth: (
    c: Context<{ Variables: AppVariables }>,
    next: Next,
    options?: { requireTenantMatch?: string },
  ) => Promise<void | Response>;
}

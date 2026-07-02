/**
 * context.ts - the injected service context the lean core hands the capability
 * plugin at registration.
 *
 * the plugin's routes need shared core singletons (db, audit writer, the agent
 * resolver, json parsing) and the auth middleware that gate operator/tenant
 * endpoints. those live in the CORE (`@stwd/api`). to avoid a circular dependency
 * (core must not import plugin; plugin must not import core), the core does NOT
 * export them to the plugin via an import - it BUILDS this context object and
 * passes it to `register(app, ctx)`. the plugin codes against this interface only.
 *
 * this shape mirrors `@stwd/api`'s `StewardAppContext` (identical to
 * `@stwd/plugin-trading`'s), so the context the core BUILDS (`buildPluginContext()`)
 * is assignable to it at the W-1c composition root. every member is typed against
 * the underlying `@stwd/*` package types, never `@stwd/api`.
 */

import type { getDb } from "@stwd/db";
import type { PolicyEngine } from "@stwd/policy-engine";
import type { IoredisLike } from "@stwd/redis";
import type { AgentIdentity, AppVariables, PolicyRule, PriceOracle } from "@stwd/shared";
import type { Vault } from "@stwd/vault";
import type { Context, Next } from "hono";

/** the live drizzle db handle (same shape the core's `db` proxy resolves to). */
export type DbHandle = ReturnType<typeof getDb>;

/** the audit event shape the core's `writeAuditEvent` accepts (mirrors @stwd/api). */
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

/** last-observed agent trade-token expiry (part of the shared ctx shape). */
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
 * the context the core injects into the capability plugin. structurally matches
 * `@stwd/api`'s `StewardAppContext` (so the core-built context is assignable at
 * the composition root); the capability routes use a subset (db, ensureAgentForTenant,
 * safeJsonParse, writeAuditEvent, operatorAuth, tenantAuth).
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
  requireAgentJwt: StewardMiddleware;
  operatorAuth: StewardMiddleware;
  tenantAuth: (
    c: Context<{ Variables: AppVariables }>,
    next: Next,
    options?: { requireTenantMatch?: string },
  ) => Promise<void | Response>;
}

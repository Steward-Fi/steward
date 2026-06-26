/**
 * app-variables.ts — the per-request context variables the steward hono app
 * carries (the `Variables` of `Hono<{ Variables: AppVariables }>`).
 *
 * this lives in `@stwd/shared` (not in `@stwd/api`) so that an opt-in plugin can
 * type its own hono routes against the same per-request context WITHOUT importing
 * `@stwd/api`. that keeps the core free of any plugin dependency and keeps plugins
 * free of a circular dependency back on the core. the auth middleware that POPULATES
 * these variables stays in the core; only the shared shape lives here.
 */

import type { Tenant, TenantConfig } from "../index.js";

export type AppVariables = {
  tenant: Tenant;
  tenantConfig: TenantConfig;
  tenantId: string;
  userId?: string;
  tenantRole?: string;
  sessionMfaVerifiedAt?: number;
  sessionMfaMethod?: string;
  agentScope?: string;
  agentSubject?: string;
  agentScopes?: string[];
  authType?:
    | "api-key"
    | "app-secret"
    | "session-jwt"
    | "agent-token"
    | "dashboard-jwt"
    | "platform";
  requestSignatureVerified?: boolean;
  requestId?: string;
  platformKeyHash?: string;
  platformScopes?: string[];
  agentPolicyIds?: string[];
};

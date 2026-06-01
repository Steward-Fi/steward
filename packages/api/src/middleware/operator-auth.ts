/**
 * operator-auth.ts — Auth gate for operator fund-recovery endpoints.
 *
 * The operator close-all + withdraw endpoints must be reachable by a HUMAN
 * operator even when no valid agent JWT exists (the expired-token / control-
 * plane-down scenario the recovery feature exists to solve).
 *
 * This middleware accepts EITHER credential:
 *   1. A platform key — header `X-Steward-Platform-Key`, validated by
 *      `isValidPlatformKey`. This is the cross-tenant operator credential
 *      (issued out-of-band to trusted operators such as Eliza Cloud).
 *   2. A tenant-admin credential — falls through to `tenantAuth`, which
 *      accepts a tenant API key (`X-Steward-Key` + `X-Steward-Tenant`) or a
 *      user session JWT.
 *
 * It deliberately does NOT use `requireAgentJwt`. That RS256 path is exactly
 * what stranded funds when the agent token expired.
 *
 * On platform-key auth we still need a tenant context. The platform operator
 * supplies it via `X-Steward-Tenant`; we look the tenant up and set the
 * standard context vars so downstream handlers behave identically to the
 * tenant-auth path.
 */

import { isValidPlatformKey } from "@stwd/auth";
import type { Context, Next } from "hono";
import {
  type ApiResponse,
  type AppVariables,
  DEFAULT_TENANT_ID,
  findTenant,
  tenantAuth,
  tenantConfigs,
} from "../services/context";

export async function operatorAuth(c: Context<{ Variables: AppVariables }>, next: Next) {
  const platformKey = c.req.header("X-Steward-Platform-Key");

  if (platformKey) {
    if (!isValidPlatformKey(platformKey)) {
      return c.json<ApiResponse>({ ok: false, error: "Invalid platform key" }, 403);
    }

    const tenantId = c.req.header("X-Steward-Tenant") || DEFAULT_TENANT_ID;
    const tenant = await findTenant(tenantId);
    if (!tenant) return c.json<ApiResponse>({ ok: false, error: "Tenant not found" }, 404);

    c.set("tenantId", tenantId);
    c.set("tenant", tenant);
    c.set("tenantConfig", tenantConfigs.get(tenantId) || { id: tenant.id, name: tenant.name });
    c.set("authType", "platform");
    return next();
  }

  // No platform key supplied — require tenant-admin auth instead.
  return tenantAuth(c, next);
}

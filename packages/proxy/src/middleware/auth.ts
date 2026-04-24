/**
 * JWT authentication middleware for the proxy.
 *
 * Validates the agent's Bearer token, extracts agentId/tenantId,
 * and sets them on the Hono context for downstream handlers.
 */

import { verifyToken } from "@stwd/auth";
import type { Context, Next } from "hono";
import { PROXY_SCOPE } from "../config";

const AGENT_SCOPE = "agent";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AgentClaims {
  agentId: string;
  tenantId: string;
  /** Legacy singular scope. Kept for backward compatibility. */
  scope: string;
  /** New explicit permissions list. Proxy access requires api:proxy. */
  scopes?: string[];
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * Authenticate incoming requests via Bearer JWT.
 *
 * Sets `agentId` and `tenantId` on the Hono context variables.
 * Rejects with 401 if token is missing/invalid, 403 if scope is wrong.
 */
export async function authMiddleware(c: Context, next: Next) {
  const authHeader = c.req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json({ ok: false, error: "Missing or invalid Authorization header" }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifyToken(token);

    const agentId = payload.agentId as string | undefined;
    const tenantId = payload.tenantId as string | undefined;
    const scope = payload.scope as string | undefined;
    const scopes = payload.scopes;

    if (!agentId || !tenantId) {
      return c.json({ ok: false, error: "Token missing agentId or tenantId claims" }, 401);
    }

    if (Array.isArray(scopes)) {
      if (!scopes.includes(PROXY_SCOPE)) {
        return c.json({ ok: false, error: `Token missing required ${PROXY_SCOPE} scope` }, 403);
      }
    } else if (scopes === undefined && scope === AGENT_SCOPE) {
      // Backward compatibility for legacy agent tokens minted before the plural
      // scopes claim existed. Keep for 1-2 release cycles, then reject.
      console.warn(
        `[proxy:auth] Legacy agent token without scopes accepted for agent ${agentId}; ` +
          `mint a replacement token with scopes including ${PROXY_SCOPE}. This fallback will be removed in a future release.`,
      );
    } else {
      return c.json({ ok: false, error: `Token missing required ${PROXY_SCOPE} scope` }, 403);
    }

    // Set on context for downstream handlers
    c.set("agentId", agentId);
    c.set("tenantId", tenantId);

    await next();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Token verification failed";
    return c.json({ ok: false, error: `Authentication failed: ${message}` }, 401);
  }
}

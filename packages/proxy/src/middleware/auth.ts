/**
 * JWT authentication middleware for the proxy.
 *
 * Validates the agent's Bearer token, extracts agentId/tenantId,
 * and sets them on the Hono context for downstream handlers.
 */

import { verifyToken } from "@stwd/auth";
import type { Context, Next } from "hono";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface AgentClaims {
  agentId: string;
  tenantId: string;
  scope: string;
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

    if (!agentId || !tenantId) {
      return c.json({ ok: false, error: "Token missing agentId or tenantId claims" }, 401);
    }

    // For now, all agent tokens implicitly have api:proxy scope.
    // In the future we'll check: scope === "agent" || scopes.includes("api:proxy")
    if (scope !== "agent") {
      return c.json({ ok: false, error: "Token does not have agent scope" }, 403);
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

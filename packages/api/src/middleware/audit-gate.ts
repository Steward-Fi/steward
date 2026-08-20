/**
 * Shared owner/admin + recent-MFA gate for evidence surfaces.
 *
 * Both `/audit/*` and `/v2/provider-actions/:id/{case,evidence}` require
 * the SAME authorization posture (spec §5.2): a `session-jwt` caller with
 * tenant role `owner` or `admin`, recent MFA (≤5 min), and `no-store` headers.
 * Agent tokens are rejected. Factoring the gate here guarantees the case routes
 * inherit an IDENTICAL (never weaker) gate rather than re-implementing it (spec
 * §6.3: "Do not create a new router with a weaker gate").
 */

import type { Context, Next } from "hono";
import { type ApiResponse, type AppVariables, setNoStoreHeaders } from "../services/context";
import { isRecentMfaTimestamp } from "../services/recent-mfa";

/** Recent-MFA window for evidence reads (spec §5.2 / audit.ts). */
export const AUDIT_READ_MFA_MAX_AGE_MS = 5 * 60_000;

export function hasRecentSessionMfa(
  c: Context<{ Variables: AppVariables }>,
  maxAgeMs = AUDIT_READ_MFA_MAX_AGE_MS,
): boolean {
  return isRecentMfaTimestamp(c.get("sessionMfaVerifiedAt"), maxAgeMs);
}

/**
 * The owner/admin + recent-MFA gate. Returns a 403 (generic, non-enumerating)
 * for a non-owner/admin session, an agent token, or stale MFA; otherwise sets
 * no-store headers and continues.
 */
export async function auditOwnerAdminMfaGate(
  c: Context<{ Variables: AppVariables }>,
  next: Next,
): Promise<Response | void> {
  const role = c.get("tenantRole");
  if (c.get("authType") !== "session-jwt" || (role !== "owner" && role !== "admin")) {
    return c.json<ApiResponse>(
      { ok: false, error: "Audit routes require owner or admin session" },
      403,
    );
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Audit routes require recent MFA verification" },
      403,
    );
  }
  setNoStoreHeaders(c);
  return next();
}

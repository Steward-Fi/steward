/**
 * Session signers — labeled, scoped, revocable delegated signing tokens.
 *
 * A session signer is an agent JWT (scope: "agent") with:
 *  - a unique jti recorded in `session_signers`
 *  - a custom expiry (default 24h, max 30d)
 *  - an optional subset of the agent's policies enforced when this token signs
 *  - operator-friendly label for the dashboard / audit log
 *
 * Mount: app.route("/agents/:agentId/session-signers", sessionSignerRoutes)
 */

import { randomUUID } from "node:crypto";

import { revocationStore, signAgentToken } from "@stwd/auth";
import { auditEvents, sessionSigners } from "@stwd/db";
import { and, desc, eq, isNull } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  ensureAgentForTenant,
  isNonEmptyString,
  parseAgentTokenScopes,
  policies,
  requireTenantLevel,
  safeJsonParse,
  setNoStoreHeaders,
} from "../services/context";

const MAX_LIFETIME_MS = 30 * 24 * 3600 * 1000;
const DEFAULT_LIFETIME_MS = 24 * 3600 * 1000;
const LABEL_MAX_LEN = 128;

/** Parse a duration string like "30m", "24h", "7d" into ms. Returns null on parse error. */
function parseDuration(input: string): number | null {
  const m = /^(\d+)\s*(s|m|h|d)$/i.exec(input.trim());
  if (!m) return null;
  const n = Number(m[1]);
  const unit = m[2].toLowerCase();
  if (!Number.isFinite(n) || n <= 0) return null;
  const mult = unit === "s" ? 1000 : unit === "m" ? 60_000 : unit === "h" ? 3_600_000 : 86_400_000;
  return n * mult;
}

export const sessionSignerRoutes = new Hono<{ Variables: AppVariables }>();

sessionSignerRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

function requireTenantAdminSession(c: Parameters<typeof requireTenantLevel>[0]): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function hasRecentSessionMfa(c: Parameters<typeof requireTenantLevel>[0], maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

function requireRecentAdminMfa(c: Parameters<typeof requireTenantLevel>[0], reason: string) {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

async function hasRevocationAudit(tenantId: string, signerId: string): Promise<boolean> {
  const rows = await db
    .select({ id: auditEvents.id })
    .from(auditEvents)
    .where(
      and(
        eq(auditEvents.tenantId, tenantId),
        eq(auditEvents.action, "session_signer.revoked"),
        eq(auditEvents.resourceType, "session_signer"),
        eq(auditEvents.resourceId, signerId),
      ),
    )
    .limit(1);
  return rows.length > 0;
}

async function writeSessionSignerRevokedAudit(
  c: Parameters<typeof requireTenantLevel>[0],
  tenantId: string,
  agentId: string,
  signerId: string,
  jti: string,
): Promise<void> {
  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? tenantId,
    action: "session_signer.revoked",
    resourceType: "session_signer",
    resourceId: signerId,
    metadata: { agentId, jti },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });
}

// POST /agents/:agentId/session-signers
sessionSignerRoutes.post("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Session signer creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Session signer creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  if (!tenantId || !agentId) {
    return c.json<ApiResponse>({ ok: false, error: "Missing tenant or agent context" }, 400);
  }
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const body = await safeJsonParse<{
    label: string;
    expiresIn?: string;
    scopes?: string[] | string;
    policyIds?: string[];
  }>(c);
  if (!body || !isNonEmptyString(body.label)) {
    return c.json<ApiResponse>(
      { ok: false, error: "'label' is required and must be a non-empty string" },
      400,
    );
  }
  if (body.label.length > LABEL_MAX_LEN) {
    return c.json<ApiResponse>(
      { ok: false, error: `'label' must be at most ${LABEL_MAX_LEN} characters` },
      400,
    );
  }

  const scopes = parseAgentTokenScopes(body.scopes);
  if (!scopes) {
    return c.json<ApiResponse>(
      { ok: false, error: "Invalid scopes — supported values: agent, api:proxy" },
      400,
    );
  }

  let lifetimeMs = DEFAULT_LIFETIME_MS;
  if (body.expiresIn) {
    const parsed = parseDuration(body.expiresIn);
    if (parsed === null) {
      return c.json<ApiResponse>(
        { ok: false, error: "'expiresIn' must be like '30m', '24h', '7d'" },
        400,
      );
    }
    lifetimeMs = Math.min(parsed, MAX_LIFETIME_MS);
  }
  const expiresAt = new Date(Date.now() + lifetimeMs);

  // Validate that any provided policyIds are policies attached to THIS agent.
  // Without this check, a tenant operator could pin a signer to a policy
  // belonging to another agent within the tenant — the signing path wouldn't
  // honor it, but the metadata would be misleading.
  let policyIds: string[] = [];
  if (Array.isArray(body.policyIds) && body.policyIds.length > 0) {
    const rows = await db
      .select({ id: policies.id })
      .from(policies)
      .where(eq(policies.agentId, agentId));
    const owned = new Set(rows.map((r) => r.id));
    for (const id of body.policyIds) {
      if (!owned.has(id)) {
        return c.json<ApiResponse>(
          { ok: false, error: `policyId ${id} does not belong to agent ${agentId}` },
          400,
        );
      }
    }
    policyIds = body.policyIds;
  }

  const jti = randomUUID();
  const expiresInSeconds = Math.floor(lifetimeMs / 1000);
  const token = await signAgentToken({ agentId, tenantId, scopes, jti }, `${expiresInSeconds}s`);

  const [row] = await db
    .insert(sessionSigners)
    .values({
      tenantId,
      agentId,
      jti,
      label: body.label,
      scopes,
      policyIds,
      expiresAt,
    })
    .returning();

  // Minting a delegated signing credential is a security-relevant mutation, so
  // its audit record must be durable (non-repudiation). Write it BLOCKING; if
  // the tamper-evident append fails, roll the issuance back (revoke the jti +
  // delete the row) so we never hand back a credential that has no audit trail.
  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? tenantId,
      action: "session_signer.created",
      resourceType: "session_signer",
      resourceId: row.id,
      metadata: {
        agentId,
        label: body.label,
        scopes,
        policyIds,
        expiresAt: expiresAt.toISOString(),
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (err) {
    console.error(`[session-signer] audit write failed; rolling back issuance ${row.id}:`, err);
    try {
      await revocationStore.revokeToken(jti, Math.floor(expiresAt.getTime() / 1000));
      await db.delete(sessionSigners).where(eq(sessionSigners.id, row.id));
    } catch (rollbackErr) {
      // Best-effort cleanup failed; the jti was at least revocation-attempted.
      console.error(
        `[session-signer] rollback after audit failure failed for ${row.id}:`,
        rollbackErr,
      );
    }
    return c.json<ApiResponse>(
      { ok: false, error: "Failed to record session signer creation; issuance rolled back" },
      500,
    );
  }

  return c.json<ApiResponse>({
    ok: true,
    data: {
      id: row.id,
      jti,
      token,
      label: row.label,
      scopes,
      policyIds,
      expiresAt: row.expiresAt,
      createdAt: row.createdAt,
    },
  });
});

// GET /agents/:agentId/session-signers
sessionSignerRoutes.get("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Session signer access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Session signer access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  if (!tenantId || !agentId) {
    return c.json<ApiResponse>({ ok: false, error: "Missing tenant or agent context" }, 400);
  }
  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  const showRevoked = c.req.query("includeRevoked") === "true";
  const rows = await db
    .select({
      id: sessionSigners.id,
      label: sessionSigners.label,
      scopes: sessionSigners.scopes,
      policyIds: sessionSigners.policyIds,
      expiresAt: sessionSigners.expiresAt,
      createdAt: sessionSigners.createdAt,
      revokedAt: sessionSigners.revokedAt,
      lastUsedAt: sessionSigners.lastUsedAt,
    })
    .from(sessionSigners)
    .where(
      showRevoked
        ? and(eq(sessionSigners.tenantId, tenantId), eq(sessionSigners.agentId, agentId))
        : and(
            eq(sessionSigners.tenantId, tenantId),
            eq(sessionSigners.agentId, agentId),
            isNull(sessionSigners.revokedAt),
          ),
    )
    .orderBy(desc(sessionSigners.createdAt));

  return c.json<ApiResponse>({ ok: true, data: rows });
});

// DELETE /agents/:agentId/session-signers/:id
sessionSignerRoutes.delete("/:id", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Session signer revocation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentAdminMfa(c, "Session signer revocation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const agentId = c.req.param("agentId");
  const signerId = c.req.param("id");
  if (!tenantId || !agentId || !signerId) {
    return c.json<ApiResponse>({ ok: false, error: "Missing tenant, agent, or signer id" }, 400);
  }

  const agent = await ensureAgentForTenant(tenantId, agentId);
  if (!agent) {
    return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
  }

  // Fetch the row first so we can refuse cross-agent revocation and surface a
  // clean 404 instead of silently mutating zero rows.
  const [existing] = await db
    .select()
    .from(sessionSigners)
    .where(
      and(
        eq(sessionSigners.id, signerId),
        eq(sessionSigners.tenantId, tenantId),
        eq(sessionSigners.agentId, agentId),
      ),
    );
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Session signer not found" }, 404);
  }
  if (existing.revokedAt) {
    if (!(await hasRevocationAudit(tenantId, signerId))) {
      try {
        await writeSessionSignerRevokedAudit(c, tenantId, agentId, signerId, existing.jti);
      } catch (err) {
        console.error(
          `[session-signer] audit repair failed for already-revoked signer ${signerId}:`,
          err,
        );
        return c.json<ApiResponse>(
          {
            ok: false,
            error:
              "Session signer is revoked but audit record failed to persist; retry to record it",
          },
          500,
        );
      }
    }
    return c.json<ApiResponse>({ ok: true, data: { alreadyRevoked: true, id: signerId } });
  }

  await revocationStore.revokeToken(existing.jti, Math.floor(existing.expiresAt.getTime() / 1000));

  const now = new Date();
  await db.update(sessionSigners).set({ revokedAt: now }).where(eq(sessionSigners.id, signerId));

  // Revoking a delegated signing credential is a security-relevant mutation; its
  // audit record must be durable. Write it BLOCKING. We do NOT roll back on
  // failure — the credential is already revoked (the safe direction) and
  // un-revoking would re-enable a credential the operator asked to kill. The
  // already-revoked branch above verifies or repairs the audit record so a
  // retry after a transient audit outage can still complete the trail.
  try {
    await writeSessionSignerRevokedAudit(c, tenantId, agentId, signerId, existing.jti);
  } catch (err) {
    console.error(`[session-signer] audit write failed for revocation ${signerId}:`, err);
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Session signer revoked but audit record failed to persist; retry to record it",
      },
      500,
    );
  }

  return c.json<ApiResponse>({ ok: true, data: { id: signerId, revokedAt: now } });
});

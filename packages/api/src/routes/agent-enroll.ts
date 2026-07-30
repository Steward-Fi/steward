/**
 * agent-enroll.ts — the PUBLIC keypair-only agent enrollment surface (lane A1,
 * scope 1). Mounted BEFORE the tenant gate: an enrolling agent holds only its
 * identity keypair, not a token or an API key.
 *
 *   POST /agent-enroll/challenge  { agentId }
 *        → { nonce, canonicalString, expiresAt }  (single-use, short TTL)
 *
 *   POST /agent-enroll/verify     { agentId, nonce, signature }
 *        → { token, agentId, tenantId, scope, scopes, expiresIn }  (short-lived)
 *
 * Reuses the shipped crypto + stores:
 *   - challenge/response + P-256 verify: @stwd/auth agent-enroll core.
 *   - registered key: `agent_signers` (keyType="p256", status="active").
 *   - token mint: signAgentToken (short TTL — minute-scale, so revocation via a
 *     signer status flip lands at the next enroll cycle).
 *
 * The tenant is derived SERVER-SIDE from the resolved signer row, never taken
 * from the request. Fail-closed everywhere: any resolution/verify failure denies
 * with a generic message (no enumeration signal beyond "denied").
 */

import {
  type AgentSignerResolver,
  challengeStore,
  issueEnrollChallenge,
  type ResolvedAgentSigner,
  signAgentToken,
  verifyEnrollResponse,
} from "@stwd/auth";
import { agentSigners, eq } from "@stwd/db";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import { type ApiResponse, type AppVariables, db, safeJsonParse } from "../services/context";

/** Short-lived enrollment token TTL. Minute-scale: the agent immediately renews
 * (or exchanges for scoped capabilities), and a revoked signer stops enrolling
 * within one cycle. Overridable via env for operators who want a different bound. */
const ENROLL_TOKEN_TTL = process.env.STEWARD_AGENT_ENROLL_TOKEN_TTL?.trim() || "5m";

export const agentEnrollRoutes = new Hono<{ Variables: AppVariables }>();

/** Resolve an agent's ACTIVE p256 signer rows (+ its tenant) from agent_signers.
 * Returns the signers for the enrollment core AND the resolved tenantId (set as a
 * side effect via the out-param map) — kept as two calls to keep the core pure. */
async function resolveP256Signers(agentId: string): Promise<{
  signers: ResolvedAgentSigner[];
  tenantId: string | null;
}> {
  const rows = await db
    .select({
      publicKey: agentSigners.publicKey,
      status: agentSigners.status,
      keyType: agentSigners.keyType,
      tenantId: agentSigners.tenantId,
    })
    .from(agentSigners)
    .where(eq(agentSigners.agentId, agentId));

  const signers: ResolvedAgentSigner[] = [];
  let tenantId: string | null = null;
  for (const r of rows) {
    if (r.keyType === "p256" && r.status === "active" && typeof r.publicKey === "string") {
      signers.push({ publicKey: r.publicKey, status: r.status, keyType: r.keyType });
      tenantId = r.tenantId; // all rows for an agent share a tenant (FK)
    }
  }
  return { signers, tenantId };
}

// ── POST /challenge ──────────────────────────────────────────────────────────
agentEnrollRoutes.post("/challenge", async (c) => {
  const body = await safeJsonParse<{ agentId?: unknown }>(c);
  const agentId = typeof body?.agentId === "string" ? body.agentId.trim() : "";
  if (!agentId) {
    return c.json<ApiResponse>({ ok: false, error: "agentId required" }, 400);
  }

  const issued = await issueEnrollChallenge(challengeStore, agentId);
  if (!issued.ok) {
    return c.json<ApiResponse>({ ok: false, error: "enrollment unavailable" }, 503);
  }
  // Do NOT leak whether the agent exists (enumeration resistance): a challenge is
  // handed out regardless; verify fails closed for unknown/keyless agents.
  return c.json<ApiResponse>({
    ok: true,
    data: {
      agentId: issued.challenge.agentId,
      nonce: issued.challenge.nonce,
      canonicalString: issued.challenge.canonicalString,
      expiresAt: issued.challenge.expiresAt,
    },
  });
});

// ── POST /verify ─────────────────────────────────────────────────────────────
agentEnrollRoutes.post("/verify", async (c) => {
  const body = await safeJsonParse<{
    agentId?: unknown;
    nonce?: unknown;
    signature?: unknown;
  }>(c);
  const agentId = typeof body?.agentId === "string" ? body.agentId.trim() : "";
  const nonce = typeof body?.nonce === "string" ? body.nonce.trim() : "";
  const signature = typeof body?.signature === "string" ? body.signature.trim() : "";
  if (!agentId || !nonce || !signature) {
    return c.json<ApiResponse>({ ok: false, error: "agentId, nonce and signature required" }, 400);
  }

  // Resolve signers ONCE; the enrollment core is handed a thin resolver closure so
  // it stays db-agnostic. We keep the tenant from the same query.
  let resolvedTenant: string | null = null;
  const resolver: AgentSignerResolver = async (id) => {
    const { signers, tenantId } = await resolveP256Signers(id);
    resolvedTenant = tenantId;
    return signers;
  };

  const result = await verifyEnrollResponse(challengeStore, resolver, {
    agentId,
    nonce,
    signature,
  });

  if (!result.ok) {
    // Uniform generic denial (never leak which step failed). Fail closed on
    // evidence: if this append breaks, enrollment verification returns an error
    // rather than producing an unaudited denial path.
    await writeAuditEvent({
      tenantId: resolvedTenant ?? "unknown",
      actorType: "agent",
      actorId: agentId,
      action: "capability.enroll",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { decision: "deny", code: result.code },
    });
    return c.json<ApiResponse>({ ok: false, error: "enrollment denied" }, 401);
  }

  if (!resolvedTenant) {
    // Verified but tenant unresolved (should not happen — verify required an
    // active signer, which carries a tenant). Fail closed.
    return c.json<ApiResponse>({ ok: false, error: "enrollment denied" }, 401);
  }

  // Fail closed before minting the bearer token: no successful enrollment token
  // leaves the server unless its evidence row was appended to the tenant chain.
  await writeAuditEvent({
    tenantId: resolvedTenant,
    actorType: "agent",
    actorId: agentId,
    action: "capability.enroll",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { decision: "allow", ttl: ENROLL_TOKEN_TTL },
  });

  const token = await signAgentToken(
    { agentId, tenantId: resolvedTenant, scopes: ["agent"] },
    ENROLL_TOKEN_TTL,
  );

  c.header("Cache-Control", "no-store, max-age=0");
  c.header("Pragma", "no-cache");
  return c.json<ApiResponse>({
    ok: true,
    data: {
      token,
      agentId,
      tenantId: resolvedTenant,
      scope: "agent",
      scopes: ["agent"],
      expiresIn: ENROLL_TOKEN_TTL,
    },
  });
});

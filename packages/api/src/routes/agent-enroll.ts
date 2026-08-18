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
 *   - challenge persistence: the API's initialized ChallengeStore (Redis or
 *     Postgres in production — see initAuthStores), so challenges survive
 *     restarts and verify can land on a different instance than challenge.
 *   - registered key: `agent_signers` (keyType="p256", status="active").
 *   - token mint: signAgentToken (short TTL — minute-scale, so revocation via a
 *     signer status flip lands at the next enroll cycle).
 *
 * The tenant is derived SERVER-SIDE from the resolved signer row, never taken
 * from the request. Fail-closed everywhere: any resolution/verify failure denies
 * with a generic message (no enumeration signal beyond "denied"). Both endpoints
 * are unauthenticated, so they sit behind the same Redis-backed auth rate
 * limiter as the other public auth surfaces (SEC-051).
 */

import {
  type AgentSignerResolver,
  issueEnrollChallenge,
  parseDurationSeconds,
  type ResolvedAgentSigner,
  signAgentToken,
  verifyEnrollResponse,
} from "@stwd/auth";
import { agentSigners, eq } from "@stwd/db";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  isValidAgentId,
  safeJsonParse,
} from "../services/context";
import { checkAuthRateLimit, getAuthChallengeStore } from "./auth";

/** Short-lived enrollment token TTL. Minute-scale: the agent immediately renews
 * (or exchanges for scoped capabilities), and a revoked signer stops enrolling
 * within one cycle. Overridable via env for operators who want a different bound. */

/** Hard upper bound for the enrollment token TTL: one hour. Enrollment tokens
 * exist only to bootstrap renewal/capability exchange, so a longer value would
 * blunt signer-revocation response (SEC-134-style bound for this env). */
export const ENROLL_TOKEN_TTL_MAX_SECONDS = 3600;

/** Validate STEWARD_AGENT_ENROLL_TOKEN_TTL at module load (startup), the same
 * posture SEC-134 applied to AGENT_TOKEN_EXPIRY: a malformed value otherwise
 * surfaces as a 500 at token-mint time, and an unbounded value mints
 * long-lived tokens that defeat the minute-scale revocation story. */
function resolveEnrollTokenTtl(): string {
  const raw = process.env.STEWARD_AGENT_ENROLL_TOKEN_TTL?.trim();
  if (!raw) return "5m";
  const seconds = parseDurationSeconds(raw);
  if (seconds === null) {
    throw new Error(
      `⛔ STEWARD_AGENT_ENROLL_TOKEN_TTL "${raw}" is not a valid positive duration (examples: "5m", "15m", "1h").`,
    );
  }
  if (seconds > ENROLL_TOKEN_TTL_MAX_SECONDS) {
    throw new Error(
      `⛔ STEWARD_AGENT_ENROLL_TOKEN_TTL "${raw}" exceeds the one-hour maximum; enrollment tokens must stay minute-scale so signer revocation lands quickly.`,
    );
  }
  return raw;
}

const ENROLL_TOKEN_TTL = resolveEnrollTokenTtl();

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
  const rl = await checkAuthRateLimit(c, "agent-enroll-challenge", 60_000, 30);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many enrollment attempts. Try again later." },
      429,
      { "Retry-After": String(rl.retryAfterSecs ?? 60) },
    );
  }

  const body = await safeJsonParse<{ agentId?: unknown }>(c);
  const agentId = typeof body?.agentId === "string" ? body.agentId.trim() : "";
  if (!agentId) {
    return c.json<ApiResponse>({ ok: false, error: "agentId required" }, 400);
  }
  // Cap length + charset (schema shape): the agentId is embedded in the store
  // key, so an uncapped value pins attacker-controlled memory per request.
  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>({ ok: false, error: "invalid agentId" }, 400);
  }

  const issued = await issueEnrollChallenge(getAuthChallengeStore(), agentId);
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
  const rl = await checkAuthRateLimit(c, "agent-enroll-verify", 60_000, 20);
  if (!rl.allowed) {
    return c.json<ApiResponse>(
      { ok: false, error: "Too many enrollment attempts. Try again later." },
      429,
      { "Retry-After": String(rl.retryAfterSecs ?? 60) },
    );
  }

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
  if (!isValidAgentId(agentId)) {
    return c.json<ApiResponse>({ ok: false, error: "invalid agentId" }, 400);
  }

  // Resolve signers ONCE; the enrollment core is handed a thin resolver closure so
  // it stays db-agnostic. We keep the tenant from the same query.
  let resolvedTenant: string | null = null;
  const resolver: AgentSignerResolver = async (id) => {
    const { signers, tenantId } = await resolveP256Signers(id);
    resolvedTenant = tenantId;
    return signers;
  };

  const result = await verifyEnrollResponse(getAuthChallengeStore(), resolver, {
    agentId,
    nonce,
    signature,
  });

  if (!result.ok) {
    // Uniform generic denial (never leak which step failed).
    await writeAuditEvent({
      tenantId: resolvedTenant ?? "unknown",
      actorType: "agent",
      actorId: agentId,
      action: "capability.enroll",
      resourceType: "agent",
      resourceId: agentId,
      metadata: { decision: "deny", code: result.code },
    }).catch((error) => {
      console.error("[agent-enroll] Failed to record denied enrollment:", error);
    });
    return c.json<ApiResponse>({ ok: false, error: "enrollment denied" }, 401);
  }

  if (!resolvedTenant) {
    // Verified but tenant unresolved (should not happen — verify required an
    // active signer, which carries a tenant). Fail closed.
    return c.json<ApiResponse>({ ok: false, error: "enrollment denied" }, 401);
  }

  const token = await signAgentToken(
    { agentId, tenantId: resolvedTenant, scopes: ["agent"] },
    ENROLL_TOKEN_TTL,
  );

  await writeAuditEvent({
    tenantId: resolvedTenant,
    actorType: "agent",
    actorId: agentId,
    action: "capability.enroll",
    resourceType: "agent",
    resourceId: agentId,
    metadata: { decision: "allow", ttl: ENROLL_TOKEN_TTL },
  });

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

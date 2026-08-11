/**
 * provider-approvals.ts — PR3 human approval + safe-resume HTTP surface (spec §9).
 *
 *   GET  /v2/provider-actions/:id/approval  — eligible workspace approver + MFA
 *   POST /v2/provider-actions/:id/approval  — approve/deny decision
 *   POST /v2/provider-actions/:id/execute   — request typed system resume
 *
 * Authority comes ONLY from persisted state + the service's current-authority
 * revalidation. The route never supplies actor/action/resource fields to the
 * service; the resume actor is always the in-process `steward-system` identity.
 *
 * These handlers are registered directly on the composed app (like
 * registerProviderActionRoutes) to avoid a second `/v2` sub-app mount colliding
 * with the provider-authority wildcard.
 */

import { decodeUtf8Strict, isApprovalReasonCode, strictParseJson } from "@stwd/shared";
import type { Context, Hono } from "hono";
import { type AppVariables, setNoStoreHeaders, tenantAuth } from "../services/context";
import { providerApprovalService } from "../services/provider-approval";

type RouteContext = Context<{ Variables: AppVariables }>;

const MAX_REQUEST_BYTES = 64 * 1024;
const ALLOWED_MEDIA = new Set(["application/json", "application/json; charset=utf-8"]);
const IDEM_KEY_RE = /^[\x21-\x7e]{8,255}$/;
const MAX_REASON_LEN = 1000;

const DECIDE_KEYS = new Set([
  "decision",
  "expectedVersion",
  "expectedRequestHash",
  "expectedActionDigest",
  "reasonCode",
  "reason",
  "idempotencyKey",
]);

function err(c: RouteContext, code: string, status: number) {
  // Spec §9 structured error body. `ApiResponse.error` is a string, so we return a
  // bespoke shape here (never echo dependency IDs on scope failures).
  return c.json(
    {
      ok: false as const,
      error: { code, message: safeMessage(code), requestId: c.get("requestId") ?? null },
    },
    status as never,
  );
}

function safeMessage(code: string): string {
  // Safe, non-enumerating messages. Never echo dependency IDs.
  switch (code) {
    case "SCOPE_RESOURCE_NOT_FOUND":
      return "resource not found";
    case "APPROVAL_HUMAN_SESSION_REQUIRED":
      return "a verified human session is required";
    default:
      return code.toLowerCase().replace(/_/g, " ");
  }
}

/** Human-session gate (spec §3.2 items 1-3). Agent tokens/API keys are rejected. */
function requireHumanSession(
  c: RouteContext,
): { ok: true; userId: string; tenantId: string } | { ok: false } {
  const authType = c.get("authType");
  const userId = c.get("userId");
  const tenantId = c.get("tenantId");
  if (
    (authType === "session-jwt" || authType === "dashboard-jwt") &&
    typeof userId === "string" &&
    userId.length > 0 &&
    typeof tenantId === "string" &&
    tenantId.length > 0
  ) {
    return { ok: true, userId, tenantId };
  }
  return { ok: false };
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async function handleGetApproval(c: RouteContext) {
  const human = requireHumanSession(c);
  if (!human.ok) return err(c, "APPROVAL_HUMAN_SESSION_REQUIRED", 403);
  const intentId = c.req.param("id");
  if (!intentId) return err(c, "SCOPE_RESOURCE_NOT_FOUND", 404);

  // MFA gate — even safe summaries are sensitive (spec §9.1).
  const mfa = c.get("sessionMfaVerifiedAt");
  if (typeof mfa !== "number" || !Number.isFinite(mfa)) {
    return err(c, "APPROVAL_MFA_REQUIRED", 403);
  }
  if (Date.now() - mfa > 300_000) return err(c, "APPROVAL_MFA_STALE", 403);

  // Eligibility (exact workspace approver) is enforced by the service via a
  // detail-load that first checks the caller is an eligible approver. For the
  // GET we require the same eligibility as a decision would, so reuse the
  // service's approver check by attempting a no-op eligibility probe.
  const eligible = await providerApprovalService.getApprovalDetailForApprover(
    human.tenantId,
    intentId,
    human.userId,
    mfa,
  );
  if (!eligible.ok) return err(c, eligible.code, eligible.httpStatus);
  return c.json({ ok: true, data: eligible.data }, 200);
}

async function handlePostApproval(c: RouteContext) {
  const human = requireHumanSession(c);
  if (!human.ok) return err(c, "APPROVAL_HUMAN_SESSION_REQUIRED", 403);
  const intentId = c.req.param("id");
  if (!intentId) return err(c, "SCOPE_RESOURCE_NOT_FOUND", 404);

  const contentType = (c.req.header("content-type") ?? "").trim().toLowerCase();
  if (!ALLOWED_MEDIA.has(contentType)) return err(c, "APPROVAL_FIELD_INVALID", 400);

  let bytes: Uint8Array;
  try {
    const buf = await c.req.raw.clone().arrayBuffer();
    if (buf.byteLength > MAX_REQUEST_BYTES) return err(c, "APPROVAL_FIELD_INVALID", 400);
    bytes = new Uint8Array(buf);
  } catch {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  let parsed: unknown;
  try {
    parsed = strictParseJson(decodeUtf8Strict(bytes));
  } catch {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  const body = parsed as Record<string, unknown>;
  for (const key of Object.keys(body)) {
    if (!DECIDE_KEYS.has(key)) return err(c, "APPROVAL_UNKNOWN_FIELD", 400);
  }

  const decision = body.decision;
  if (decision !== "approve" && decision !== "deny") return err(c, "APPROVAL_FIELD_INVALID", 400);
  const expectedVersion = body.expectedVersion;
  if (typeof expectedVersion !== "number" || !Number.isInteger(expectedVersion)) {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  const expectedRequestHash = body.expectedRequestHash;
  const expectedActionDigest = body.expectedActionDigest;
  if (
    typeof expectedRequestHash !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(expectedRequestHash) ||
    typeof expectedActionDigest !== "string" ||
    !/^sha256:[0-9a-f]{64}$/.test(expectedActionDigest)
  ) {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  const idempotencyKey = body.idempotencyKey;
  if (typeof idempotencyKey !== "string" || !IDEM_KEY_RE.test(idempotencyKey)) {
    return err(c, "APPROVAL_FIELD_INVALID", 400);
  }
  let reasonCode: string | null = null;
  if (body.reasonCode !== undefined) {
    if (!isApprovalReasonCode(body.reasonCode)) return err(c, "APPROVAL_FIELD_INVALID", 400);
    reasonCode = body.reasonCode;
  }
  let reason: string | null = null;
  if (body.reason !== undefined) {
    if (typeof body.reason !== "string" || [...body.reason].length > MAX_REASON_LEN) {
      return err(c, "APPROVAL_FIELD_INVALID", 400);
    }
    reason = body.reason;
  }

  const result = await providerApprovalService.decide({
    intentId,
    tenantId: human.tenantId,
    authenticatedUserId: human.userId,
    sessionMfaVerifiedAt: c.get("sessionMfaVerifiedAt"),
    decision,
    expectedVersion,
    expectedRequestHash,
    expectedActionDigest,
    reasonCode,
    reason,
    idempotencyKey,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  if (!result.ok) return err(c, result.code, result.httpStatus);
  return c.json(
    {
      id: result.id,
      status: result.status,
      version: result.version,
      requestHash: result.requestHash,
      actionDigest: result.actionDigest,
      ...(result.replayed ? { replayed: true } : {}),
    },
    result.httpStatus,
  );
}

async function handlePostExecute(c: RouteContext) {
  const tenantId = c.get("tenantId");
  if (typeof tenantId !== "string" || tenantId.length === 0) {
    return err(c, "APPROVAL_HUMAN_SESSION_REQUIRED", 403);
  }
  const intentId = c.req.param("id");
  if (!intentId) return err(c, "SCOPE_RESOURCE_NOT_FOUND", 404);

  const authType = c.get("authType");
  const executeCaller =
    authType === "agent-token"
      ? { agentId: c.get("agentScope") }
      : authType === "session-jwt"
        ? { userId: c.get("userId") }
        : {};
  const callerAuthorization = await providerApprovalService.authorizeExecuteCaller(
    tenantId,
    intentId,
    executeCaller,
  );
  if (!callerAuthorization.ok) {
    return err(c, callerAuthorization.code, callerAuthorization.httpStatus);
  }

  // Reject any body that supplies actor/action fields (I4 / RESUME_ACTOR_SUBSTITUTION).
  const contentType = (c.req.header("content-type") ?? "").trim().toLowerCase();
  if (contentType && ALLOWED_MEDIA.has(contentType)) {
    try {
      const buf = await c.req.raw.clone().arrayBuffer();
      if (buf.byteLength > 0) {
        const parsed = strictParseJson(decodeUtf8Strict(new Uint8Array(buf)));
        if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) {
          for (const key of Object.keys(parsed as Record<string, unknown>)) {
            if (key !== "idempotencyKey") {
              return err(c, "RESUME_ACTOR_SUBSTITUTION_FORBIDDEN", 400);
            }
          }
        }
      }
    } catch {
      return err(c, "RESUME_ACTOR_SUBSTITUTION_FORBIDDEN", 400);
    }
  }

  const result = await providerApprovalService.resume({
    intentId,
    tenantId,
    caller: executeCaller,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  if (!result.ok) return err(c, result.code, result.httpStatus);
  return c.json(
    {
      id: result.id,
      status: result.status,
      version: result.version,
      requestHash: result.requestHash,
      actionDigest: result.actionDigest,
      ...(result.resumeAttemptId ? { resumeAttemptId: result.resumeAttemptId } : {}),
    },
    result.httpStatus,
  );
}

/**
 * Register the PR3 approval + execute routes directly on the composed app.
 * `tenantAuth` populates authType/userId/tenantId/sessionMfaVerifiedAt for both
 * human sessions and agent tokens; the handlers enforce the human-session
 * requirement where the spec demands it.
 */
export function registerProviderApprovalRoutes(app: Hono<{ Variables: AppVariables }>): void {
  const paths = ["/v2/provider-actions/:id/approval", "/v2/provider-actions/:id/execute"];
  for (const p of paths) {
    app.use(p, async (c, next) => {
      setNoStoreHeaders(c);
      await next();
    });
    app.use(p, (c, next) => tenantAuth(c, next));
  }
  app.get("/v2/provider-actions/:id/approval", handleGetApproval);
  app.post("/v2/provider-actions/:id/approval", handlePostApproval);
  app.post("/v2/provider-actions/:id/execute", handlePostExecute);
}

// Test/mount surface: a standalone sub-app for isolated unit tests.
export const providerApprovalRoutes = { registerProviderApprovalRoutes };

/**
 * provider-actions.ts — POST /v2/provider-actions (PR2 spec §2).
 *
 * The public provider-action ingress. It:
 *   1. Reads BOUNDED raw UTF-8 bytes (never `request.json()` first — JSON.parse
 *      silently overwrites duplicate keys). Uses the shared strict parser which
 *      rejects duplicate members at every depth.
 *   2. Validates the exact public request shape (§2.1); unknown top-level fields,
 *      caller-supplied identity/decision fields, and wrong media type deny.
 *   3. Derives tenant + actor ONLY from the verified provider principal, resolves
 *      the operation via the adapter, generates requestedAt/expiresAt/nonce and
 *      the idempotency-key hash, and hands off to the provider-action service.
 *
 * The route never dispatches a real request, decrypts a credential, or mints an
 * authorization. Allow calls the in-process stub after the decision commits.
 */

import { createHash, randomBytes } from "node:crypto";
import { getDb, intents, providerActionBindings } from "@stwd/db";
import { buildGithubAction, isGithubOperationKey } from "@stwd/provider-github";
import { buildXAction, isXOperationKey } from "@stwd/provider-x";
import { CanonError, decodeUtf8Strict, isCanonError, strictParseJson } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import type { Context } from "hono";
import { Hono } from "hono";
import { requireProviderAgentJwt } from "../middleware/agent-jwt";
import { resolveProviderPrincipal } from "../middleware/provider-principal";
import { type ApiResponse, type AppVariables, setNoStoreHeaders } from "../services/context";
import { toProviderActionStatusResponse } from "../services/intent-response";
import {
  type ProviderActionOutcome,
  providerActionService,
} from "../services/provider-action-service";

export const providerActionRoutes = new Hono<{ Variables: AppVariables }>();

providerActionRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

providerActionRoutes.use("*", requireProviderAgentJwt);

type RouteContext = Context<{ Variables: AppVariables }>;

/**
 * Register the provider-action route DIRECTLY on the composed app.
 *
 * Why not `app.route("/v2", providerActionRoutes)`: co-mounting a second sub-app
 * at the `/v2` prefix (already owned by providerAuthorityRoutes' wildcard
 * middleware) does not reliably resolve the concrete `/v2/provider-actions`
 * handler under the composed router. Registering the middleware chain + handler
 * directly on the app is unambiguous and keeps the exact same behavior.
 */
export function registerProviderActionRoutes(app: Hono<{ Variables: AppVariables }>): void {
  app.use("/v2/provider-actions", async (c, next) => {
    setNoStoreHeaders(c);
    await next();
  });
  app.use("/v2/provider-actions", requireProviderAgentJwt);
  app.post("/v2/provider-actions", handleCreateProviderAction);

  // #233: a read-only status view for the authenticated agent's own actions.
  // Keep this path exact (no wildcard suffix) so the sibling approval, execute,
  // case, and evidence routes retain their distinct human/MFA gates.
  app.use("/v2/provider-actions/:id", async (c, next) => {
    setNoStoreHeaders(c);
    await next();
  });
  app.use("/v2/provider-actions/:id", requireProviderAgentJwt);
  app.get("/v2/provider-actions/:id", handleGetProviderActionStatus);
}

const MAX_REQUEST_BYTES = 256 * 1024; // 256 KiB bound
const ALLOWED_MEDIA = new Set(["application/json", "application/json; charset=utf-8"]);
const IDEM_KEY_RE = /^[\x21-\x7e]{8,255}$/; // 8..255 visible ASCII
const NONCE_BYTES = 24; // 192 bits

const TOP_LEVEL_KEYS = new Set([
  "workspaceId",
  "providerAccountId",
  "operationKey",
  "arguments",
  "idempotencyKey",
]);

function deny(c: RouteContext, code: string, status: number) {
  return c.json<ApiResponse>({ ok: false, error: code }, status as never);
}

function providerActionNotFound(c: RouteContext) {
  return c.json<ApiResponse>({ ok: false, error: "PROVIDER_ACTION_NOT_FOUND" }, 404);
}

async function handleGetProviderActionStatus(c: RouteContext) {
  const principal = resolveProviderPrincipal(c);
  const intentId = c.req.param("id") ?? "";

  // Provider action ids are currently `pa_` + UUID. Treat malformed ids exactly
  // like absent/foreign ids so this read surface is non-enumerating.
  if (!/^pa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(intentId)) {
    return providerActionNotFound(c);
  }

  const [owned] = await getDb()
    .select({ binding: providerActionBindings, intent: intents })
    .from(providerActionBindings)
    .innerJoin(
      intents,
      and(
        eq(intents.id, providerActionBindings.intentId),
        eq(intents.tenantId, providerActionBindings.tenantId),
      ),
    )
    .where(
      and(
        eq(providerActionBindings.intentId, intentId),
        eq(providerActionBindings.tenantId, principal.tenantId),
        eq(providerActionBindings.actorAgentId, principal.agentId),
        eq(intents.intentType, "provider-action"),
      ),
    )
    .limit(1);

  if (!owned) return providerActionNotFound(c);
  return c.json<ApiResponse>({
    ok: true,
    data: toProviderActionStatusResponse({
      id: owned.binding.intentId,
      status: owned.binding.status,
      version: owned.binding.bindingRevision,
      workspaceId: owned.binding.workspaceId,
      providerAccountId: owned.binding.providerAccountId,
      operationId: owned.binding.operationId,
      operationRevision: owned.binding.operationRevision,
      actionDigest: owned.binding.actionDigest,
      requestHash: owned.binding.requestHash,
      expiresAt: owned.intent.expiresAt,
      createdAt: owned.binding.createdAt,
      updatedAt: owned.binding.updatedAt,
    }),
  });
}

function outcomeToResponse(c: RouteContext, outcome: ProviderActionOutcome) {
  switch (outcome.kind) {
    case "scope_not_found":
      return c.json<ApiResponse>({ ok: false, error: outcome.code }, 404);
    case "access_denied":
    case "policy_denied":
      return c.json<ApiResponse>(
        {
          ok: false,
          error: outcome.code,
          data: {
            id: outcome.intentId,
            status: outcome.kind === "access_denied" ? "denied_access" : "denied_policy",
            requestHash: outcome.requestHash,
            actionDigest: outcome.actionDigest,
          },
        },
        outcome.httpStatus as never,
      );
    case "approval_required":
      return c.json(
        {
          id: outcome.intentId,
          status: "pending_approval",
          requestHash: outcome.requestHash,
          actionDigest: outcome.actionDigest,
        },
        202,
      );
    case "allowed":
      return c.json(
        {
          id: outcome.intentId,
          status: outcome.stub.status,
          requestHash: outcome.requestHash,
          actionDigest: outcome.actionDigest,
          result: outcome.stub,
        },
        200,
      );
    case "replay_conflict":
      return c.json<ApiResponse>({ ok: false, error: outcome.code }, 409);
    case "evidence_failure":
      return c.json<ApiResponse>({ ok: false, error: outcome.code }, 503);
    case "backend_unavailable":
      return c.json<ApiResponse>({ ok: false, error: outcome.code }, 503);
  }
}

async function handleCreateProviderAction(c: RouteContext) {
  // Principal is guaranteed present by requireProviderAgentJwt; resolve fail-closed.
  const principal = resolveProviderPrincipal(c);

  // ── Media type (§2.1). ──
  const contentType = (c.req.header("content-type") ?? "").trim().toLowerCase();
  if (!ALLOWED_MEDIA.has(contentType)) {
    return deny(c, "CANON_REQUEST_CONTENT_TYPE_UNSUPPORTED", 415);
  }

  // ── Bounded raw bytes. ──
  let bytes: Uint8Array;
  try {
    const buf = await c.req.raw.clone().arrayBuffer();
    if (buf.byteLength > MAX_REQUEST_BYTES) return deny(c, "CANON_REQUEST_TOO_LARGE", 413);
    bytes = new Uint8Array(buf);
  } catch {
    return deny(c, "CANON_INVALID_UTF8", 400);
  }

  // ── Strict UTF-8 + strict JSON (duplicate keys rejected at every depth). ──
  let parsed: unknown;
  try {
    const text = decodeUtf8Strict(bytes);
    parsed = strictParseJson(text);
  } catch (e) {
    if (isCanonError(e)) return deny(c, e.code, e.httpStatus);
    return deny(c, "CANON_JSON_SYNTAX_INVALID", 400);
  }

  // ── Public request shape (§2.1). ──
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return deny(c, "CANON_JSON_SHAPE_INVALID", 400);
  }
  const body = parsed as Record<string, unknown>;
  for (const key of Object.keys(body)) {
    // Caller-supplied identity/decision fields (actor/agentId/tenantId/...) are
    // unknown top-level fields and rejected here (§1.2).
    if (!TOP_LEVEL_KEYS.has(key)) return deny(c, "CANON_UNKNOWN_FIELD", 400);
  }

  const workspaceId = body.workspaceId;
  const providerAccountId = body.providerAccountId;
  const operationKey = body.operationKey;
  const idempotencyKey = body.idempotencyKey;
  const args = body.arguments;

  if (
    workspaceId === undefined ||
    providerAccountId === undefined ||
    operationKey === undefined ||
    idempotencyKey === undefined ||
    args === undefined
  ) {
    return deny(c, "CANON_REQUIRED_FIELD_MISSING", 400);
  }
  if (
    typeof workspaceId !== "string" ||
    typeof providerAccountId !== "string" ||
    typeof operationKey !== "string" ||
    typeof idempotencyKey !== "string"
  ) {
    return deny(c, "CANON_FIELD_TYPE_INVALID", 400);
  }
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    return deny(c, "CANON_FIELD_TYPE_INVALID", 400);
  }
  if (!IDEM_KEY_RE.test(idempotencyKey)) {
    return deny(c, "CANON_FIELD_TYPE_INVALID", 400);
  }
  // ── Adapter dispatch: resolve the operation to its owning provider adapter
  // and validate + canonicalize the arguments. Both adapters emit a
  // structurally-compatible build the pipeline accepts uniformly. An operation
  // key belonging to no registered adapter is an unsupported profile. ──
  let build: import("../services/provider-action-service").ProviderActionBuild;
  try {
    if (isGithubOperationKey(operationKey)) {
      build = buildGithubAction(operationKey, args);
    } else if (isXOperationKey(operationKey)) {
      build = buildXAction(operationKey, args);
    } else {
      return deny(c, "CANON_PROFILE_UNSUPPORTED", 400);
    }
  } catch (e) {
    if (isCanonError(e)) return deny(c, e.code, e.httpStatus);
    // Never surface an arbitrary thrown value as a 500.
    return deny(c, "CANON_JCS_FAILED", 400);
  }

  // ── Server-derived envelope fields (never caller-supplied). ──
  const requestedAt = new Date();
  const expiresAt = new Date(requestedAt.getTime() + 5 * 60_000);
  const nonce = toBase64Url(randomBytes(NONCE_BYTES));
  const idempotencyKeyHash = `sha256:${createHash("sha256")
    .update(Buffer.from(idempotencyKey, "utf8"))
    .digest("hex")}`;

  let outcome: ProviderActionOutcome;
  try {
    outcome = await providerActionService.createProviderAction({
      principal,
      workspaceId,
      providerAccountId,
      operationKey,
      build,
      idempotencyKeyHash,
      requestedAt: toRfc3339Millis(requestedAt),
      expiresAt: toRfc3339Millis(expiresAt),
      nonce,
      requestId: c.get("requestId") ?? null,
    });
  } catch (e) {
    if (isCanonError(e)) return deny(c, e.code, e.httpStatus);
    // Unknown exception before/within persistence -> evaluator error class, only
    // a correlation id public (never an arbitrary 500 body).
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "POLICY_EVALUATOR_ERROR",
        data: { requestId: c.get("requestId") ?? null },
      },
      503,
    );
  }

  return outcomeToResponse(c, outcome);
}

// Also register on the standalone sub-app so it can be unit-tested in isolation
// (and remains a valid mount target if the router behavior changes).
providerActionRoutes.post("/provider-actions", handleCreateProviderAction);
providerActionRoutes.get("/provider-actions/:id", handleGetProviderActionStatus);

/** RFC 3339 UTC with exactly three fractional digits and trailing Z. */
function toRfc3339Millis(d: Date): string {
  return d.toISOString().replace(/\.(\d{3})\d*Z$/, ".$1Z");
}

/**
 * base64url-encode raw bytes without padding. Implemented over the hex string
 * (the only Buffer encoding the local api tsconfig types accept) so it needs no
 * base64/base64url Buffer support.
 */
const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function toBase64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += B64URL_ALPHABET[(triple >> 18) & 0x3f];
    out += B64URL_ALPHABET[(triple >> 12) & 0x3f];
    if (i + 1 < bytes.length) out += B64URL_ALPHABET[(triple >> 6) & 0x3f];
    if (i + 2 < bytes.length) out += B64URL_ALPHABET[triple & 0x3f];
  }
  return out;
}

// Re-export for tests that assert the CanonError contract stays wired.
export { CanonError };

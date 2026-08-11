/**
 * manifest-routes.ts — agent-facing manifest + issuance/renewal surface (A1).
 *
 * These routes are AGENT-token authed (the same requireAgentJwt gate the invoke
 * path uses); agent identity comes from the token (c.get("agentScope")), never
 * the body. They layer on the existing capability store + the issuance core:
 *
 *   GET  /capabilities/manifest
 *        → list THIS agent's manifest (provider:kind entries it may request).
 *
 *   POST /capabilities/manifest/:id/issue   { ttlSeconds? }
 *   POST /capabilities/manifest/:id/renew   { ttlSeconds? }
 *        → issue (or renew) the capability. token mode returns a short-lived
 *          scoped token; broker mode returns a delegation descriptor. Renewal is
 *          the same fully-checked path (revocation lands at the next renewal).
 *
 * There is deliberately NO agent-facing revoke route: revocation is an OPERATOR
 * act (disable capability / revoke grant via the existing CRUD), effective at the
 * agent's next renewal. The short TTL bounds the window (<5min, Pillar-A green).
 */

import { randomUUID } from "node:crypto";
import { signAgentToken } from "@stwd/auth";
import type { ApiResponse, AppVariables } from "@stwd/shared";
import type { Context } from "hono";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { StewardAppContext } from "./context";
import {
  type CapabilityAuditEvent,
  type CapabilityAuditSink,
  issueCapability,
  type ShortLivedTokenMinter,
} from "./issuance";
import { listAgentManifest, resolveManifestEntry } from "./manifest";
import { CapabilityStore } from "./store";

/** Mint a short-lived agent token carrying the given scopes; pre-generate the jti
 * so we can return it (for out-of-band revocation) and audit it. */
const mintShortLivedToken: ShortLivedTokenMinter = async ({
  agentId,
  tenantId,
  scopes,
  ttlSeconds,
}) => {
  const jti = randomUUID();
  const token = await signAgentToken({ agentId, tenantId, scopes, jti }, `${ttlSeconds}s`);
  return { token, jti };
};

/** Build the audit sink from the injected core audit writer. Maps the structured
 * capability event onto the core writeAuditEvent shape (interface only for E1). */
function buildAuditSink(ctx: StewardAppContext): CapabilityAuditSink {
  return async (ev: CapabilityAuditEvent) => {
    await ctx.writeAuditEvent({
      tenantId: ev.tenantId,
      actorType: "agent",
      actorId: ev.agentId,
      action: ev.action,
      resourceType: "capability",
      resourceId: ev.capabilityId ?? ev.manifest,
      metadata: {
        manifest: ev.manifest,
        mode: ev.mode,
        decision: ev.decision,
        reason: ev.reason,
        jti: ev.jti,
        ttlSeconds: ev.ttlSeconds,
      },
    });
  };
}

/** HTTP status for an issuance deny code. */
function issuanceDenyStatus(code: string): ContentfulStatusCode {
  switch (code) {
    case "not_granted":
      return 403;
    case "invalid_manifest":
    case "ttl_out_of_range":
      return 400;
    default:
      return 500;
  }
}

function parseTtl(body: unknown): number | undefined {
  if (body && typeof body === "object" && !Array.isArray(body)) {
    const v = (body as { ttlSeconds?: unknown }).ttlSeconds;
    if (typeof v === "number") return v;
  }
  return undefined;
}

export function createManifestRoutes(ctx: StewardAppContext): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const store = new CapabilityStore(ctx.db);
  const emitAudit = buildAuditSink(ctx);

  // ── GET /manifest — list the agent's manifest ───────────────────────────────
  routes.get("/manifest", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return c.json<ApiResponse>({ ok: false, error: "agent authentication required" }, 401);
    }
    const listing = await listAgentManifest(store, tenantId, agentId);
    return c.json<ApiResponse>({ ok: true, data: { manifest: listing } });
  });

  // ── POST /manifest/:id/issue and /manifest/:id/renew ────────────────────────
  const issueHandler =
    (isRenewal: boolean) =>
    async (c: Context<{ Variables: AppVariables }>): Promise<Response> => {
      const tenantId = c.get("tenantId");
      const agentId = c.get("agentScope");
      if (!tenantId || !agentId) {
        return c.json<ApiResponse>({ ok: false, error: "agent authentication required" }, 401);
      }
      const manifestId = c.req.param("id") ?? "";

      let body: unknown = {};
      const raw = await c.req.text().catch(() => "");
      if (raw.trim() !== "") {
        try {
          body = JSON.parse(raw);
        } catch {
          return c.json<ApiResponse>({ ok: false, error: "invalid JSON in request body" }, 400);
        }
      }

      const resolved = await resolveManifestEntry(store, tenantId, agentId, manifestId).catch(
        () => null,
      );

      const result = await issueCapability({
        tenantId,
        agentId,
        manifest: manifestId,
        resolved,
        ttlSeconds: parseTtl(body),
        isRenewal,
        mintToken: mintShortLivedToken,
        emitAudit,
      });

      if (!result.ok) {
        return c.json<ApiResponse>(
          { ok: false, error: result.error },
          issuanceDenyStatus(result.code),
        );
      }
      c.header("Cache-Control", "no-store, max-age=0");
      return c.json<ApiResponse>({ ok: true, data: result });
    };

  routes.post("/manifest/:id/issue", issueHandler(false));
  routes.post("/manifest/:id/renew", issueHandler(true));

  return routes;
}

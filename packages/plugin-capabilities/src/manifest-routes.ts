/**
 * manifest-routes.ts — agent-facing manifest + issuance/renewal surface (A1).
 *
 * These routes are AGENT-token authed (the same capability agent-jwt gate the
 * invoke path uses — no `trade:order` scope requirement); agent identity comes
 * from the token (c.get("agentScope")), never the body. They layer on the
 * existing capability store + the issuance core:
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
 * GitHub token delivery is one-shot and must be acknowledged with token proof;
 * unacknowledged deliveries are revoked by the bounded recovery sweep. Both the
 * holder and an operator authority mutation can revoke the provider token.
 */

import type { ApiResponse, AppVariables } from "@stwd/shared";
import type { Context } from "hono";
import { Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { StewardAppContext } from "./context";
import { GitHubAppInstallationTokenIssuer } from "./github-app-issuer";
import {
  type CapabilityAuditEvent,
  type CapabilityAuditSink,
  issueCapability,
  type ShortLivedTokenMinter,
} from "./issuance";
import { listAgentManifest, resolveManifestEntry } from "./manifest";
import { enforceCapabilityRateLimit } from "./rate-limit";
import { CapabilityStore } from "./store";
import {
  acknowledgeUpstreamCredentialLease,
  DELIVERY_ACK_TIMEOUT_MS,
  GITHUB_APP_LEASE_ISSUER,
  type GitHubLeaseResource,
  issueUpstreamCredentialLease,
  MAX_UPSTREAM_LEASE_SWEEP_INTERVAL_MS,
  recoverInterruptedUpstreamCredentialLeases,
  revokeUpstreamCredentialLease,
  UPSTREAM_LEASE_LIFECYCLE_DEADLINE_MS,
} from "./upstream-leases";

export function upstreamLeaseIssuanceAvailableInRuntime(): boolean {
  // The Workers entry has no timer/queue/scheduled handler that can honor the
  // 30-second delivery recovery contract. Do not expose live provider tokens
  // from a runtime that cannot autonomously revoke abandoned delivery.
  if (
    process.env.STEWARD_RUNTIME === "workers" ||
    process.env.STEWARD_UPSTREAM_LEASE_SWEEPER === "false"
  ) {
    return false;
  }
  const configured = process.env.STEWARD_UPSTREAM_LEASE_SWEEP_INTERVAL_MS;
  if (configured === undefined) return true;
  const intervalMs = Number(configured);
  return (
    Number.isSafeInteger(intervalMs) &&
    intervalMs >= 1_000 &&
    intervalMs <= MAX_UPSTREAM_LEASE_SWEEP_INTERVAL_MS
  );
}

const denyInternalTokenMint: ShortLivedTokenMinter = async () => {
  throw new Error("provider token mode requires an upstream issuer");
};
const githubIssuer = new GitHubAppInstallationTokenIssuer();

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

function parseLeaseBody(
  body: unknown,
): { workspaceId: string; ttlSeconds: number; resource: GitHubLeaseResource } | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const value = body as Record<string, unknown>;
  const resource = value.resource;
  if (
    typeof value.workspaceId !== "string" ||
    typeof value.ttlSeconds !== "number" ||
    !resource ||
    typeof resource !== "object" ||
    Array.isArray(resource)
  )
    return null;
  const scope = resource as Record<string, unknown>;
  if (
    !Array.isArray(scope.repositories) ||
    !scope.repositories.every((entry) => typeof entry === "string") ||
    !scope.permissions ||
    typeof scope.permissions !== "object" ||
    Array.isArray(scope.permissions)
  )
    return null;
  const permissions = scope.permissions as Record<string, unknown>;
  if (
    !Object.values(permissions).every(
      (entry) => entry === "read" || entry === "write" || entry === "admin",
    )
  )
    return null;
  return {
    workspaceId: value.workspaceId,
    ttlSeconds: value.ttlSeconds,
    resource: {
      repositories: scope.repositories as string[],
      permissions: permissions as GitHubLeaseResource["permissions"],
    },
  };
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

      // Per-agent throttle on issuance/renewal (SEC-094): each attempt mints a
      // token and writes an audit row, so it must be bounded like invoke.
      const rate = await enforceCapabilityRateLimit(ctx, "issue", agentId);
      if (!rate.allowed) {
        c.header("Retry-After", String(Math.ceil(rate.resetMs / 1000)));
        return c.json<ApiResponse>(
          { ok: false, error: "capability issuance rate limit exceeded" },
          429,
        );
      }

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

      if (resolved?.provider === "github") {
        if (!upstreamLeaseIssuanceAvailableInRuntime()) {
          return c.json<ApiResponse>(
            { ok: false, error: "upstream credential leases require autonomous recovery" },
            503,
          );
        }
        const leaseBody = parseLeaseBody(body);
        const idempotencyKey = c.req.header("Idempotency-Key") ?? "";
        if (!leaseBody) {
          return c.json<ApiResponse>(
            {
              ok: false,
              error: "workspaceId, ttlSeconds, and an explicit resource scope are required",
            },
            400,
          );
        }
        if (!ctx.exerciseCredentialSecret) {
          return c.json<ApiResponse>(
            { ok: false, error: "upstream credential issuer is not configured" },
            503,
          );
        }
        if (!ctx.sealCredentialLeaseToken) {
          return c.json<ApiResponse>(
            { ok: false, error: "credential lease escrow is not configured" },
            503,
          );
        }
        if (!ctx.exerciseCredentialLeaseToken) {
          return c.json<ApiResponse>(
            { ok: false, error: "credential lease recovery is not configured" },
            503,
          );
        }
        const leaseDeadlineAt = Date.now() + UPSTREAM_LEASE_LIFECYCLE_DEADLINE_MS;
        try {
          await recoverInterruptedUpstreamCredentialLeases({
            db: ctx.db,
            tenantId,
            issuer: githubIssuer,
            exerciseToken: ctx.exerciseCredentialLeaseToken,
            auditedTransaction: ctx.withTenantAuditedTransaction,
            deadlineAt: leaseDeadlineAt,
            withDatabaseDeadline: ctx.withCredentialLeaseDatabaseDeadline,
          });
        } catch {
          return c.json<ApiResponse>({ ok: false, error: "credential lease recovery failed" }, 503);
        }
        const leased = await issueUpstreamCredentialLease({
          db: ctx.db,
          tenantId,
          agentId,
          workspaceId: leaseBody.workspaceId,
          idempotencyKey,
          ttlSeconds: leaseBody.ttlSeconds,
          resource: leaseBody.resource,
          resolved,
          exerciseSecret: ctx.exerciseCredentialSecret,
          sealToken: ctx.sealCredentialLeaseToken,
          auditedTransaction: ctx.withTenantAuditedTransaction,
          issuer: githubIssuer,
          deadlineAt: leaseDeadlineAt,
          withDatabaseDeadline: ctx.withCredentialLeaseDatabaseDeadline,
        });
        if (!leased.ok) {
          return c.json<ApiResponse>({ ok: false, error: leased.error }, leased.status);
        }
        c.header("Cache-Control", "no-store, max-age=0");
        c.header("Pragma", "no-cache");
        return c.json<ApiResponse>({
          ok: true,
          data: {
            mode: "token",
            issuer: GITHUB_APP_LEASE_ISSUER,
            leaseId: leased.leaseId,
            token: leased.token,
            acknowledgementRequired: true,
            acknowledgementDeadlineSeconds: DELIVERY_ACK_TIMEOUT_MS / 1000,
            expiresAt: leased.expiresAt,
            resource: leased.resource,
            manifest: manifestId,
            capabilityId: resolved.capability.id,
          },
        });
      }

      const result = await issueCapability({
        tenantId,
        agentId,
        manifest: manifestId,
        resolved,
        ttlSeconds: parseTtl(body),
        isRenewal,
        mintToken: denyInternalTokenMint,
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

  routes.post("/manifest/leases/:leaseId/revoke", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return c.json<ApiResponse>({ ok: false, error: "agent authentication required" }, 401);
    }
    const body = (await c.req.json().catch(() => null)) as { token?: unknown } | null;
    if (!body || typeof body.token !== "string" || body.token.length === 0) {
      return c.json<ApiResponse>({ ok: false, error: "token proof is required" }, 400);
    }
    const result = await revokeUpstreamCredentialLease({
      db: ctx.db,
      tenantId,
      agentId,
      leaseId: c.req.param("leaseId"),
      token: body.token,
      issuer: githubIssuer,
      auditedTransaction: ctx.withTenantAuditedTransaction,
      withDatabaseDeadline: ctx.withCredentialLeaseDatabaseDeadline,
    });
    if (!result.ok) return c.json<ApiResponse>({ ok: false, error: result.error }, result.status);
    c.header("Cache-Control", "no-store, max-age=0");
    return c.json<ApiResponse>({ ok: true, data: { revoked: true } });
  });

  routes.post("/manifest/leases/:leaseId/ack", async (c) => {
    const tenantId = c.get("tenantId");
    const agentId = c.get("agentScope");
    if (!tenantId || !agentId) {
      return c.json<ApiResponse>({ ok: false, error: "agent authentication required" }, 401);
    }
    const body = (await c.req.json().catch(() => null)) as { token?: unknown } | null;
    if (!body || typeof body.token !== "string" || body.token.length === 0) {
      return c.json<ApiResponse>({ ok: false, error: "token proof is required" }, 400);
    }
    const result = await acknowledgeUpstreamCredentialLease({
      db: ctx.db,
      tenantId,
      agentId,
      leaseId: c.req.param("leaseId"),
      token: body.token,
      auditedTransaction: ctx.withTenantAuditedTransaction,
      withDatabaseDeadline: ctx.withCredentialLeaseDatabaseDeadline,
    });
    if (!result.ok) return c.json<ApiResponse>({ ok: false, error: result.error }, result.status);
    c.header("Cache-Control", "no-store, max-age=0");
    return c.json<ApiResponse>({ ok: true, data: { active: true } });
  });

  return routes;
}

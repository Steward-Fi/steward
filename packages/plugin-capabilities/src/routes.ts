/**
 * routes.ts — operator/tenant-auth CRUD for capabilities + grants.
 *
 * these are the OPERATOR-facing management routes (create/list/read/update/delete
 * a capability, grant/revoke, and "what may an agent use"). the agent-facing
 * invoke route is W-1c and is NOT here. mounted by the plugin's `register` behind
 * the tenant gate (see index.ts), and each mutation additionally requires a
 * recent tenant-admin MFA verification — the SAME bar the core /secrets + route
 * CRUD requires, because capabilities drive live credential injection.
 *
 * the routes NEVER return a secret value (they only ever touch secret IDs +
 * routing metadata). validation goes through the shared secret-route validator
 * (validate.ts), so a capability can never be broader than a legal route.
 */

import type { ApiResponse, AppVariables } from "@stwd/shared";
import type { Context } from "hono";
import { Hono } from "hono";
import type { StewardAppContext } from "./context";
import type { Capability, CapabilityGrant } from "./schema";
import { AgentNotFoundError, CapabilityStore } from "./store";
import {
  createCapabilitySchema,
  createGrantSchema,
  updateCapabilitySchema,
  validateCapabilitySpec,
} from "./validate";

/** the public (never-secret) view of a capability returned by the API. */
function toCapabilityView(cap: Capability) {
  return {
    id: cap.id,
    name: cap.name,
    secretId: cap.secretId,
    host: cap.host,
    pathPattern: cap.pathPattern,
    method: cap.method,
    injectAs: cap.injectAs,
    injectKey: cap.injectKey,
    injectFormat: cap.injectFormat,
    constraints: cap.constraints,
    enabled: cap.enabled,
    createdAt: cap.createdAt,
    updatedAt: cap.updatedAt,
  };
}

/** the public view of a grant (route id included so an operator can trace it). */
function toGrantView(grant: CapabilityGrant) {
  return {
    id: grant.id,
    capabilityId: grant.capabilityId,
    agentId: grant.agentId,
    secretRouteId: grant.secretRouteId,
    expiresAt: grant.expiresAt,
    status: grant.status,
    createdAt: grant.createdAt,
  };
}

/** tenant-admin session predicate — mirrors the core /secrets route gate. */
function isTenantAdminSession(c: Context<{ Variables: AppVariables }>): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

/** recent-MFA check — mirrors the core /secrets route gate (5 min default). */
function hasRecentSessionMfa(
  c: Context<{ Variables: AppVariables }>,
  maxAgeMs = 5 * 60_000,
): boolean {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

/**
 * Gate a mutating capability route: require a tenant-admin session with recent
 * MFA (the same bar the core /secrets + secret-route CRUD enforce). Returns a
 * 403 Response to short-circuit, or null when authorized. Fail-closed.
 */
function requireCapabilityAdmin(
  c: Context<{ Variables: AppVariables }>,
  reason: string,
): Response | null {
  if (!isTenantAdminSession(c)) {
    return c.json<ApiResponse>({ ok: false, error: `${reason} requires owner or admin session` }, 403);
  }
  if (!hasRecentSessionMfa(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: `${reason} requires recent MFA verification` },
      403,
    );
  }
  return null;
}

/**
 * Build the capability CRUD + grants router. `ctx` is the injected core context
 * (db + audit + json parse). The router is mounted behind the tenant gate by the
 * plugin's `register`.
 */
export function createCapabilityRoutes(
  ctx: StewardAppContext,
): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const store = new CapabilityStore(ctx.db);

  async function audit(
    c: Context<{ Variables: AppVariables }>,
    event: {
      tenantId: string;
      action: string;
      resourceType: string;
      resourceId: string;
      metadata?: Record<string, unknown>;
    },
  ): Promise<void> {
    await ctx.writeAuditEvent({
      tenantId: event.tenantId,
      actorType: c.get("authType") === "api-key" ? "api-key" : "user",
      actorId: c.get("userId") ?? c.get("authType") ?? event.tenantId,
      action: event.action,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      metadata: event.metadata,
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  }

  // ── POST /capabilities — create (validates, no grants -> no routes yet) ─────
  routes.post("/", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");

    const body = await ctx.safeJsonParse<Record<string, unknown>>(c);
    if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

    const parsed = createCapabilitySchema.safeParse(body);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.issues[0]?.message ?? "invalid body" }, 400);
    }
    const input = parsed.data;

    const validated = validateCapabilitySpec({
      secretId: input.secretId,
      host: input.host,
      pathPattern: input.pathPattern,
      method: input.method,
      injectAs: input.injectAs,
      injectKey: input.injectKey,
      injectFormat: input.injectFormat,
    });
    if (!validated.ok) return c.json<ApiResponse>({ ok: false, error: validated.error }, 400);

    try {
      const existing = await store.getCapabilityByName(tenantId, input.name);
      if (existing) {
        return c.json<ApiResponse>({ ok: false, error: `capability '${input.name}' already exists` }, 409);
      }
      const cap = await store.createCapability({
        tenantId,
        name: input.name,
        spec: validated.spec,
        constraints: input.constraints ?? {},
        enabled: input.enabled ?? true,
      });
      await audit(c, {
        tenantId,
        action: "capability.create",
        resourceType: "capability",
        resourceId: cap.id,
        metadata: {
          name: cap.name,
          secretId: cap.secretId,
          host: cap.host,
          pathPattern: cap.pathPattern,
          method: cap.method,
          enabled: cap.enabled,
        },
      });
      return c.json<ApiResponse>({ ok: true, data: toCapabilityView(cap) }, 201);
    } catch (e) {
      return errorResponse(c, e);
    }
  });

  // ── GET /capabilities — list ────────────────────────────────────────────────
  routes.get("/", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const caps = await store.listCapabilities(tenantId);
    return c.json<ApiResponse>({ ok: true, data: caps.map(toCapabilityView) });
  });

  // ── GET /capabilities/:id — read ─────────────────────────────────────────────
  routes.get("/:id", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const cap = await store.getCapabilityById(tenantId, c.req.param("id"));
    if (!cap) return c.json<ApiResponse>({ ok: false, error: "capability not found" }, 404);
    return c.json<ApiResponse>({ ok: true, data: toCapabilityView(cap) });
  });

  // ── PATCH /capabilities/:id — enable/disable + constraint/routing update ────
  routes.patch("/:id", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const id = c.req.param("id");

    const body = await ctx.safeJsonParse<Record<string, unknown>>(c);
    if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

    const parsed = updateCapabilitySchema.safeParse(body);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.issues[0]?.message ?? "invalid body" }, 400);
    }
    const patch = parsed.data;

    const current = await store.getCapabilityById(tenantId, id);
    if (!current) return c.json<ApiResponse>({ ok: false, error: "capability not found" }, 404);

    // if any routing/inject field is patched, re-validate the MERGED config with
    // strict-host enforcement ON (no widen-by-patch: a strict host stays narrow).
    const touchesRouting =
      patch.secretId !== undefined ||
      patch.host !== undefined ||
      patch.pathPattern !== undefined ||
      patch.method !== undefined ||
      patch.injectAs !== undefined ||
      patch.injectKey !== undefined ||
      patch.injectFormat !== undefined;

    let spec: ReturnType<typeof validateCapabilitySpec> | undefined;
    if (touchesRouting) {
      spec = validateCapabilitySpec({
        secretId: patch.secretId ?? current.secretId,
        host: patch.host ?? current.host,
        pathPattern: patch.pathPattern ?? current.pathPattern,
        method: patch.method ?? current.method,
        injectAs: patch.injectAs ?? current.injectAs,
        injectKey: patch.injectKey ?? current.injectKey,
        injectFormat: patch.injectFormat ?? current.injectFormat,
      });
      if (!spec.ok) return c.json<ApiResponse>({ ok: false, error: spec.error }, 400);
    }

    try {
      const updated = await store.updateCapability(tenantId, id, {
        ...(spec?.ok ? { spec: spec.spec } : {}),
        ...(patch.constraints !== undefined ? { constraints: patch.constraints } : {}),
        ...(patch.enabled !== undefined ? { enabled: patch.enabled } : {}),
      });
      if (!updated) return c.json<ApiResponse>({ ok: false, error: "capability not found" }, 404);
      await audit(c, {
        tenantId,
        action: "capability.update",
        resourceType: "capability",
        resourceId: updated.id,
        metadata: {
          enabled: updated.enabled,
          routingChanged: touchesRouting,
          constraintsChanged: patch.constraints !== undefined,
        },
      });
      return c.json<ApiResponse>({ ok: true, data: toCapabilityView(updated) });
    } catch (e) {
      return errorResponse(c, e);
    }
  });

  // ── DELETE /capabilities/:id — delete + tear down paired routes ─────────────
  routes.delete("/:id", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const id = c.req.param("id");
    try {
      const removed = await store.deleteCapability(tenantId, id);
      if (!removed) return c.json<ApiResponse>({ ok: false, error: "capability not found" }, 404);
      await audit(c, {
        tenantId,
        action: "capability.delete",
        resourceType: "capability",
        resourceId: id,
      });
      return c.json<ApiResponse>({ ok: true, data: { id } });
    } catch (e) {
      return errorResponse(c, e);
    }
  });

  // ── POST /capabilities/:id/grants — grant an agent (materializes route) ─────
  routes.post("/:id/grants", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability grant management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const capabilityId = c.req.param("id");

    const body = await ctx.safeJsonParse<Record<string, unknown>>(c);
    if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);

    const parsed = createGrantSchema.safeParse(body);
    if (!parsed.success) {
      return c.json<ApiResponse>({ ok: false, error: parsed.error.issues[0]?.message ?? "invalid body" }, 400);
    }
    const { agentId, expiresAt } = parsed.data;
    const expires = expiresAt ? new Date(expiresAt) : null;
    if (expires && Number.isFinite(expires.getTime()) && expires.getTime() <= Date.now()) {
      return c.json<ApiResponse>({ ok: false, error: "expiresAt must be in the future" }, 400);
    }

    try {
      const result = await store.createGrant({ tenantId, capabilityId, agentId, expiresAt: expires });
      if (!result) return c.json<ApiResponse>({ ok: false, error: "capability not found" }, 404);
      await audit(c, {
        tenantId,
        action: "capability.grant.create",
        resourceType: "capability_grant",
        resourceId: result.grant.id,
        metadata: {
          capabilityId,
          agentId,
          secretRouteId: result.grant.secretRouteId,
          expiresAt: result.grant.expiresAt,
        },
      });
      return c.json<ApiResponse>({ ok: true, data: toGrantView(result.grant) }, 201);
    } catch (e) {
      if (e instanceof AgentNotFoundError) {
        return c.json<ApiResponse>({ ok: false, error: e.message }, 404);
      }
      // unique-violation on (tenant, agent, capability) -> already granted.
      const msg = e instanceof Error ? e.message : "";
      if (/unique|duplicate/i.test(msg)) {
        return c.json<ApiResponse>({ ok: false, error: "agent already granted this capability" }, 409);
      }
      return errorResponse(c, e);
    }
  });

  // ── DELETE /grants/:grantId — revoke (tears down paired route) ──────────────
  routes.delete("/grants/:grantId", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability grant management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const grantId = c.req.param("grantId");
    try {
      const revoked = await store.revokeGrant(tenantId, grantId);
      if (!revoked) return c.json<ApiResponse>({ ok: false, error: "grant not found" }, 404);
      await audit(c, {
        tenantId,
        action: "capability.grant.revoke",
        resourceType: "capability_grant",
        resourceId: grantId,
      });
      return c.json<ApiResponse>({ ok: true, data: { id: grantId } });
    } catch (e) {
      return errorResponse(c, e);
    }
  });

  return routes;
}

/**
 * The agent-scoped read: what capabilities an agent may USE (active, unexpired
 * grants to enabled capabilities). This is what the W-1c invoke path consults. It
 * is a SEPARATE router mounted under a different prefix (/agents) — see index.ts.
 * Never returns a secret value.
 */
export function createAgentCapabilityRoutes(
  ctx: StewardAppContext,
): Hono<{ Variables: AppVariables }> {
  const routes = new Hono<{ Variables: AppVariables }>();
  const store = new CapabilityStore(ctx.db);

  // ── GET /agents/:agentId/capabilities — usable-by-agent listing ─────────────
  routes.get("/:agentId/capabilities", async (c) => {
    const mfa = requireCapabilityAdmin(c, "Capability management");
    if (mfa) return mfa;
    const tenantId = c.get("tenantId");
    const agentId = c.req.param("agentId");
    const usable = await store.listUsableCapabilitiesForAgent(tenantId, agentId);
    return c.json<ApiResponse>({
      ok: true,
      data: usable.map(({ capability, grant }) => ({
        ...toCapabilityView(capability),
        grantId: grant.id,
        grantExpiresAt: grant.expiresAt,
      })),
    });
  });

  return routes;
}

/** map an internal error to a fail-closed API response (never leaks internals). */
function errorResponse(c: Context<{ Variables: AppVariables }>, e: unknown): Response {
  const msg = e instanceof Error ? e.message : "Unknown error";
  if (/not found/i.test(msg)) return c.json<ApiResponse>({ ok: false, error: msg }, 404);
  return c.json<ApiResponse>({ ok: false, error: "internal error" }, 500);
}

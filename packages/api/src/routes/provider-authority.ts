import type {
  ProviderAccessRequestV1,
  ProviderEnvironment,
  ProviderPrincipalType,
  ProviderRiskClass,
  ProviderRole,
} from "@stwd/shared";
import type { Context } from "hono";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  safeJsonParse,
  setNoStoreHeaders,
} from "../services/context";
import {
  type AuthorityAudit,
  ProviderAuthorityError,
  providerAuthorityStore,
} from "../services/provider-authority-store";

export const providerAuthorityRoutes = new Hono<{ Variables: AppVariables }>();

providerAuthorityRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

type RouteContext = Context<{ Variables: AppVariables }>;

function fail(c: RouteContext, error: unknown) {
  if (error instanceof ProviderAuthorityError) {
    return c.json<ApiResponse>({ ok: false, error: error.message }, error.status);
  }
  throw error;
}

function userSession(c: RouteContext): { userId: string; tenantRole: string } {
  const userId = c.get("userId");
  const tenantRole = c.get("tenantRole") ?? "";
  if (c.get("authType") !== "session-jwt" || !userId) {
    throw new ProviderAuthorityError("human session required", "forbidden", 403);
  }
  return { userId, tenantRole };
}

function auditFor(c: RouteContext, userId: string): AuthorityAudit {
  return async (event) => {
    await writeAuditEvent({
      tenantId: c.get("tenantId"),
      actorType: "user",
      actorId: userId,
      action: event.action,
      resourceType: event.resourceType,
      resourceId: event.resourceId,
      metadata: event.metadata,
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  };
}

function mutationContext(c: RouteContext, body: { expectedRevision?: unknown; reason?: unknown }) {
  const { userId, tenantRole } = userSession(c);
  return {
    tenantId: c.get("tenantId"),
    actorUserId: userId,
    tenantRole,
    mfaVerifiedAt: c.get("sessionMfaVerifiedAt") ?? Number.NaN,
    idempotencyKey: c.req.header("Idempotency-Key") ?? "",
    expectedRevision: typeof body.expectedRevision === "number" ? body.expectedRevision : -1,
    reason: typeof body.reason === "string" ? body.reason : "",
    requestId: c.get("requestId"),
    audit: auditFor(c, userId),
  };
}

async function requireReadAdmin(c: RouteContext, workspaceId?: string) {
  const { userId, tenantRole } = userSession(c);
  if (
    !(await providerAuthorityStore.canAdminister(
      c.get("tenantId"),
      workspaceId,
      userId,
      tenantRole,
    ))
  ) {
    throw new ProviderAuthorityError("resource not found", "not_found", 404);
  }
}

providerAuthorityRoutes.get("/workspaces", async (c) => {
  try {
    await requireReadAdmin(c);
    const data = await providerAuthorityStore.listWorkspaces(c.get("tenantId"));
    return c.json({
      ok: true,
      data,
      authorityRevision: await providerAuthorityStore.getTenantRevision(c.get("tenantId")),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/workspaces", async (c) => {
  const body = await safeJsonParse<{
    key: string;
    name: string;
    environment: ProviderEnvironment;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    const data = await providerAuthorityStore.createWorkspace(mutationContext(c, body), body);
    return c.json({ ok: true, data }, 201);
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/workspaces/:id/disable", async (c) => {
  const body = await safeJsonParse<{ expectedRevision: number; reason: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.disableWorkspace(
        mutationContext(c, body),
        c.req.param("id"),
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.get("/provider-accounts", async (c) => {
  const workspaceId = c.req.query("workspaceId");
  try {
    await requireReadAdmin(c, workspaceId);
    return c.json({
      ok: true,
      data: await providerAuthorityStore.listProviderAccounts(c.get("tenantId"), workspaceId),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-accounts", async (c) => {
  const body = await safeJsonParse<{
    workspaceId: string;
    adapterKey: string;
    externalRef: string;
    displayName: string;
    credentialSecretId?: string;
    credentialVersion?: number;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json(
      {
        ok: true,
        data: await providerAuthorityStore.createProviderAccount(mutationContext(c, body), body),
      },
      201,
    );
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-accounts/:id/disable", async (c) => {
  const body = await safeJsonParse<{ expectedRevision: number; reason: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.disableProviderAccount(
        mutationContext(c, body),
        c.req.param("id"),
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.get("/provider-accounts/:id/operations", async (c) => {
  const workspaceId = c.req.query("workspaceId");
  try {
    await requireReadAdmin(c, workspaceId);
    return c.json({
      ok: true,
      data: await providerAuthorityStore.listOperations(
        c.get("tenantId"),
        workspaceId,
        c.req.param("id"),
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-accounts/:id/operations", async (c) => {
  const body = await safeJsonParse<{
    operationKey: string;
    riskClass: ProviderRiskClass;
    capabilityId?: string;
    secretRouteId?: string;
    requestProfile?: Record<string, unknown>;
    responseProfile?: Record<string, unknown>;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json(
      {
        ok: true,
        data: await providerAuthorityStore.registerOperation(
          mutationContext(c, body),
          c.req.param("id"),
          body,
        ),
      },
      201,
    );
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.get("/provider-role-bindings", async (c) => {
  const workspaceId = c.req.query("workspaceId");
  try {
    await requireReadAdmin(c, workspaceId);
    return c.json({
      ok: true,
      data: await providerAuthorityStore.listRoleBindings(c.get("tenantId"), workspaceId),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-role-bindings", async (c) => {
  const body = await safeJsonParse<{
    workspaceId?: string;
    providerAccountId?: string;
    principalType: ProviderPrincipalType;
    principalId: string;
    roleKey: ProviderRole;
    operationKeys?: string[];
    environment?: ProviderEnvironment;
    notBefore?: string;
    expiresAt?: string;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    const data = await providerAuthorityStore.issueRoleBinding(mutationContext(c, body), {
      workspaceId: body.workspaceId,
      providerAccountId: body.providerAccountId,
      principalType: body.principalType,
      principalId: body.principalId,
      roleKey: body.roleKey,
      operationKeys: body.operationKeys ?? [],
      environment: body.environment,
      notBefore: body.notBefore ? new Date(body.notBefore) : undefined,
      expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
    });
    return c.json({ ok: true, data }, 201);
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-role-bindings/:id/revoke", async (c) => {
  const body = await safeJsonParse<{ expectedRevision: number; reason: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.revokeRoleBinding(
        mutationContext(c, body),
        c.req.param("id"),
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.get("/provider-grants", async (c) => {
  const workspaceId = c.req.query("workspaceId");
  try {
    await requireReadAdmin(c, workspaceId);
    return c.json({
      ok: true,
      data: await providerAuthorityStore.listGrants(c.get("tenantId"), workspaceId),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-grants", async (c) => {
  const body = await safeJsonParse<{
    workspaceId: string;
    providerAccountId: string;
    agentId: string;
    operationKeys: string[];
    environment?: ProviderEnvironment;
    notBefore?: string;
    expiresAt: string;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    const data = await providerAuthorityStore.issueGrant(mutationContext(c, body), {
      workspaceId: body.workspaceId,
      providerAccountId: body.providerAccountId,
      agentId: body.agentId,
      operationKeys: body.operationKeys,
      environment: body.environment,
      notBefore: body.notBefore ? new Date(body.notBefore) : undefined,
      expiresAt: new Date(body.expiresAt),
    });
    return c.json({ ok: true, data }, 201);
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-grants/:id/revoke", async (c) => {
  const body = await safeJsonParse<{ expectedRevision: number; reason: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.revokeGrant(mutationContext(c, body), c.req.param("id")),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.get("/provider-agent-budgets", async (c) => {
  const agentId = c.req.query("agentId") ?? "";
  const workspaceId = c.req.query("workspaceId");
  if (!agentId) return c.json<ApiResponse>({ ok: false, error: "agentId is required" }, 400);
  try {
    await requireReadAdmin(c, workspaceId);
    return c.json({
      ok: true,
      data: await providerAuthorityStore.listAgentBudgets(c.get("tenantId"), agentId, workspaceId),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-agent-budgets", async (c) => {
  const body = await safeJsonParse<{
    agentId: string;
    workspaceId?: string | null;
    dimension: "count" | "notional";
    windowSeconds: number;
    max: number;
    currency?: string | null;
    autoFreeze?: boolean;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json(
      {
        ok: true,
        data: await providerAuthorityStore.createAgentBudget(mutationContext(c, body), body),
      },
      201,
    );
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.put("/provider-agent-budgets/:id", async (c) => {
  const body = await safeJsonParse<{
    dimension: "count" | "notional";
    windowSeconds: number;
    max: number;
    currency?: string | null;
    autoFreeze?: boolean;
    enabled?: boolean;
    expectedRevision: number;
    reason: string;
  }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.updateAgentBudget(
        mutationContext(c, body),
        c.req.param("id"),
        body,
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.delete("/provider-agent-budgets/:id", async (c) => {
  const body = await safeJsonParse<{ expectedRevision: number; reason: string }>(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  try {
    return c.json({
      ok: true,
      data: await providerAuthorityStore.deleteAgentBudget(
        mutationContext(c, body),
        c.req.param("id"),
      ),
    });
  } catch (error) {
    return fail(c, error);
  }
});

providerAuthorityRoutes.post("/provider-access/check", async (c) => {
  const body = await safeJsonParse<
    Omit<ProviderAccessRequestV1, "tenantId" | "actor" | "evaluatedAt"> & {
      actor?: ProviderAccessRequestV1["actor"];
      evaluatedAt?: string;
    }
  >(c);
  if (!body) return c.json<ApiResponse>({ ok: false, error: "Invalid JSON body" }, 400);
  const authType = c.get("authType");
  const actor =
    authType === "agent-token"
      ? { type: "agent" as const, id: c.get("agentScope") ?? "" }
      : authType === "session-jwt" && c.get("userId")
        ? { type: "human" as const, id: c.get("userId") as string }
        : null;
  if (!actor?.id)
    return c.json<ApiResponse>(
      { ok: false, error: "authenticated human or agent principal required" },
      403,
    );
  try {
    const data = await providerAuthorityStore.checkAccess({
      ...body,
      tenantId: c.get("tenantId"),
      actor,
      evaluatedAt: body.evaluatedAt ?? new Date().toISOString(),
    });
    return c.json({ ok: true, data });
  } catch (error) {
    return fail(c, error);
  }
});

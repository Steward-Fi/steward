/**
 * Secret Vault + Credential Route CRUD endpoints.
 *
 * Mount: app.route("/secrets", secretsRoutes)
 *
 * All endpoints require an owner/admin user session. Tenant API keys and agent
 * tokens must not expose secret inventory or credential injection topology.
 * Secret values are NEVER returned in responses.
 *
 * IMPORTANT: Route handlers for /routes/* MUST be registered before /:id
 * handlers to prevent Hono from treating "routes" as a secret ID.
 */

import {
  getDb as getVaultDb,
  secretRoutes as secretRouteRows,
  tenantConfigs as tenantConfigsTable,
} from "@stwd/db";
import { type SecretVault, validateSecretRouteConfig } from "@stwd/vault";
import { and, eq } from "drizzle-orm";
import { type Context, Hono } from "hono";
import {
  type AuditEventInput,
  withTenantAuditedTransaction,
  writeAuditEvent,
} from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  ensureAgentForTenant,
  isNonEmptyString,
  safeJsonParse,
  sanitizeErrorMessage,
  setNoStoreHeaders,
} from "../services/context";
import { isRecentMfaTimestamp } from "../services/recent-mfa";
import {
  assertGovernedRouteUpdateIsSafe,
  assertNoOppositeAuthorityOverlap,
  lockSecretRouteNamespaces,
  SecretRouteAuthorityConflict,
} from "../services/secret-route-authority";
import { getConfiguredSecretVault } from "../services/vault-factory";

export const secretsRoutes = new Hono<{ Variables: AppVariables }>();

secretsRoutes.use("*", async (c, next) => {
  setNoStoreHeaders(c);
  await next();
});

async function writeSecretsAudit(
  c: Context<{ Variables: AppVariables }>,
  event: Omit<AuditEventInput, "ipAddress" | "userAgent" | "requestId">,
): Promise<void> {
  await writeAuditEvent(secretsAuditEvent(c, event));
}

function secretsAuditEvent(
  c: Context<{ Variables: AppVariables }>,
  event: Omit<AuditEventInput, "ipAddress" | "userAgent" | "requestId">,
): AuditEventInput {
  return {
    ...event,
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  };
}

type VaultDb = ReturnType<typeof getVaultDb>;
type VaultTx = Parameters<Parameters<VaultDb["transaction"]>[0]>[0];

// Route-config validation (host allowlist, path/method/injectAs/injectKey/
// injectFormat rules, per-host strictness) lives in the shared
// validateSecretRouteConfig in @stwd/vault — the single source of truth also
// used at the vault boundary. Only request-shape parsing stays local here.
const MAX_SECRET_ROUTE_PRIORITY = 1_000_000;
const SECRET_ROUTE_UPDATE_KEYS = new Set([
  "hostPattern",
  "agentId",
  "pathPattern",
  "method",
  "injectAs",
  "injectKey",
  "injectFormat",
  "injectionStrategy",
  "injectionConfig",
  "priority",
  "enabled",
  "requiresApproval",
  "approvalConfig",
]);

type SecretRouteUpdate = Partial<{
  hostPattern: string;
  agentId: string;
  pathPattern: string;
  method: string;
  injectAs: string;
  injectKey: string;
  injectFormat: string;
  injectionStrategy: "header" | "sigv4";
  injectionConfig: { service?: string; region?: string };
  priority: number;
  enabled: boolean;
  requiresApproval: boolean;
  approvalConfig: Record<string, unknown>;
}>;

type SecretRouteCreate = {
  secretId: string;
  agentId: string;
  hostPattern: string;
  pathPattern: string;
  method: string;
  injectAs: string;
  injectKey: string;
  injectFormat?: string;
  injectionStrategy?: "header" | "sigv4";
  injectionConfig?: { service?: string; region?: string };
  priority?: number;
  enabled?: boolean;
  requiresApproval?: boolean;
  approvalConfig?: Record<string, unknown>;
};

function parseSecretRouteUpdate(body: Record<string, unknown>):
  | {
      ok: true;
      value: SecretRouteUpdate;
    }
  | {
      ok: false;
      error: string;
    } {
  for (const key of Object.keys(body)) {
    if (!SECRET_ROUTE_UPDATE_KEYS.has(key)) {
      return { ok: false, error: `Unknown secret route field '${key}'` };
    }
  }

  const update: SecretRouteUpdate = {};
  const stringFields = [
    "hostPattern",
    "agentId",
    "pathPattern",
    "method",
    "injectAs",
    "injectKey",
    "injectFormat",
    "injectionStrategy",
  ] as const;

  for (const field of stringFields) {
    const value = body[field];
    if (value === undefined) continue;
    if (typeof value !== "string") {
      return { ok: false, error: `'${field}' must be a string` };
    }
    update[field] = value as never;
  }
  if (body.injectionConfig !== undefined) {
    if (
      typeof body.injectionConfig !== "object" ||
      body.injectionConfig === null ||
      Array.isArray(body.injectionConfig)
    ) {
      return { ok: false, error: "'injectionConfig' must be an object" };
    }
    update.injectionConfig = body.injectionConfig as { service?: string; region?: string };
  }

  if (body.priority !== undefined) {
    if (
      typeof body.priority !== "number" ||
      !Number.isSafeInteger(body.priority) ||
      body.priority < 0 ||
      body.priority > MAX_SECRET_ROUTE_PRIORITY
    ) {
      return {
        ok: false,
        error: `'priority' must be an integer between 0 and ${MAX_SECRET_ROUTE_PRIORITY}`,
      };
    }
    update.priority = body.priority;
  }

  if (body.enabled !== undefined) {
    if (typeof body.enabled !== "boolean") {
      return { ok: false, error: "'enabled' must be a boolean" };
    }
    update.enabled = body.enabled;
  }
  if (body.requiresApproval !== undefined) {
    if (typeof body.requiresApproval !== "boolean") {
      return { ok: false, error: "'requiresApproval' must be a boolean" };
    }
    update.requiresApproval = body.requiresApproval;
  }
  if (body.approvalConfig !== undefined) {
    if (
      typeof body.approvalConfig !== "object" ||
      body.approvalConfig === null ||
      Array.isArray(body.approvalConfig)
    ) {
      return { ok: false, error: "'approvalConfig' must be an object" };
    }
    update.approvalConfig = body.approvalConfig as Record<string, unknown>;
  }

  if (Object.keys(update).length === 0) {
    return { ok: false, error: "At least one route field is required" };
  }
  return { ok: true, value: update };
}

function parseSecretRouteCreate(
  body: Record<string, unknown>,
): { ok: true; value: SecretRouteCreate } | { ok: false; error: string } {
  const required = [
    "secretId",
    "agentId",
    "hostPattern",
    "pathPattern",
    "method",
    "injectAs",
    "injectKey",
  ] as const;
  for (const field of required) {
    if (!isNonEmptyString(body[field])) {
      return { ok: false, error: `'${field}' is required` };
    }
  }
  if (body.injectFormat !== undefined && typeof body.injectFormat !== "string") {
    return { ok: false, error: "'injectFormat' must be a string" };
  }
  if (
    body.injectionStrategy !== undefined &&
    body.injectionStrategy !== "header" &&
    body.injectionStrategy !== "sigv4"
  ) {
    return { ok: false, error: "'injectionStrategy' must be header or sigv4" };
  }
  if (
    body.injectionConfig !== undefined &&
    (typeof body.injectionConfig !== "object" ||
      body.injectionConfig === null ||
      Array.isArray(body.injectionConfig))
  ) {
    return { ok: false, error: "'injectionConfig' must be an object" };
  }
  if (body.priority !== undefined) {
    if (
      typeof body.priority !== "number" ||
      !Number.isSafeInteger(body.priority) ||
      body.priority < 0 ||
      body.priority > MAX_SECRET_ROUTE_PRIORITY
    ) {
      return {
        ok: false,
        error: `'priority' must be an integer between 0 and ${MAX_SECRET_ROUTE_PRIORITY}`,
      };
    }
  }
  if (body.enabled !== undefined && typeof body.enabled !== "boolean") {
    return { ok: false, error: "'enabled' must be a boolean" };
  }
  if (body.requiresApproval !== undefined && typeof body.requiresApproval !== "boolean") {
    return { ok: false, error: "'requiresApproval' must be a boolean" };
  }
  if (
    body.approvalConfig !== undefined &&
    (typeof body.approvalConfig !== "object" ||
      body.approvalConfig === null ||
      Array.isArray(body.approvalConfig))
  ) {
    return { ok: false, error: "'approvalConfig' must be an object" };
  }
  return {
    ok: true,
    value: {
      secretId: body.secretId as string,
      agentId: body.agentId as string,
      hostPattern: body.hostPattern as string,
      pathPattern: body.pathPattern as string,
      method: body.method as string,
      injectAs: body.injectAs as string,
      injectKey: body.injectKey as string,
      injectFormat: body.injectFormat as string | undefined,
      injectionStrategy: (body.injectionStrategy as "header" | "sigv4" | undefined) ?? "header",
      injectionConfig:
        (body.injectionConfig as { service?: string; region?: string } | undefined) ?? {},
      priority: body.priority as number | undefined,
      enabled: body.enabled as boolean | undefined,
      requiresApproval: body.requiresApproval as boolean | undefined,
      approvalConfig: body.approvalConfig as Record<string, unknown> | undefined,
    },
  };
}

function getSecretVault(): SecretVault {
  return getConfiguredSecretVault();
}

function requireTenantAdminSession(c: Context<{ Variables: AppVariables }>): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function hasRecentSessionMfa(c: Context<{ Variables: AppVariables }>, maxAgeMs = 5 * 60_000) {
  return isRecentMfaTimestamp(c.get("sessionMfaVerifiedAt"), maxAgeMs);
}

type TenantMfaPolicyConfig = {
  maxAgeSeconds?: number;
  requireFor?: {
    tenantAdmin?: boolean;
  };
};

type TenantAuthAbuseConfigWithMfa = {
  mfa?: TenantMfaPolicyConfig;
};

async function readTenantMfaPolicy(tenantId: string): Promise<TenantMfaPolicyConfig> {
  const [row] = await getVaultDb()
    .select({ authAbuseConfig: tenantConfigsTable.authAbuseConfig })
    .from(tenantConfigsTable)
    .where(eq(tenantConfigsTable.tenantId, tenantId));
  return (row?.authAbuseConfig as TenantAuthAbuseConfigWithMfa | undefined)?.mfa ?? {};
}

function tenantMfaMaxAgeMs(policy: TenantMfaPolicyConfig): number {
  const seconds = policy.maxAgeSeconds;
  return typeof seconds === "number" && Number.isFinite(seconds)
    ? Math.max(30, Math.min(3600, Math.floor(seconds))) * 1000
    : 5 * 60_000;
}

async function requireRecentTenantAdminMfa(
  c: Context<{ Variables: AppVariables }>,
  reason: string,
): Promise<Response | null> {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: `${reason} requires owner or admin session` },
      403,
    );
  }
  const tenantId = c.get("tenantId");
  const policy = tenantId ? await readTenantMfaPolicy(tenantId) : {};
  if (policy.requireFor?.tenantAdmin === false) return null;
  if (hasRecentSessionMfa(c, tenantMfaMaxAgeMs(policy))) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function validateSecretValue(value: string): string | null {
  if (/[\r\n]/.test(value)) {
    return "secret value must not contain line breaks";
  }
  return null;
}

// ─── Secret CRUD (collection) ─────────────────────────────────────────────────

/** POST /secrets — create a new secret */
secretsRoutes.post("/", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    name: string;
    value: string;
    description?: string;
    expiresAt?: string;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>({ ok: false, error: "'name' is required" }, 400);
  }

  if (!isNonEmptyString(body.value)) {
    return c.json<ApiResponse>({ ok: false, error: "'value' is required" }, 400);
  }
  const secretValueError = validateSecretValue(body.value);
  if (secretValueError) {
    return c.json<ApiResponse>({ ok: false, error: secretValueError }, 400);
  }

  try {
    const sv = getSecretVault();
    await writeSecretsAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
      action: "secret.create.authorized",
      resourceType: "secret",
      resourceId: body.name,
      metadata: { name: body.name, hasExpiry: !!body.expiresAt },
    });
    const secret = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const created = await sv.createSecretWithinTx(
        txRaw as VaultTx,
        tenantId,
        body.name,
        body.value,
        {
          description: body.description,
          expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
        },
      );
      await appendAudit(
        secretsAuditEvent(c, {
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
          action: "secret.create",
          resourceType: "secret",
          resourceId: created.id,
          metadata: { name: body.name, hasExpiry: !!body.expiresAt },
        }),
      );
      return created;
    });
    return c.json<ApiResponse>({ ok: true, data: secret }, 201);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    if (msg.includes("duplicate") || msg.includes("unique")) {
      return c.json<ApiResponse>({ ok: false, error: `Secret "${body.name}" already exists` }, 409);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

/** GET /secrets — list all secrets (metadata only) */
secretsRoutes.get("/", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const sv = getSecretVault();
  const list = await sv.listSecrets(tenantId);
  return c.json<ApiResponse>({ ok: true, data: list });
});

// ─── Route CRUD ───────────────────────────────────────────────────────────────
// NOTE: These MUST be registered before /:id routes to avoid "routes" being
// matched as a secret ID by the dynamic param handler.

/** POST /secrets/routes — create a credential injection route */
secretsRoutes.post("/routes", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Route management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    secretId: string;
    agentId: string;
    hostPattern: string;
    pathPattern?: string;
    method?: string;
    injectAs: string;
    injectKey: string;
    injectFormat?: string;
    injectionStrategy?: "header" | "sigv4";
    injectionConfig?: { service?: string; region?: string };
    priority?: number;
    enabled?: boolean;
    requiresApproval?: boolean;
    approvalConfig?: Record<string, unknown>;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const parsedCreate = parseSecretRouteCreate(body as Record<string, unknown>);
  if (!parsedCreate.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedCreate.error }, 400);
  }
  const routeInput = parsedCreate.value;
  const validationError = validateSecretRouteConfig(routeInput);
  if (validationError) {
    return c.json<ApiResponse>({ ok: false, error: validationError }, 400);
  }

  try {
    const agent = await ensureAgentForTenant(tenantId, routeInput.agentId);
    if (!agent) {
      return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
    }

    const sv = getSecretVault();
    const secretBefore = await sv.getSecretById(tenantId, routeInput.secretId);
    if (!secretBefore) {
      return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
    }
    await writeSecretsAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
      action: "secret_route.create.authorized",
      resourceType: "secret_route",
      resourceId: routeInput.secretId,
      metadata: {
        secretId: routeInput.secretId,
        agentId: routeInput.agentId,
        hostPattern: routeInput.hostPattern,
        pathPattern: routeInput.pathPattern,
        method: routeInput.method,
        injectAs: routeInput.injectAs,
        injectKey: routeInput.injectKey,
        priority: routeInput.priority ?? 0,
        enabled: routeInput.enabled ?? true,
        requiresApproval: routeInput.requiresApproval ?? false,
        approvalConfig: routeInput.approvalConfig ?? {},
      },
    });
    const route = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const tx = txRaw as VaultTx;
      await sv.lockSecretLineageWithinTx(tx, tenantId, secretBefore.name);
      const currentSecret = await sv.getSecretByIdWithinTx(tx, tenantId, routeInput.secretId);
      if (!currentSecret || currentSecret.version !== secretBefore.version) {
        throw new SecretRouteAuthorityConflict("secret changed during route creation");
      }
      await lockSecretRouteNamespaces(tx, tenantId, [routeInput.agentId]);
      const created = await sv.createRouteWithinTx(tx, tenantId, routeInput.secretId, {
        agentId: routeInput.agentId,
        hostPattern: routeInput.hostPattern,
        pathPattern: routeInput.pathPattern,
        method: routeInput.method,
        injectAs: routeInput.injectAs,
        injectKey: routeInput.injectKey,
        injectFormat: routeInput.injectFormat,
        injectionStrategy: routeInput.injectionStrategy,
        injectionConfig: routeInput.injectionConfig,
        priority: routeInput.priority,
        enabled: routeInput.enabled,
        requiresApproval: routeInput.requiresApproval,
        approvalConfig: routeInput.approvalConfig,
      });
      await assertNoOppositeAuthorityOverlap(tx, {
        ...created,
        agentId: routeInput.agentId,
      });
      await appendAudit(
        secretsAuditEvent(c, {
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
          action: "secret_route.create",
          resourceType: "secret_route",
          resourceId: created.id,
          metadata: {
            secretId: routeInput.secretId,
            agentId: routeInput.agentId,
            hostPattern: routeInput.hostPattern,
            pathPattern: routeInput.pathPattern,
            method: routeInput.method,
            injectAs: routeInput.injectAs,
            injectKey: routeInput.injectKey,
            priority: routeInput.priority ?? 0,
            enabled: routeInput.enabled ?? true,
            requiresApproval: routeInput.requiresApproval ?? false,
            approvalConfig: routeInput.approvalConfig ?? {},
          },
        }),
      );
      return created;
    });
    return c.json<ApiResponse>({ ok: true, data: route }, 201);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    if (e instanceof SecretRouteAuthorityConflict) {
      return c.json<ApiResponse>({ ok: false, error: msg }, 409);
    }
    if (msg.includes("not found")) {
      return c.json<ApiResponse>({ ok: false, error: msg }, 404);
    }
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

/** GET /secrets/routes — list all routes */
secretsRoutes.get("/routes", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Route management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const sv = getSecretVault();
  const secretId = c.req.query("secretId");
  const routes = (await sv.listRoutes(tenantId)).filter(
    (route) => !secretId || route.secretId === secretId,
  );
  return c.json<ApiResponse>({ ok: true, data: routes });
});

/** PUT /secrets/routes/:id — update route */
secretsRoutes.put("/routes/:id", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Route management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const routeId = c.req.param("id");
  const body = await safeJsonParse<Record<string, unknown>>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const parsedUpdate = parseSecretRouteUpdate(body);
  if (!parsedUpdate.ok) {
    return c.json<ApiResponse>({ ok: false, error: parsedUpdate.error }, 400);
  }
  const update = parsedUpdate.value;

  // Partial-patch validation: skip per-host strictness here (the patch may omit
  // method/path). The merged-config pass below enforces strict-host rules.
  const validationError = validateSecretRouteConfig(update, { enforceStrictHosts: false });
  if (validationError) {
    return c.json<ApiResponse>({ ok: false, error: validationError }, 400);
  }
  if (update.agentId !== undefined) {
    if (!isNonEmptyString(update.agentId)) {
      return c.json<ApiResponse>({ ok: false, error: "'agentId' is invalid" }, 400);
    }
    const agent = await ensureAgentForTenant(tenantId, update.agentId);
    if (!agent) {
      return c.json<ApiResponse>({ ok: false, error: "Agent not found" }, 404);
    }
  }

  const sv = getSecretVault();
  const existing = await sv.getRoute(tenantId, routeId);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Route not found" }, 404);
  }
  const existingSecret = await sv.getSecretById(tenantId, existing.secretId);
  if (!existingSecret) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }
  try {
    assertGovernedRouteUpdateIsSafe(existing, update);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Route update conflicts with governed authority";
    return c.json<ApiResponse>({ ok: false, error: msg }, 409);
  }
  // Fail-closed re-validation against the MERGED config. A partial update (e.g.
  // changing only pathPattern or method) is validated in isolation above and so
  // would not trigger per-host strictness for a route that already targets a
  // strict host. Re-run the shared validator on existing ∪ update so a strict
  // host's narrowness (explicit method + deep path) can never be loosened by a
  // partial edit.
  //
  // Skipped when the update leaves the route DISABLED: a disabled route injects
  // no credential, so strictness is moot, and an admin must always be able to
  // disable a legacy strict-host route that predates these rules.
  const willBeEnabled = update.enabled ?? existing.enabled ?? true;
  if (willBeEnabled) {
    const mergedConfig = {
      hostPattern: update.hostPattern ?? existing.hostPattern ?? undefined,
      pathPattern: update.pathPattern ?? existing.pathPattern ?? undefined,
      method: update.method ?? existing.method ?? undefined,
      injectAs: update.injectAs ?? existing.injectAs ?? undefined,
      injectKey: update.injectKey ?? existing.injectKey ?? undefined,
      injectFormat: update.injectFormat ?? existing.injectFormat ?? undefined,
    };
    const mergedValidationError = validateSecretRouteConfig(mergedConfig);
    if (mergedValidationError) {
      return c.json<ApiResponse>({ ok: false, error: mergedValidationError }, 400);
    }
  }
  await writeSecretsAudit(c, {
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
    action: "secret_route.update.authorized",
    resourceType: "secret_route",
    resourceId: routeId,
    metadata: { before: existing, updates: update },
  });
  let updated: Awaited<ReturnType<typeof sv.updateRoute>>;
  try {
    updated = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const tx = txRaw as VaultTx;
      await sv.lockSecretLineageWithinTx(tx, tenantId, existingSecret.name);
      const [currentBeforeLock] = await tx
        .select()
        .from(secretRouteRows)
        .where(and(eq(secretRouteRows.id, routeId), eq(secretRouteRows.tenantId, tenantId)))
        .limit(1);
      if (!currentBeforeLock) return null;
      if (!currentBeforeLock.agentId) {
        throw new SecretRouteAuthorityConflict("route has no agent namespace");
      }
      const destinationAgentId = update.agentId ?? currentBeforeLock.agentId;
      await lockSecretRouteNamespaces(tx, tenantId, [
        currentBeforeLock.agentId,
        destinationAgentId,
      ]);
      const [current] = await tx
        .select()
        .from(secretRouteRows)
        .where(and(eq(secretRouteRows.id, routeId), eq(secretRouteRows.tenantId, tenantId)))
        .limit(1);
      if (
        !current ||
        current.agentId !== currentBeforeLock.agentId ||
        current.secretId !== existing.secretId
      ) {
        throw new SecretRouteAuthorityConflict("route changed during update");
      }
      assertGovernedRouteUpdateIsSafe(current, update);
      const changed = await sv.updateRouteWithinTx(tx, tenantId, routeId, update);
      if (changed) {
        await assertNoOppositeAuthorityOverlap(tx, {
          ...changed,
          agentId: destinationAgentId,
        });
        await appendAudit(
          secretsAuditEvent(c, {
            tenantId,
            actorType: "user",
            actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
            action: "secret_route.update",
            resourceType: "secret_route",
            resourceId: routeId,
            metadata: { before: current, after: changed },
          }),
        );
      }
      return changed;
    });
  } catch (e) {
    if (e instanceof SecretRouteAuthorityConflict) {
      return c.json<ApiResponse>({ ok: false, error: e.message }, 409);
    }
    throw e;
  }

  if (!updated) {
    return c.json<ApiResponse>({ ok: false, error: "Route not found" }, 404);
  }

  return c.json<ApiResponse>({ ok: true, data: updated });
});

/** DELETE /secrets/routes/:id — delete route */
secretsRoutes.delete("/routes/:id", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Route management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const routeId = c.req.param("id");
  const sv = getSecretVault();
  const existing = await sv.getRoute(tenantId, routeId);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Route not found" }, 404);
  }
  const existingSecret = await sv.getSecretById(tenantId, existing.secretId);
  if (!existingSecret) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }
  await writeSecretsAudit(c, {
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
    action: "secret_route.delete.authorized",
    resourceType: "secret_route",
    resourceId: routeId,
    metadata: { deleted: existing },
  });
  let deleted: typeof secretRouteRows.$inferSelect | null;
  try {
    deleted = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const tx = txRaw as VaultTx;
      await sv.lockSecretLineageWithinTx(tx, tenantId, existingSecret.name);
      const [currentBeforeLock] = await tx
        .select()
        .from(secretRouteRows)
        .where(and(eq(secretRouteRows.id, routeId), eq(secretRouteRows.tenantId, tenantId)))
        .limit(1);
      if (!currentBeforeLock) return null;
      if (!currentBeforeLock.agentId) {
        throw new SecretRouteAuthorityConflict("route has no agent namespace");
      }
      await lockSecretRouteNamespaces(tx, tenantId, [currentBeforeLock.agentId]);
      const [current] = await tx
        .select()
        .from(secretRouteRows)
        .where(and(eq(secretRouteRows.id, routeId), eq(secretRouteRows.tenantId, tenantId)))
        .limit(1);
      if (
        !current ||
        current.agentId !== currentBeforeLock.agentId ||
        current.secretId !== existing.secretId
      ) {
        throw new SecretRouteAuthorityConflict("route changed during delete");
      }
      const [removed] = await tx
        .delete(secretRouteRows)
        .where(and(eq(secretRouteRows.id, routeId), eq(secretRouteRows.tenantId, tenantId)))
        .returning();
      if (!removed) return null;
      await appendAudit(
        secretsAuditEvent(c, {
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
          action: "secret_route.delete",
          resourceType: "secret_route",
          resourceId: routeId,
          metadata: { deleted: current },
        }),
      );
      return removed;
    });
  } catch (e) {
    if (e instanceof SecretRouteAuthorityConflict) {
      return c.json<ApiResponse>({ ok: false, error: e.message }, 409);
    }
    throw e;
  }

  if (!deleted) {
    return c.json<ApiResponse>({ ok: false, error: "Route not found" }, 404);
  }

  return c.json<ApiResponse>({ ok: true, data: { deleted: routeId } });
});

// ─── Secret CRUD (by ID) ──────────────────────────────────────────────────────
// NOTE: These /:id handlers are registered AFTER /routes/* to avoid swallowing
// the literal path segment "routes" as a dynamic param.

/** GET /secrets/:id — get secret metadata */
secretsRoutes.get("/:id", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const secretId = c.req.param("id");
  const sv = getSecretVault();
  const secret = await sv.getSecretById(tenantId, secretId);

  if (!secret) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }

  return c.json<ApiResponse>({ ok: true, data: secret });
});

/** PUT /secrets/:id — update secret value (creates new version) */
secretsRoutes.put("/:id", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const secretId = c.req.param("id");
  const body = await safeJsonParse<{ value: string }>(c);

  if (!body || !isNonEmptyString(body.value)) {
    return c.json<ApiResponse>({ ok: false, error: "'value' is required" }, 400);
  }
  const secretValueError = validateSecretValue(body.value);
  if (secretValueError) {
    return c.json<ApiResponse>({ ok: false, error: secretValueError }, 400);
  }

  const sv = getSecretVault();
  const existing = await sv.getSecretById(tenantId, secretId);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }

  try {
    await writeSecretsAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
      action: "secret.rotate.authorized",
      resourceType: "secret",
      resourceId: secretId,
      metadata: { name: existing.name },
    });
    const rotated = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const current = await sv.getSecretByIdWithinTx(txRaw as VaultTx, tenantId, secretId);
      if (!current || current.name !== existing.name || current.version !== existing.version) {
        return null;
      }
      const changed = await sv.rotateSecretWithinTx(
        txRaw as VaultTx,
        tenantId,
        existing.name,
        body.value,
      );
      await appendAudit(
        secretsAuditEvent(c, {
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
          action: "secret.rotate",
          resourceType: "secret",
          resourceId: changed.id,
          metadata: { name: existing.name },
        }),
      );
      return changed;
    });
    if (!rotated)
      return c.json<ApiResponse>({ ok: false, error: "Secret changed concurrently" }, 409);
    return c.json<ApiResponse>({ ok: true, data: rotated });
  } catch (e: unknown) {
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

/** DELETE /secrets/:id — soft delete */
secretsRoutes.delete("/:id", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const secretId = c.req.param("id");
  const sv = getSecretVault();
  const existing = await sv.getSecretById(tenantId, secretId);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }
  await writeSecretsAudit(c, {
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
    action: "secret.delete.authorized",
    resourceType: "secret",
    resourceId: secretId,
    metadata: { name: existing.name },
  });
  const deleted = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
    const removed = await sv.deleteSecretWithinTx(
      txRaw as VaultTx,
      tenantId,
      secretId,
      existing.name,
    );
    if (!removed) return false;
    await appendAudit(
      secretsAuditEvent(c, {
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
        action: "secret.delete",
        resourceType: "secret",
        resourceId: secretId,
      }),
    );
    return true;
  });

  if (!deleted) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }

  return c.json<ApiResponse>({ ok: true, data: { deleted: secretId } });
});

/** POST /secrets/:id/rotate — rotate with new value */
secretsRoutes.post("/:id/rotate", async (c) => {
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Secret management");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const secretId = c.req.param("id");
  const body = await safeJsonParse<{ value: string }>(c);

  if (!body || !isNonEmptyString(body.value)) {
    return c.json<ApiResponse>({ ok: false, error: "'value' is required" }, 400);
  }
  const secretValueError = validateSecretValue(body.value);
  if (secretValueError) {
    return c.json<ApiResponse>({ ok: false, error: secretValueError }, 400);
  }

  const sv = getSecretVault();
  const existing = await sv.getSecretById(tenantId, secretId);
  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Secret not found" }, 404);
  }

  try {
    await writeSecretsAudit(c, {
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
      action: "secret.rotate.authorized",
      resourceType: "secret",
      resourceId: secretId,
      metadata: { name: existing.name },
    });
    const rotated = await withTenantAuditedTransaction(tenantId, async (txRaw, appendAudit) => {
      const current = await sv.getSecretByIdWithinTx(txRaw as VaultTx, tenantId, secretId);
      if (!current || current.name !== existing.name || current.version !== existing.version) {
        return null;
      }
      const changed = await sv.rotateSecretWithinTx(
        txRaw as VaultTx,
        tenantId,
        existing.name,
        body.value,
      );
      await appendAudit(
        secretsAuditEvent(c, {
          tenantId,
          actorType: "user",
          actorId: c.get("userId") ?? c.get("authType") ?? tenantId,
          action: "secret.rotate",
          resourceType: "secret",
          resourceId: changed.id,
          metadata: { name: existing.name },
        }),
      );
      return changed;
    });
    if (!rotated)
      return c.json<ApiResponse>({ ok: false, error: "Secret changed concurrently" }, 409);
    return c.json<ApiResponse>({ ok: true, data: rotated });
  } catch (e: unknown) {
    return c.json<ApiResponse>({ ok: false, error: sanitizeErrorMessage(e) }, 500);
  }
});

/**
 * Tenant management routes.
 *
 * Mount: app.route("/tenants", tenantRoutes)
 */

import { hashApiKey, hasPlatformScope, platformAuthMiddleware } from "@stwd/auth";
import {
  auditEvents as auditEventRows,
  proxyAuditLog as proxyAuditLogRows,
  secretRoutes as secretRouteRows,
  secrets as secretRows,
} from "@stwd/db";
import { encryptWebhookSecret } from "@stwd/webhooks";
import { and, eq, ne } from "drizzle-orm";
import { type Context, Hono, type Next } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  findTenant,
  getConditionSetReferenceValidationError,
  getTenantPayload,
  isNonEmptyString,
  isValidTenantId,
  type PolicyRule,
  requireTenantLevel,
  safeJsonParse,
  type Tenant,
  type TenantConfig,
  tenantAuth,
  tenantConfigs,
  tenants,
  webhookConfigs,
} from "../services/context";
import { getPolicyRulesValidationError } from "../services/policy-validation";
import { validateWebhookUrl } from "../services/webhook-url";

export const tenantRoutes = new Hono<{ Variables: AppVariables }>();
const LEGACY_TENANT_WEBHOOK_DESCRIPTION = "legacy:tenant-webhook";
type LegacyTenantWebhookConfig = typeof webhookConfigs.$inferSelect;

// Per-route auth that pins the JWT's tenantId to the URL :id path param.
// Applied directly on handlers below so the "public discovery" route in
// tenantConfigRoutes (mounted before this router) doesn't need a magic-string
// skip in a catch-all middleware.
export const requireTenantId = (c: Context<{ Variables: AppVariables }>, next: Next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") });

function generateWebhookSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `whsec_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function isReservedTenantId(id: string): boolean {
  const normalized = id.toLowerCase();
  return (
    normalized === "platform" ||
    normalized === "system" ||
    normalized === "default" ||
    normalized === "personal" ||
    normalized.startsWith("personal-") ||
    normalized.startsWith("eth:") ||
    normalized.startsWith("t-") ||
    normalized.startsWith("solana:")
  );
}

async function tenantIdHasRetainedState(tenantId: string): Promise<boolean> {
  const [[secret], [secretRoute], [proxyAudit], [auditEvent]] = await Promise.all([
    db
      .select({ id: secretRows.id })
      .from(secretRows)
      .where(eq(secretRows.tenantId, tenantId))
      .limit(1),
    db
      .select({ id: secretRouteRows.id })
      .from(secretRouteRows)
      .where(eq(secretRouteRows.tenantId, tenantId))
      .limit(1),
    db
      .select({ id: proxyAuditLogRows.id })
      .from(proxyAuditLogRows)
      .where(eq(proxyAuditLogRows.tenantId, tenantId))
      .limit(1),
    db
      .select({ id: auditEventRows.id })
      .from(auditEventRows)
      .where(eq(auditEventRows.tenantId, tenantId))
      .limit(1),
  ]);

  return Boolean(secret || secretRoute || proxyAudit || auditEvent);
}

async function upsertLegacyTenantWebhook(tenantId: string, url: string): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .update(webhookConfigs)
      .set({ enabled: false, updatedAt: new Date() })
      .where(
        and(
          eq(webhookConfigs.tenantId, tenantId),
          eq(webhookConfigs.description, LEGACY_TENANT_WEBHOOK_DESCRIPTION),
          ne(webhookConfigs.url, url),
        ),
      );

    await tx
      .insert(webhookConfigs)
      .values({
        tenantId,
        url,
        secret: encryptWebhookSecret(generateWebhookSecret()),
        events: [],
        enabled: true,
        description: LEGACY_TENANT_WEBHOOK_DESCRIPTION,
      })
      .onConflictDoUpdate({
        target: [webhookConfigs.tenantId, webhookConfigs.url],
        set: {
          events: [],
          enabled: true,
          description: LEGACY_TENANT_WEBHOOK_DESCRIPTION,
          updatedAt: new Date(),
        },
      });
  });
}

async function snapshotLegacyTenantWebhooks(
  tenantId: string,
): Promise<LegacyTenantWebhookConfig[]> {
  return db
    .select()
    .from(webhookConfigs)
    .where(
      and(
        eq(webhookConfigs.tenantId, tenantId),
        eq(webhookConfigs.description, LEGACY_TENANT_WEBHOOK_DESCRIPTION),
      ),
    );
}

async function restoreLegacyTenantWebhooks(
  tenantId: string,
  snapshot: LegacyTenantWebhookConfig[],
): Promise<void> {
  await db.transaction(async (tx) => {
    await tx
      .delete(webhookConfigs)
      .where(
        and(
          eq(webhookConfigs.tenantId, tenantId),
          eq(webhookConfigs.description, LEGACY_TENANT_WEBHOOK_DESCRIPTION),
        ),
      );

    if (snapshot.length > 0) {
      await tx.insert(webhookConfigs).values(snapshot);
    }
  });
}

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

function requireRecentTenantAdminMfa(
  c: Parameters<typeof requireTenantLevel>[0],
  reason: string,
): Response | null {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: `${reason} requires owner or admin session` },
      403,
    );
  }
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function getTenantPayloadForRequest(
  c: Parameters<typeof requireTenantLevel>[0],
  tenant: Tenant,
): Omit<Tenant, "apiKeyHash"> & Partial<TenantConfig> {
  const payload = getTenantPayload(tenant);
  if (requireTenantAdminSession(c) && hasRecentSessionMfa(c)) return payload;
  const { webhookUrl: _webhookUrl, defaultPolicies: _defaultPolicies, ...redacted } = payload;
  return redacted;
}

function requirePlatformRouteScope(
  c: Context<{ Variables: AppVariables }>,
  scope: string,
): Response | null {
  if (hasPlatformScope(c.get("platformScopes"), scope)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `Platform route requires scoped platform key with ${scope}` },
    403,
  );
}

tenantRoutes.post("/", platformAuthMiddleware(), async (c) => {
  const writeScopeResponse = requirePlatformRouteScope(c, "platform:write");
  if (writeScopeResponse) return writeScopeResponse;
  const scopeResponse = requirePlatformRouteScope(c, "platform:tenant:create");
  if (scopeResponse) return scopeResponse;

  const body = await safeJsonParse<{
    id: string;
    name: string;
    apiKeyHash: string;
    webhookUrl?: string;
    defaultPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (!isValidTenantId(body.id)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Invalid tenant id — must be 1-64 alphanumeric characters (plus _ - . :)",
      },
      400,
    );
  }
  if (isReservedTenantId(body.id)) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant id is reserved" }, 400);
  }

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>(
      { ok: false, error: "name is required and must be a non-empty string" },
      400,
    );
  }

  if (typeof body.apiKeyHash !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "apiKeyHash is required" }, 400);
  }
  if (body.webhookUrl !== undefined) {
    const urlError = isNonEmptyString(body.webhookUrl)
      ? validateWebhookUrl(body.webhookUrl)
      : "webhookUrl must be a non-empty string";
    if (urlError) return c.json<ApiResponse>({ ok: false, error: urlError }, 400);
  }
  if (body.defaultPolicies !== undefined) {
    if (!Array.isArray(body.defaultPolicies)) {
      return c.json<ApiResponse>({ ok: false, error: "defaultPolicies must be an array" }, 400);
    }
    const policiesError = getPolicyRulesValidationError(body.defaultPolicies);
    if (policiesError) return c.json<ApiResponse>({ ok: false, error: policiesError }, 400);
    const conditionSetError = await getConditionSetReferenceValidationError(
      body.id,
      body.defaultPolicies,
    );
    if (conditionSetError) return c.json<ApiResponse>({ ok: false, error: conditionSetError }, 400);
  }

  const existingTenant = await findTenant(body.id);
  if (existingTenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 400);
  }
  if (await tenantIdHasRetainedState(body.id)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Tenant id has retained historical state and cannot be reused",
      },
      409,
    );
  }

  const apiKeyHash =
    body.apiKeyHash && !body.apiKeyHash.match(/^[0-9a-f]{64}$/)
      ? hashApiKey(body.apiKeyHash)
      : body.apiKeyHash;

  await writeAuditEvent({
    tenantId: body.id,
    actorType: "platform",
    action: "tenant.create.authorized",
    resourceType: "tenant",
    resourceId: body.id,
    metadata: {
      name: body.name,
      hasWebhook: !!body.webhookUrl,
      defaultPolicyCount: body.defaultPolicies?.length ?? 0,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  const [tenant] = await db
    .insert(tenants)
    .values({
      id: body.id,
      name: body.name,
      apiKeyHash,
    })
    .returning();

  if (body.webhookUrl) {
    await upsertLegacyTenantWebhook(body.id, body.webhookUrl);
  }

  tenantConfigs.set(body.id, {
    id: body.id,
    name: body.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies,
  });

  try {
    await writeAuditEvent({
      tenantId: body.id,
      actorType: "platform",
      action: "tenant.create",
      resourceType: "tenant",
      resourceId: body.id,
      metadata: {
        name: body.name,
        hasWebhook: !!body.webhookUrl,
        defaultPolicyCount: body.defaultPolicies?.length ?? 0,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    tenantConfigs.delete(body.id);
    await db.delete(tenants).where(eq(tenants.id, body.id));
    throw error;
  }

  return c.json<ApiResponse<Omit<Tenant, "apiKeyHash"> & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

tenantRoutes.get("/:id", requireTenantId, async (c) => {
  const tenant = c.get("tenant");
  return c.json<ApiResponse<Omit<Tenant, "apiKeyHash"> & Partial<TenantConfig>>>({
    ok: true,
    data: getTenantPayloadForRequest(c, tenant),
  });
});

tenantRoutes.put("/:id/webhook", requireTenantId, async (c) => {
  const mfaResponse = requireRecentTenantAdminMfa(c, "Tenant webhook updates");
  if (mfaResponse) return mfaResponse;

  const tenant = c.get("tenant");
  const tenantConfig = c.get("tenantConfig");
  const body = await safeJsonParse<{
    webhookUrl?: string;
    defaultPolicies?: PolicyRule[];
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (body.webhookUrl !== undefined) {
    const urlError = isNonEmptyString(body.webhookUrl)
      ? validateWebhookUrl(body.webhookUrl)
      : "webhookUrl must be a non-empty string";
    if (urlError) return c.json<ApiResponse>({ ok: false, error: urlError }, 400);
  }

  if (body.defaultPolicies !== undefined && !Array.isArray(body.defaultPolicies)) {
    return c.json<ApiResponse>({ ok: false, error: "defaultPolicies must be an array" }, 400);
  }
  if (body.defaultPolicies !== undefined) {
    const policiesError = getPolicyRulesValidationError(body.defaultPolicies);
    if (policiesError) return c.json<ApiResponse>({ ok: false, error: policiesError }, 400);
    const conditionSetError = await getConditionSetReferenceValidationError(
      tenant.id,
      body.defaultPolicies,
    );
    if (conditionSetError) return c.json<ApiResponse>({ ok: false, error: conditionSetError }, 400);
  }

  const updatedConfig: TenantConfig = {
    ...tenantConfig,
    id: tenant.id,
    name: tenant.name,
    webhookUrl: body.webhookUrl ?? tenantConfig.webhookUrl,
    defaultPolicies: body.defaultPolicies ?? tenantConfig.defaultPolicies,
  };
  const previousConfig: TenantConfig = { ...tenantConfig };
  const legacyWebhookSnapshot =
    body.webhookUrl !== undefined ? await snapshotLegacyTenantWebhooks(tenant.id) : [];

  await writeAuditEvent({
    tenantId: tenant.id,
    actorType: "user",
    actorId: c.get("userId") ?? tenant.id,
    action: "tenant.update.authorized",
    resourceType: "tenant",
    resourceId: tenant.id,
    metadata: {
      webhookUrlChanged: body.webhookUrl !== undefined,
      defaultPoliciesChanged: body.defaultPolicies !== undefined,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  if (body.webhookUrl) {
    await upsertLegacyTenantWebhook(tenant.id, body.webhookUrl);
  }

  tenantConfigs.set(tenant.id, updatedConfig);

  try {
    await writeAuditEvent({
      tenantId: tenant.id,
      actorType: "user",
      actorId: c.get("userId") ?? tenant.id,
      action: "tenant.update",
      resourceType: "tenant",
      resourceId: tenant.id,
      metadata: {
        webhookUrlChanged: body.webhookUrl !== undefined,
        defaultPoliciesChanged: body.defaultPolicies !== undefined,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (error) {
    tenantConfigs.set(tenant.id, previousConfig);
    if (body.webhookUrl !== undefined) {
      await restoreLegacyTenantWebhooks(tenant.id, legacyWebhookSnapshot);
    }
    throw error;
  }

  return c.json<ApiResponse<TenantConfig>>({
    ok: true,
    data: updatedConfig,
  });
});

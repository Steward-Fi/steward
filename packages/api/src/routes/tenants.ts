/**
 * Tenant management routes.
 *
 * Mount: app.route("/tenants", tenantRoutes)
 */

import { hashApiKey, platformAuthMiddleware } from "@stwd/auth";
import { tenantConfigs as tenantConfigsTable } from "@stwd/db";
import type { TenantAuthAbuseConfig } from "@stwd/shared";
import { encryptWebhookSecret } from "@stwd/webhooks";
import { and, eq, ne } from "drizzle-orm";
import { type Context, Hono, type Next } from "hono";
import { trackAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  findTenant,
  getTenantPayload,
  isNonEmptyString,
  isValidTenantId,
  type PolicyRule,
  safeJsonParse,
  setNoStoreHeaders,
  type Tenant,
  type TenantConfig,
  tenantAuth,
  tenantConfigs,
  tenants,
  webhookConfigs,
} from "../services/context";

export const tenantRoutes = new Hono<{ Variables: AppVariables }>();

type TenantResponse = Omit<Tenant, "apiKeyHash"> & TenantConfig;

const LEGACY_TENANT_WEBHOOK_DESCRIPTION = "legacy:tenant-webhook";

function generateWebhookSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `whsec_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
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

function requireTenantAdminSession(c: Context<{ Variables: AppVariables }>): boolean {
  const role = c.get("tenantRole");
  return c.get("authType") === "session-jwt" && (role === "owner" || role === "admin");
}

function hasRecentSessionMfa(c: Context<{ Variables: AppVariables }>, maxAgeMs = 5 * 60_000) {
  const verifiedAt = c.get("sessionMfaVerifiedAt");
  return (
    typeof verifiedAt === "number" &&
    Number.isFinite(verifiedAt) &&
    Date.now() - verifiedAt <= maxAgeMs
  );
}

type TenantMfaPolicyConfig = {
  maxAgeSeconds?: number;
  requireFor?: {
    tenantAdmin?: boolean;
  };
};

type TenantAuthAbuseConfigWithMfa = TenantAuthAbuseConfig & {
  mfa?: TenantMfaPolicyConfig;
};

async function readTenantMfaPolicy(tenantId: string): Promise<TenantMfaPolicyConfig> {
  const [row] = await db
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
  const tenantId = c.req.param("id") || c.get("tenantId");
  const policy = tenantId ? await readTenantMfaPolicy(tenantId) : {};
  if (policy.requireFor?.tenantAdmin === false) return null;
  if (hasRecentSessionMfa(c, tenantMfaMaxAgeMs(policy))) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function getTenantPayloadForRequest(
  c: Context<{ Variables: AppVariables }>,
  tenant: Tenant,
): TenantResponse {
  const payload = getTenantPayload(tenant);
  if (requireTenantAdminSession(c) && hasRecentSessionMfa(c)) return payload;
  const { webhookUrl: _webhookUrl, defaultPolicies: _defaultPolicies, ...redacted } = payload;
  return redacted;
}

// Per-route auth that pins the JWT's tenantId to the URL :id path param.
// Applied directly on handlers below so the "public discovery" route in
// tenantConfigRoutes (mounted before this router) doesn't need a magic-string
// skip in a catch-all middleware.
export const requireTenantId = (c: Context<{ Variables: AppVariables }>, next: Next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") });

const requirePlatformTenantCreate = (c: Context<{ Variables: AppVariables }>, next: Next) => {
  if (!c.req.header("X-Steward-Platform-Key")) {
    return c.json<ApiResponse>({ ok: false, error: "Forbidden" }, 403);
  }
  return platformAuthMiddleware()(c, next);
};

tenantRoutes.post("/", requirePlatformTenantCreate, async (c) => {
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

  if (!isNonEmptyString(body.name)) {
    return c.json<ApiResponse>(
      { ok: false, error: "name is required and must be a non-empty string" },
      400,
    );
  }

  if (typeof body.apiKeyHash !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "apiKeyHash is required" }, 400);
  }

  const existingTenant = await findTenant(body.id);
  if (existingTenant) {
    return c.json<ApiResponse>({ ok: false, error: "Tenant already exists" }, 400);
  }

  const apiKeyHash =
    body.apiKeyHash && !body.apiKeyHash.match(/^[0-9a-f]{64}$/)
      ? hashApiKey(body.apiKeyHash)
      : body.apiKeyHash;

  const [tenant] = await db
    .insert(tenants)
    .values({
      id: body.id,
      name: body.name,
      apiKeyHash,
    })
    .returning();

  tenantConfigs.set(body.id, {
    id: body.id,
    name: body.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies,
  });

  trackAuditEvent({
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

  return c.json<ApiResponse<TenantResponse>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

tenantRoutes.get("/:id", requireTenantId, async (c) => {
  setNoStoreHeaders(c);
  const tenant = c.get("tenant");
  return c.json<ApiResponse<TenantResponse>>({
    ok: true,
    data: getTenantPayloadForRequest(c, tenant),
  });
});

tenantRoutes.put("/:id/webhook", requireTenantId, async (c) => {
  setNoStoreHeaders(c);
  const mfaResponse = await requireRecentTenantAdminMfa(c, "Legacy tenant webhook updates");
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

  if (body.webhookUrl !== undefined && typeof body.webhookUrl !== "string") {
    return c.json<ApiResponse>({ ok: false, error: "webhookUrl must be a string" }, 400);
  }

  if (body.defaultPolicies !== undefined && !Array.isArray(body.defaultPolicies)) {
    return c.json<ApiResponse>({ ok: false, error: "defaultPolicies must be an array" }, 400);
  }

  const updatedConfig: TenantConfig = {
    ...tenantConfig,
    id: tenant.id,
    name: tenant.name,
    webhookUrl: body.webhookUrl,
    defaultPolicies: body.defaultPolicies ?? tenantConfig.defaultPolicies,
  };

  tenantConfigs.set(tenant.id, updatedConfig);
  if (body.webhookUrl !== undefined && body.webhookUrl) {
    await upsertLegacyTenantWebhook(tenant.id, body.webhookUrl);
  }

  trackAuditEvent({
    tenantId: tenant.id,
    actorType: "user",
    actorId: tenant.id,
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

  return c.json<ApiResponse<TenantConfig>>({
    ok: true,
    data: updatedConfig,
  });
});

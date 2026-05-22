/**
 * Tenant management routes.
 *
 * Mount: app.route("/tenants", tenantRoutes)
 */

import { hashApiKey } from "@stwd/auth";
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
  type Tenant,
  type TenantConfig,
  tenantAuth,
  tenantConfigs,
  tenants,
} from "../services/context";

export const tenantRoutes = new Hono<{ Variables: AppVariables }>();

// Per-route auth that pins the JWT's tenantId to the URL :id path param.
// Applied directly on handlers below so the "public discovery" route in
// tenantConfigRoutes (mounted before this router) doesn't need a magic-string
// skip in a catch-all middleware.
export const requireTenantId = (c: Context<{ Variables: AppVariables }>, next: Next) =>
  tenantAuth(c, next, { requireTenantMatch: c.req.param("id") });

tenantRoutes.post("/", async (c) => {
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

  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

tenantRoutes.get("/:id", requireTenantId, async (c) => {
  const tenant = c.get("tenant");
  return c.json<ApiResponse<Tenant & TenantConfig>>({
    ok: true,
    data: getTenantPayload(tenant),
  });
});

tenantRoutes.put("/:id/webhook", requireTenantId, async (c) => {
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

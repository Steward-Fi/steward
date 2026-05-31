/**
 * Webhook configuration and delivery tracking routes.
 *
 * Mount: app.route("/webhooks", webhookRoutes)
 */

import { randomBytes } from "node:crypto";
import { encryptWebhookSecret } from "@stwd/webhooks";
import { and, count, desc, eq, or, sql } from "drizzle-orm";
import { Hono } from "hono";
import { writeAuditEvent } from "../services/audit";
import {
  type ApiResponse,
  type AppVariables,
  db,
  isNonEmptyString,
  requireTenantLevel,
  safeJsonParse,
  webhookConfigs,
  webhookDeliveries,
} from "../services/context";
import {
  acceptsConfiguredWebhookEvent,
  CONFIGURED_WEBHOOK_EVENT_TYPES,
  type ConfiguredWebhookEventType,
} from "../services/webhook-events";
import { validateWebhookUrl } from "../services/webhook-url";

export const webhookRoutes = new Hono<{ Variables: AppVariables }>();

// Valid webhook event types
const VALID_EVENTS = CONFIGURED_WEBHOOK_EVENT_TYPES;
const MAX_WEBHOOKS_PER_TENANT = 50;

class WebhookConfigError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404 | 409,
  ) {
    super(message);
  }
}

function generateSecret(): string {
  return `whsec_${randomBytes(32).toString("hex")}`;
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

function requireRecentTenantAdminMfa(c: Parameters<typeof requireTenantLevel>[0], reason: string) {
  if (hasRecentSessionMfa(c)) return null;
  return c.json<ApiResponse>(
    { ok: false, error: `${reason} requires recent MFA verification` },
    403,
  );
}

function currentWebhookAcceptsDelivery(
  events: string[],
  eventType: string,
): eventType is ConfiguredWebhookEventType {
  return acceptsConfiguredWebhookEvent(events, eventType as ConfiguredWebhookEventType);
}

function redactWebhookSecret<T extends { secret?: unknown }>(webhook: T): Omit<T, "secret"> {
  const { secret: _secret, ...safe } = webhook;
  return safe;
}

function redactDelivery(row: {
  id: string;
  eventType: string;
  status: string;
  attempts: number;
  maxAttempts: number;
  nextRetryAt: Date | string | null;
  lastError: string | null;
  createdAt: Date | string;
  deliveredAt: Date | string | null;
}) {
  return {
    id: row.id,
    eventType: row.eventType,
    status: row.status,
    attempts: row.attempts,
    maxAttempts: row.maxAttempts,
    nextRetryAt: row.nextRetryAt,
    hasError: Boolean(row.lastError),
    createdAt: row.createdAt,
    deliveredAt: row.deliveredAt,
  };
}

async function lockWebhookConfigTenant(
  tx: Parameters<Parameters<typeof db.transaction>[0]>[0],
  tenantId: string,
): Promise<void> {
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended(${`webhook_config_${tenantId}`}, 0))`,
  );
}

function validateWebhookRetryConfig(body: {
  maxRetries?: unknown;
  retryBackoffMs?: unknown;
}): string | null {
  const { maxRetries, retryBackoffMs } = body;
  if (
    maxRetries !== undefined &&
    (typeof maxRetries !== "number" ||
      !Number.isInteger(maxRetries) ||
      maxRetries < 0 ||
      maxRetries > 10)
  ) {
    return "maxRetries must be an integer from 0-10";
  }

  if (
    retryBackoffMs !== undefined &&
    (typeof retryBackoffMs !== "number" ||
      !Number.isInteger(retryBackoffMs) ||
      retryBackoffMs < 1000 ||
      retryBackoffMs > 3600000)
  ) {
    return "retryBackoffMs must be an integer from 1000-3600000";
  }

  return null;
}

function parsePaginationParam(
  value: string | undefined,
  defaultValue: number,
  min: number,
  max: number,
): number | null {
  if (value === undefined) return defaultValue;
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) return null;
  return parsed;
}

// ─── Register webhook ─────────────────────────────────────────────────────────

webhookRoutes.post("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook creation requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook creation");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const body = await safeJsonParse<{
    url: string;
    events?: string[];
    description?: string;
    maxRetries?: number;
    retryBackoffMs?: number;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  const urlError = isNonEmptyString(body.url) ? validateWebhookUrl(body.url) : "url is required";
  if (urlError) {
    return c.json<ApiResponse>({ ok: false, error: urlError }, 400);
  }

  // Validate events if provided
  if (body.events !== undefined) {
    if (!Array.isArray(body.events)) {
      return c.json<ApiResponse>({ ok: false, error: "events must be an array" }, 400);
    }
    const invalidEvents = body.events.filter(
      (e) => !(VALID_EVENTS as readonly string[]).includes(e),
    );
    if (invalidEvents.length > 0) {
      return c.json<ApiResponse>(
        {
          ok: false,
          error: `Invalid events: ${invalidEvents.join(", ")}. Valid: ${VALID_EVENTS.join(", ")}`,
        },
        400,
      );
    }
  }

  const retryConfigError = validateWebhookRetryConfig(body);
  if (retryConfigError) {
    return c.json<ApiResponse>({ ok: false, error: retryConfigError }, 400);
  }
  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? null,
    action: "webhook.create.authorized",
    resourceType: "webhook",
    resourceId: null,
    metadata: {
      url: body.url,
      events: body.events || [...VALID_EVENTS],
      enabled: true,
      maxRetries: body.maxRetries ?? 5,
      retryBackoffMs: body.retryBackoffMs ?? 60000,
    },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  let webhook: typeof webhookConfigs.$inferSelect;
  try {
    webhook = await db.transaction(async (tx) => {
      await lockWebhookConfigTenant(tx, tenantId);

      const [{ count: existingCount } = { count: 0 }] = await tx
        .select({ count: count() })
        .from(webhookConfigs)
        .where(eq(webhookConfigs.tenantId, tenantId));
      if (Number(existingCount) >= MAX_WEBHOOKS_PER_TENANT) {
        throw new WebhookConfigError(
          `A tenant can register at most ${MAX_WEBHOOKS_PER_TENANT} webhooks`,
          400,
        );
      }

      const [existingUrl] = await tx
        .select({ id: webhookConfigs.id })
        .from(webhookConfigs)
        .where(and(eq(webhookConfigs.tenantId, tenantId), eq(webhookConfigs.url, body.url)));
      if (existingUrl) {
        throw new WebhookConfigError("Webhook URL already registered", 409);
      }

      const rawSecret = generateSecret();
      const [created] = await tx
        .insert(webhookConfigs)
        .values({
          tenantId,
          url: body.url,
          secret: encryptWebhookSecret(rawSecret),
          events: body.events || [...VALID_EVENTS],
          description: body.description,
          enabled: false,
          maxRetries: body.maxRetries ?? 5,
          retryBackoffMs: body.retryBackoffMs ?? 60000,
        })
        .returning();

      return { ...created, secret: rawSecret };
    });
  } catch (err) {
    if (err instanceof WebhookConfigError) {
      return c.json<ApiResponse>({ ok: false, error: err.message }, err.status);
    }
    throw err;
  }
  const oneTimeSecret = webhook.secret;
  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "webhook.create",
      resourceType: "webhook",
      resourceId: webhook.id,
      metadata: {
        url: webhook.url,
        events: webhook.events,
        enabled: true,
        maxRetries: webhook.maxRetries,
        retryBackoffMs: webhook.retryBackoffMs,
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (err) {
    await db
      .delete(webhookConfigs)
      .where(and(eq(webhookConfigs.id, webhook.id), eq(webhookConfigs.tenantId, tenantId)));
    throw err;
  }
  const [enabledWebhook] = await db
    .update(webhookConfigs)
    .set({ enabled: true, updatedAt: new Date() })
    .where(and(eq(webhookConfigs.id, webhook.id), eq(webhookConfigs.tenantId, tenantId)))
    .returning();
  webhook = enabledWebhook ?? webhook;

  return c.json<ApiResponse>(
    {
      ok: true,
      data: { ...redactWebhookSecret(webhook), secret: oneTimeSecret },
    },
    201,
  );
});

// ─── List webhooks ────────────────────────────────────────────────────────────

webhookRoutes.get("/", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook configuration access requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook configuration access");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");

  const webhooks = await db
    .select({
      id: webhookConfigs.id,
      tenantId: webhookConfigs.tenantId,
      url: webhookConfigs.url,
      events: webhookConfigs.events,
      enabled: webhookConfigs.enabled,
      maxRetries: webhookConfigs.maxRetries,
      retryBackoffMs: webhookConfigs.retryBackoffMs,
      description: webhookConfigs.description,
      createdAt: webhookConfigs.createdAt,
      updatedAt: webhookConfigs.updatedAt,
      // Omit secret from list view
    })
    .from(webhookConfigs)
    .where(eq(webhookConfigs.tenantId, tenantId))
    .orderBy(desc(webhookConfigs.createdAt));

  return c.json<ApiResponse>({ ok: true, data: webhooks });
});

// ─── Update webhook ───────────────────────────────────────────────────────────

webhookRoutes.put("/:id", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook updates require owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook updates");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const webhookId = c.req.param("id");

  const body = await safeJsonParse<{
    url?: string;
    events?: string[];
    enabled?: boolean;
    description?: string;
    maxRetries?: number;
    retryBackoffMs?: number;
  }>(c);

  if (!body) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid JSON in request body" }, 400);
  }

  if (body.url !== undefined) {
    const urlError = isNonEmptyString(body.url) ? validateWebhookUrl(body.url) : "url is required";
    if (urlError) {
      return c.json<ApiResponse>({ ok: false, error: urlError }, 400);
    }
  }

  if (body.events !== undefined) {
    if (!Array.isArray(body.events)) {
      return c.json<ApiResponse>({ ok: false, error: "events must be an array" }, 400);
    }
    const invalidEvents = body.events.filter(
      (e) => !(VALID_EVENTS as readonly string[]).includes(e),
    );
    if (invalidEvents.length > 0) {
      return c.json<ApiResponse>(
        { ok: false, error: `Invalid events: ${invalidEvents.join(", ")}` },
        400,
      );
    }
  }

  const retryConfigError = validateWebhookRetryConfig(body);
  if (retryConfigError) {
    return c.json<ApiResponse>({ ok: false, error: retryConfigError }, 400);
  }

  const updates: Record<string, unknown> = {};
  if (body.url !== undefined) updates.url = body.url;
  if (body.events !== undefined) updates.events = body.events;
  if (body.enabled !== undefined) updates.enabled = body.enabled;
  if (body.description !== undefined) updates.description = body.description;
  if (body.maxRetries !== undefined) updates.maxRetries = body.maxRetries;
  if (body.retryBackoffMs !== undefined) updates.retryBackoffMs = body.retryBackoffMs;
  updates.updatedAt = new Date();

  let existing: typeof webhookConfigs.$inferSelect;
  let updated: typeof webhookConfigs.$inferSelect;
  try {
    const result = await db.transaction(async (tx) => {
      await lockWebhookConfigTenant(tx, tenantId);

      const [current] = await tx
        .select()
        .from(webhookConfigs)
        .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)));

      if (!current) {
        throw new WebhookConfigError("Webhook not found", 404);
      }

      if (body.url !== undefined) {
        const [existingUrl] = await tx
          .select({ id: webhookConfigs.id })
          .from(webhookConfigs)
          .where(and(eq(webhookConfigs.tenantId, tenantId), eq(webhookConfigs.url, body.url)));
        if (existingUrl && existingUrl.id !== webhookId) {
          throw new WebhookConfigError("Webhook URL already registered", 409);
        }
      }

      await writeAuditEvent({
        tenantId,
        actorType: "user",
        actorId: c.get("userId") ?? c.get("authType") ?? null,
        action: "webhook.update.authorized",
        resourceType: "webhook",
        resourceId: webhookId,
        metadata: {
          before: redactWebhookSecret(current),
          updates,
        },
        ipAddress: c.req.header("x-forwarded-for") ?? null,
        userAgent: c.req.header("user-agent") ?? null,
        requestId: c.get("requestId") ?? null,
      });

      const [next] = await tx
        .update(webhookConfigs)
        .set(updates)
        .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)))
        .returning();

      return { existing: current, updated: next };
    });
    existing = result.existing;
    updated = result.updated;
  } catch (err) {
    if (err instanceof WebhookConfigError) {
      return c.json<ApiResponse>({ ok: false, error: err.message }, err.status);
    }
    throw err;
  }

  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "webhook.update",
      resourceType: "webhook",
      resourceId: webhookId,
      metadata: {
        before: redactWebhookSecret(existing),
        after: redactWebhookSecret(updated),
      },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (err) {
    await db
      .update(webhookConfigs)
      .set({
        url: existing.url,
        secret: existing.secret,
        events: existing.events,
        enabled: existing.enabled,
        maxRetries: existing.maxRetries,
        retryBackoffMs: existing.retryBackoffMs,
        description: existing.description,
        createdAt: existing.createdAt,
        updatedAt: existing.updatedAt,
      })
      .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)));
    throw err;
  }

  return c.json<ApiResponse>({ ok: true, data: redactWebhookSecret(updated) });
});

// ─── Delete webhook ───────────────────────────────────────────────────────────

webhookRoutes.delete("/:id", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook deletion requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook deletion");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const webhookId = c.req.param("id");

  const [existing] = await db
    .select()
    .from(webhookConfigs)
    .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)));

  if (!existing) {
    return c.json<ApiResponse>({ ok: false, error: "Webhook not found" }, 404);
  }

  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? null,
    action: "webhook.delete.authorized",
    resourceType: "webhook",
    resourceId: webhookId,
    metadata: { deleted: redactWebhookSecret(existing) },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  const [deleted] = await db
    .delete(webhookConfigs)
    .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)))
    .returning();

  if (!deleted) return c.json<ApiResponse>({ ok: false, error: "Webhook not found" }, 404);
  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "webhook.delete",
      resourceType: "webhook",
      resourceId: webhookId,
      metadata: { deleted: redactWebhookSecret(deleted) },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (err) {
    await db.insert(webhookConfigs).values({
      id: deleted.id,
      tenantId: deleted.tenantId,
      url: deleted.url,
      secret: deleted.secret,
      events: deleted.events,
      enabled: deleted.enabled,
      maxRetries: deleted.maxRetries,
      retryBackoffMs: deleted.retryBackoffMs,
      description: deleted.description,
      createdAt: deleted.createdAt,
      updatedAt: deleted.updatedAt,
    });
    throw err;
  }

  return c.json<ApiResponse>({ ok: true, data: { deleted: true } });
});

// ─── Delivery history ─────────────────────────────────────────────────────────

webhookRoutes.get("/:id/deliveries", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook delivery history requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook delivery history");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const webhookId = c.req.param("id");

  // Verify webhook belongs to tenant
  const [webhook] = await db
    .select()
    .from(webhookConfigs)
    .where(and(eq(webhookConfigs.id, webhookId), eq(webhookConfigs.tenantId, tenantId)));

  const limit = parsePaginationParam(c.req.query("limit"), 50, 1, 200);
  const offset = parsePaginationParam(c.req.query("offset"), 0, 0, 100000);
  if (limit === null || offset === null) {
    return c.json<ApiResponse>({ ok: false, error: "Invalid pagination parameters" }, 400);
  }

  const webhookDeliveryFilter = webhook
    ? or(
        eq(webhookDeliveries.webhookConfigId, webhook.id),
        sql`${webhookDeliveries.payload}->>'webhookConfigId' = ${webhookId}`,
      )
    : sql`${webhookDeliveries.payload}->>'webhookConfigId' = ${webhookId}`;

  if (!webhook) {
    const [deliveryCount] = await db
      .select({ count: count() })
      .from(webhookDeliveries)
      .where(and(eq(webhookDeliveries.tenantId, tenantId), webhookDeliveryFilter));

    if (!deliveryCount || deliveryCount.count === 0) {
      return c.json<ApiResponse>({ ok: false, error: "Webhook not found" }, 404);
    }
  }

  // Filter deliveries by tenant and webhook URL
  const deliveries = await db
    .select({
      id: webhookDeliveries.id,
      eventType: webhookDeliveries.eventType,
      status: webhookDeliveries.status,
      attempts: webhookDeliveries.attempts,
      maxAttempts: webhookDeliveries.maxAttempts,
      nextRetryAt: webhookDeliveries.nextRetryAt,
      lastError: webhookDeliveries.lastError,
      createdAt: webhookDeliveries.createdAt,
      deliveredAt: webhookDeliveries.deliveredAt,
    })
    .from(webhookDeliveries)
    .where(and(eq(webhookDeliveries.tenantId, tenantId), webhookDeliveryFilter))
    .orderBy(desc(webhookDeliveries.createdAt))
    .limit(limit)
    .offset(offset);

  return c.json<ApiResponse>({ ok: true, data: deliveries.map(redactDelivery) });
});

// ─── Retry delivery ───────────────────────────────────────────────────────────

webhookRoutes.post("/deliveries/:id/retry", async (c) => {
  if (!requireTenantAdminSession(c)) {
    return c.json<ApiResponse>(
      { ok: false, error: "Webhook delivery retry requires owner or admin session" },
      403,
    );
  }
  const mfaResponse = requireRecentTenantAdminMfa(c, "Webhook delivery retry");
  if (mfaResponse) return mfaResponse;

  const tenantId = c.get("tenantId");
  const deliveryId = c.req.param("id");

  const [delivery] = await db
    .select()
    .from(webhookDeliveries)
    .where(and(eq(webhookDeliveries.id, deliveryId), eq(webhookDeliveries.tenantId, tenantId)));

  if (!delivery) {
    return c.json<ApiResponse>({ ok: false, error: "Delivery not found" }, 404);
  }

  if (delivery.status === "delivered") {
    return c.json<ApiResponse>({ ok: false, error: "Delivery already succeeded" }, 400);
  }
  if (
    delivery.status === "processing" &&
    delivery.nextRetryAt &&
    delivery.nextRetryAt > new Date()
  ) {
    return c.json<ApiResponse>({ ok: false, error: "Delivery is currently in flight" }, 409);
  }
  if (delivery.attempts >= delivery.maxAttempts) {
    return c.json<ApiResponse>(
      { ok: false, error: "Delivery retry budget has been exhausted" },
      409,
    );
  }

  if (!delivery.webhookConfigId) {
    return c.json<ApiResponse>(
      { ok: false, error: "Delivery cannot be retried because its original webhook is unknown" },
      409,
    );
  }

  const [activeWebhook] = await db
    .select({ id: webhookConfigs.id, url: webhookConfigs.url, events: webhookConfigs.events })
    .from(webhookConfigs)
    .where(
      and(
        eq(webhookConfigs.tenantId, tenantId),
        eq(webhookConfigs.id, delivery.webhookConfigId),
        eq(webhookConfigs.enabled, true),
      ),
    );

  if (!activeWebhook) {
    return c.json<ApiResponse>(
      { ok: false, error: "Delivery cannot be retried because the webhook is disabled or deleted" },
      409,
    );
  }
  if (activeWebhook.url !== delivery.url) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Delivery cannot be retried because the webhook URL has changed",
      },
      409,
    );
  }
  if (!currentWebhookAcceptsDelivery(activeWebhook.events, delivery.eventType)) {
    return c.json<ApiResponse>(
      {
        ok: false,
        error: "Delivery cannot be retried because the webhook no longer subscribes to this event",
      },
      409,
    );
  }

  await writeAuditEvent({
    tenantId,
    actorType: "user",
    actorId: c.get("userId") ?? c.get("authType") ?? null,
    action: "webhook_delivery.retry.authorized",
    resourceType: "webhook_delivery",
    resourceId: deliveryId,
    metadata: { webhookUrl: delivery.url, previousStatus: delivery.status },
    ipAddress: c.req.header("x-forwarded-for") ?? null,
    userAgent: c.req.header("user-agent") ?? null,
    requestId: c.get("requestId") ?? null,
  });

  // Re-queue for an immediate manual retry without resetting the delivery's
  // attempt budget. Resetting attempts would let repeated manual retries bypass
  // the configured maxAttempts cap.
  const manualRetryAt = new Date();
  const [updated] = await db
    .update(webhookDeliveries)
    .set({
      status: "pending",
      nextRetryAt: manualRetryAt,
      lastError: null,
    })
    .where(
      and(
        eq(webhookDeliveries.id, deliveryId),
        eq(webhookDeliveries.tenantId, tenantId),
        sql`${webhookDeliveries.status} <> 'delivered'`,
        sql`${webhookDeliveries.attempts} < ${webhookDeliveries.maxAttempts}`,
        sql`not (${webhookDeliveries.status} = 'processing' and ${webhookDeliveries.nextRetryAt} > ${manualRetryAt})`,
      ),
    )
    .returning();
  if (!updated) {
    return c.json<ApiResponse>({ ok: false, error: "Delivery is no longer retryable" }, 409);
  }
  try {
    await writeAuditEvent({
      tenantId,
      actorType: "user",
      actorId: c.get("userId") ?? c.get("authType") ?? null,
      action: "webhook_delivery.retry",
      resourceType: "webhook_delivery",
      resourceId: deliveryId,
      metadata: { webhookUrl: delivery.url, previousStatus: delivery.status },
      ipAddress: c.req.header("x-forwarded-for") ?? null,
      userAgent: c.req.header("user-agent") ?? null,
      requestId: c.get("requestId") ?? null,
    });
  } catch (err) {
    await db
      .update(webhookDeliveries)
      .set({
        status: delivery.status,
        nextRetryAt: delivery.nextRetryAt,
        lastError: delivery.lastError,
      })
      .where(and(eq(webhookDeliveries.id, deliveryId), eq(webhookDeliveries.tenantId, tenantId)));
    throw err;
  }

  return c.json<ApiResponse>({ ok: true, data: redactDelivery(updated) });
});

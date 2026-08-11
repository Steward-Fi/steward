import { randomUUID } from "node:crypto";
import { and, eq, webhookConfigs, webhookDeliveries } from "@stwd/db";
import type { WebhookEvent } from "@stwd/shared";
import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  isEncryptedWebhookSecret,
  WebhookDispatcher,
} from "@stwd/webhooks";
import { db, tenantConfigs } from "./context";
import {
  acceptsConfiguredWebhookEvent,
  type ConfiguredWebhookEventType,
  type DispatchableWebhookEventType,
  toConfiguredWebhookEventType,
  webhookEventRegistry,
} from "./webhook-events";
import { redactWebhookSecrets } from "./webhook-redaction";

const INLINE_DELIVERY_VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000;

export { redactWebhookSecrets } from "./webhook-redaction";

export function dispatchWebhook(
  tenantId: string,
  agentId: string,
  type: DispatchableWebhookEventType,
  data: Record<string, unknown>,
): void {
  const configuredType = toConfiguredWebhookEventType(type);
  // EMISSION-PATH WIDENING (Phase 2b): a plugin-declared event is one that is NOT
  // a core configured/alias type but IS present in the runtime
  // WebhookEventRegistry (core ∪ plugin-declared) because the plugin host merged
  // it in. We thread the raw plugin event name into the configured fan-out so a
  // tenant can subscribe to a plugin event specifically (events: ["plugin.evt"]).
  // We do NOT drop unregistered types here: the legacy tenant-config webhook is a
  // deliberate catch-all escape hatch that fires for EVERY event type (it has
  // always done so), so dropping would change long-standing behavior. The
  // configured fan-out only ever matches a plugin event when it is registry-valid
  // AND a config explicitly lists it, so an arbitrary unregistered string can
  // never masquerade as a configured event.
  const isPluginEvent = configuredType === null && webhookEventRegistry.has(type);
  const redactedData = redactWebhookSecrets(data) as Record<string, unknown>;
  // `type` has passed the emission gate above (it is a configured/aliasable core
  // event OR a plugin event registered in the runtime registry). The widened
  // DispatchableWebhookEventType carries the `(string & {})` arm for plugin
  // events; cast to the WebhookEvent field type now that the name is validated.
  const eventType = (configuredType ?? type) as WebhookEvent["type"];
  const event: WebhookEvent = {
    type: eventType,
    tenantId,
    agentId,
    data: redactedData,
    timestamp: new Date(),
  };
  void dispatchConfiguredWebhooks(event, configuredType, isPluginEvent ? type : null).catch(
    (error) => {
      console.error("[webhooks] Failed to dispatch configured webhooks:", error);
    },
  );

  // Legacy tenant-config single webhook URL. Tenants can still set a webhookUrl
  // via the tenants route (tenants.ts), so this fan-out must remain until that
  // path is fully migrated to persisted webhook configs. It fires for every
  // event regardless of configured-type mapping, using the raw event type.
  // Payload is redacted on the same terms as configured webhooks.
  const tenantConfigWebhookUrl = tenantConfigs.get(tenantId)?.webhookUrl;
  if (tenantConfigWebhookUrl) {
    const tenantConfigEvent: WebhookEvent = {
      type: type as WebhookEvent["type"],
      tenantId,
      agentId,
      data: redactedData,
      timestamp: new Date(),
    };
    const dispatcher = new WebhookDispatcher();
    dispatcher.dispatch(tenantConfigEvent, tenantConfigWebhookUrl).catch((error) => {
      console.error("[webhooks] Failed to dispatch tenant config webhook:", error);
    });
  }
}

export async function dispatchTestWebhook(config: {
  id: string;
  tenantId: string;
  url: string;
  secret: string;
  events: string[];
  actorId?: string | null;
}): Promise<typeof webhookDeliveries.$inferSelect> {
  const event: WebhookEvent = {
    type: "webhook.test",
    tenantId: config.tenantId,
    agentId: "dashboard",
    data: {
      test: true,
      webhookConfigId: config.id,
      actorId: config.actorId ?? null,
    },
    timestamp: new Date(),
  };

  return dispatchConfiguredWebhook(event, {
    ...config,
    maxRetries: 0,
    retryBackoffMs: 0,
    visibilityTimeoutMs: 0,
  });
}

export async function dispatchReplayWebhook(config: {
  id: string;
  tenantId: string;
  url: string;
  secret: string;
  events: string[];
  maxRetries: number;
  retryBackoffMs: number;
  replayedFromDeliveryId: string;
  originalPayload: Record<string, unknown>;
  originalEventType: string;
  originalAgentId?: string | null;
  originalCreatedAt: Date | string;
}): Promise<typeof webhookDeliveries.$inferSelect> {
  const originalTimestamp =
    typeof config.originalPayload.timestamp === "string" ||
    config.originalPayload.timestamp instanceof Date
      ? new Date(config.originalPayload.timestamp)
      : new Date(config.originalCreatedAt);
  const event: WebhookEvent = {
    type: config.originalEventType as WebhookEvent["type"],
    tenantId: config.tenantId,
    agentId:
      typeof config.originalPayload.agentId === "string"
        ? config.originalPayload.agentId
        : (config.originalAgentId ?? undefined),
    data:
      config.originalPayload.data && typeof config.originalPayload.data === "object"
        ? (redactWebhookSecrets(config.originalPayload.data) as Record<string, unknown>)
        : {},
    timestamp: Number.isNaN(originalTimestamp.getTime())
      ? new Date(config.originalCreatedAt)
      : originalTimestamp,
  };

  return dispatchConfiguredWebhook(event, {
    ...config,
    replayedFromDeliveryId: config.replayedFromDeliveryId,
  });
}

async function dispatchConfiguredWebhooks(
  event: WebhookEvent,
  configuredType: ConfiguredWebhookEventType | null,
  pluginEventType: string | null = null,
): Promise<void> {
  const configs = await db
    .select()
    .from(webhookConfigs)
    .where(and(eq(webhookConfigs.tenantId, event.tenantId), eq(webhookConfigs.enabled, true)));

  await Promise.all(
    configs
      .filter((config) => {
        // Plugin-declared event (registry-valid, not a core configured type): a
        // config matches when it explicitly lists the event OR is a catch-all
        // (no events filter). It can never match by being a core configured type.
        if (pluginEventType) {
          return config.events.length === 0 || config.events.includes(pluginEventType);
        }
        return configuredType
          ? acceptsConfiguredWebhookEvent(config.events, configuredType)
          : config.events.length === 0;
      })
      .map((config) =>
        dispatchConfiguredWebhook(event, {
          id: config.id,
          url: config.url,
          secret: config.secret,
          events: config.events,
          maxRetries: config.maxRetries,
          retryBackoffMs: config.retryBackoffMs,
        }),
      ),
  );
}

async function dispatchConfiguredWebhook(
  event: WebhookEvent,
  config: {
    id: string;
    url: string;
    secret: string;
    events: string[];
    maxRetries: number;
    retryBackoffMs: number;
    visibilityTimeoutMs?: number;
    replayedFromDeliveryId?: string | null;
  },
): Promise<typeof webhookDeliveries.$inferSelect> {
  const signingSecret = decryptWebhookSecret(config.secret);
  const encryptedSecret = isEncryptedWebhookSecret(config.secret)
    ? config.secret
    : encryptWebhookSecret(signingSecret);
  if (encryptedSecret !== config.secret) {
    await db
      .update(webhookConfigs)
      .set({ secret: encryptedSecret, updatedAt: new Date() })
      .where(and(eq(webhookConfigs.id, config.id), eq(webhookConfigs.secret, config.secret)));
  }
  const deliveryId = randomUUID();
  const signedAt = Math.floor(Date.now() / 1000);
  const eventWithDelivery: WebhookEvent & {
    deliveryId: string;
    webhookConfigId: string;
    signedAt: number;
  } = {
    ...event,
    deliveryId,
    webhookConfigId: config.id,
    signedAt,
    ...(config.replayedFromDeliveryId
      ? { replayedFromDeliveryId: config.replayedFromDeliveryId }
      : {}),
  };
  const [delivery] = await db
    .insert(webhookDeliveries)
    .values({
      id: deliveryId,
      tenantId: event.tenantId,
      webhookConfigId: config.id,
      agentId: event.agentId,
      eventType: event.type,
      replayedFromDeliveryId: config.replayedFromDeliveryId ?? null,
      payload: eventWithDelivery as unknown as Record<string, unknown>,
      url: config.url,
      secret: encryptedSecret,
      events: config.events,
      status: "processing",
      attempts: 0,
      maxAttempts: config.maxRetries + 1,
      nextRetryAt:
        config.visibilityTimeoutMs === 0
          ? null
          : new Date(
              Date.now() + (config.visibilityTimeoutMs ?? INLINE_DELIVERY_VISIBILITY_TIMEOUT_MS),
            ),
    })
    .returning();

  if (!delivery) {
    throw new Error("Failed to create webhook delivery record");
  }

  const dispatcher = new WebhookDispatcher({
    maxRetries: 0,
    retryDelayMs: 0,
  });
  const result = await dispatcher.dispatch(eventWithDelivery, { ...config, secret: signingSecret });
  const retryable = !result.success && config.maxRetries > 0;

  const [updated] = await db
    .update(webhookDeliveries)
    .set({
      status: result.success ? "delivered" : retryable ? "pending" : "failed",
      attempts: result.attempts,
      deliveredAt: result.deliveredAt ?? null,
      lastError: result.error ?? null,
      nextRetryAt: retryable ? new Date(Date.now() + config.retryBackoffMs) : null,
      payload: eventWithDelivery as unknown as Record<string, unknown>,
    })
    .where(eq(webhookDeliveries.id, delivery.id))
    .returning();

  return updated ?? delivery;
}

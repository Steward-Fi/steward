import { and, eq, webhookConfigs, webhookDeliveries } from "@stwd/db";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "@stwd/webhooks";
import { db, tenantConfigs } from "./context";
import {
  acceptsConfiguredWebhookEvent,
  type ConfiguredWebhookEventType,
  type DispatchableWebhookEventType,
  toConfiguredWebhookEventType,
} from "./webhook-events";

export function dispatchWebhook(
  tenantId: string,
  agentId: string,
  type: DispatchableWebhookEventType,
  data: Record<string, unknown>,
): void {
  const configuredType = toConfiguredWebhookEventType(type);
  if (configuredType) {
    const event: WebhookEvent = {
      type: configuredType,
      tenantId,
      agentId,
      data,
      timestamp: new Date(),
    };
    void dispatchConfiguredWebhooks(event).catch((error) => {
      console.error("[webhooks] Failed to dispatch configured webhooks:", error);
    });
  }

  const tenantConfigWebhookUrl = tenantConfigs.get(tenantId)?.webhookUrl;
  if (tenantConfigWebhookUrl) {
    const tenantConfigEvent: WebhookEvent = {
      type,
      tenantId,
      agentId,
      data,
      timestamp: new Date(),
    };
    const dispatcher = new WebhookDispatcher();
    dispatcher.dispatch(tenantConfigEvent, tenantConfigWebhookUrl).catch((error) => {
      console.error("[webhooks] Failed to dispatch tenant config webhook:", error);
    });
  }
}

async function dispatchConfiguredWebhooks(event: WebhookEvent): Promise<void> {
  const configs = await db
    .select()
    .from(webhookConfigs)
    .where(and(eq(webhookConfigs.tenantId, event.tenantId), eq(webhookConfigs.enabled, true)));

  const eventType = event.type as ConfiguredWebhookEventType;
  await Promise.all(
    configs
      .filter((config) => acceptsConfiguredWebhookEvent(config.events, eventType))
      .map((config) =>
        dispatchConfiguredWebhook(event, {
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
    url: string;
    secret: string;
    events: string[];
    maxRetries: number;
    retryBackoffMs: number;
  },
): Promise<void> {
  const [delivery] = await db
    .insert(webhookDeliveries)
    .values({
      tenantId: event.tenantId,
      agentId: event.agentId,
      eventType: event.type,
      payload: event as unknown as Record<string, unknown>,
      url: config.url,
      status: "pending",
      attempts: 0,
      maxAttempts: config.maxRetries + 1,
      nextRetryAt: new Date(),
    })
    .returning();

  if (!delivery) {
    throw new Error("Failed to create webhook delivery record");
  }

  const dispatcher = new WebhookDispatcher({
    maxRetries: config.maxRetries,
    retryDelayMs: config.retryBackoffMs,
  });
  const result = await dispatcher.dispatch(event, config);

  await db
    .update(webhookDeliveries)
    .set({
      status: result.success ? "delivered" : "failed",
      attempts: result.attempts,
      deliveredAt: result.deliveredAt ?? null,
      lastError: result.error ?? null,
      nextRetryAt: null,
    })
    .where(eq(webhookDeliveries.id, delivery.id));
}

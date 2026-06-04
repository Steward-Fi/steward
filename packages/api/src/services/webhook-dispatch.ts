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
} from "./webhook-events";

const INLINE_DELIVERY_VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000;
const SENSITIVE_WEBHOOK_KEYS = new Set([
  "accesstoken",
  "claimtoken",
  "claimtokenhash",
  "mnemonic",
  "password",
  "privatekey",
  "recoveryphrase",
  "refreshtoken",
  "refresh_token",
  "secret",
  "seedphrase",
]);

export function redactWebhookSecrets<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => redactWebhookSecrets(item)) as T;
  }
  if (!value || typeof value !== "object") return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, nestedValue] of Object.entries(value as Record<string, unknown>)) {
    redacted[key] = SENSITIVE_WEBHOOK_KEYS.has(key.toLowerCase())
      ? "[REDACTED]"
      : redactWebhookSecrets(nestedValue);
  }
  return redacted as T;
}

export function dispatchWebhook(
  tenantId: string,
  agentId: string,
  type: DispatchableWebhookEventType,
  data: Record<string, unknown>,
): void {
  const configuredType = toConfiguredWebhookEventType(type);
  const event: WebhookEvent = {
    type: configuredType ?? type,
    tenantId,
    agentId,
    data: redactWebhookSecrets(data),
    timestamp: new Date(),
  };
  void dispatchConfiguredWebhooks(event, configuredType).catch((error) => {
    console.error("[webhooks] Failed to dispatch configured webhooks:", error);
  });

  // Legacy tenant-config single webhook URL. Tenants can still set a webhookUrl
  // via the tenants route (tenants.ts), so this fan-out must remain until that
  // path is fully migrated to persisted webhook configs. It fires for every
  // event regardless of configured-type mapping, using the raw event type.
  const tenantConfigWebhookUrl = tenantConfigs.get(tenantId)?.webhookUrl;
  if (tenantConfigWebhookUrl) {
    const tenantConfigEvent: WebhookEvent = {
      type,
      tenantId,
      agentId,
      data: redactWebhookSecrets(data),
      timestamp: new Date(),
    };
    const dispatcher = new WebhookDispatcher();
    dispatcher.dispatch(tenantConfigEvent, tenantConfigWebhookUrl).catch((error) => {
      console.error("[webhooks] Failed to dispatch tenant config webhook:", error);
    });
  }
}

async function dispatchConfiguredWebhooks(
  event: WebhookEvent,
  configuredType: ConfiguredWebhookEventType | null,
): Promise<void> {
  const configs = await db
    .select()
    .from(webhookConfigs)
    .where(and(eq(webhookConfigs.tenantId, event.tenantId), eq(webhookConfigs.enabled, true)));

  await Promise.all(
    configs
      .filter((config) =>
        configuredType
          ? acceptsConfiguredWebhookEvent(config.events, configuredType)
          : config.events.length === 0,
      )
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
  },
): Promise<void> {
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
  const eventWithDelivery: WebhookEvent & { deliveryId: string; webhookConfigId: string } = {
    ...event,
    deliveryId,
    webhookConfigId: config.id,
  };
  const [delivery] = await db
    .insert(webhookDeliveries)
    .values({
      id: deliveryId,
      tenantId: event.tenantId,
      webhookConfigId: config.id,
      agentId: event.agentId,
      eventType: event.type,
      payload: eventWithDelivery as unknown as Record<string, unknown>,
      url: config.url,
      secret: encryptedSecret,
      events: config.events,
      status: "processing",
      attempts: 0,
      maxAttempts: config.maxRetries + 1,
      nextRetryAt: new Date(Date.now() + INLINE_DELIVERY_VISIBILITY_TIMEOUT_MS),
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

  await db
    .update(webhookDeliveries)
    .set({
      status: result.success ? "delivered" : retryable ? "pending" : "failed",
      attempts: result.attempts,
      deliveredAt: result.deliveredAt ?? null,
      lastError: result.error ?? null,
      nextRetryAt: retryable ? new Date(Date.now() + config.retryBackoffMs) : null,
    })
    .where(eq(webhookDeliveries.id, delivery.id));
}

import { randomUUID } from "node:crypto";
import { and, eq, webhookConfigs, webhookDeliveries } from "@stwd/db";
import type { WebhookEvent } from "@stwd/shared";
import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  isEncryptedWebhookSecret,
  WebhookDispatcher,
} from "@stwd/webhooks";
import { db } from "./context";
import {
  acceptsConfiguredWebhookEvent,
  type ConfiguredWebhookEventType,
  type DispatchableWebhookEventType,
  toConfiguredWebhookEventType,
} from "./webhook-events";

const INLINE_DELIVERY_VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000;
const REDACTED_WEBHOOK_SECRET = "[REDACTED]";

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSensitiveWebhookPayloadKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, "");
  return (
    normalized === "secret" ||
    normalized.endsWith("secret") ||
    normalized === "password" ||
    normalized === "passphrase" ||
    normalized === "mnemonic" ||
    normalized === "recoveryphrase" ||
    normalized === "seedphrase" ||
    normalized === "privatekey" ||
    normalized === "accesskey" ||
    normalized === "apikey" ||
    normalized === "accesstoken" ||
    normalized === "refreshtoken" ||
    normalized === "idtoken" ||
    normalized === "sessiontoken" ||
    normalized === "authtoken"
  );
}

export function redactWebhookSecrets(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => redactWebhookSecrets(entry));
  }
  if (!isPlainObject(value) || value instanceof Date) {
    return value;
  }

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [
      key,
      isSensitiveWebhookPayloadKey(key) ? REDACTED_WEBHOOK_SECRET : redactWebhookSecrets(entry),
    ]),
  );
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
    data: redactWebhookSecrets(data) as Record<string, unknown>,
    timestamp: new Date(),
  };
  void dispatchConfiguredWebhooks(event, configuredType).catch((error) => {
    console.error("[webhooks] Failed to dispatch configured webhooks:", error);
  });
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

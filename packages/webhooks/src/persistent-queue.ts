/**
 * Persistent webhook delivery queue backed by the `webhook_deliveries` DB table.
 *
 * Replaces the in-memory RetryQueue for production use. Webhooks survive
 * process restarts and use exponential backoff for retries. Delivery is
 * at-least-once: receivers must deduplicate the stable deliveryId because an
 * HTTP success followed by a lost database acknowledgement is ambiguous.
 */

import { randomUUID } from "node:crypto";
import { getDb, webhookConfigs, webhookDeliveries } from "@stwd/db";
import type { WebhookEvent } from "@stwd/shared";
import { and, eq, sql } from "drizzle-orm";

import { WebhookDispatcher } from "./dispatcher";
import { decryptWebhookSecret, encryptWebhookSecret } from "./secret-codec";
import type { WebhookConfig, WebhookDeliveryResult } from "./types";

// Exponential backoff schedule: 1min, 5min, 30min, 2hr, 12hr
const RETRY_DELAYS_MS = [
  1 * 60 * 1000, // 1 minute
  5 * 60 * 1000, // 5 minutes
  30 * 60 * 1000, // 30 minutes
  2 * 60 * 60 * 1000, // 2 hours
  12 * 60 * 60 * 1000, // 12 hours
];

const DEFAULT_MAX_ATTEMPTS = 5;
const CLAIM_VISIBILITY_TIMEOUT_MS = 5 * 60 * 1000;

export interface PersistentQueueOptions {
  maxAttempts?: number;
  /** How many deliveries to process per tick */
  batchSize?: number;
}

export interface PersistentQueueStats {
  pending: number;
  delivered: number;
  failed: number;
  dead: number;
}

type ClaimOutcomePatch = {
  status: "delivered" | "failed" | "dead";
  attempts: number;
  lastError: string | null;
  deliveredAt?: Date;
  nextRetryAt?: Date | null;
  payload?: Record<string, unknown>;
};

async function settleClaim(
  deliveryId: string,
  claimToken: string,
  patch: ClaimOutcomePatch,
): Promise<boolean> {
  const [updated] = await getDb()
    .update(webhookDeliveries)
    .set({ ...patch, claimToken: null })
    .where(
      and(
        eq(webhookDeliveries.id, deliveryId),
        eq(webhookDeliveries.status, "processing"),
        eq(webhookDeliveries.claimToken, claimToken),
      ),
    )
    .returning({ id: webhookDeliveries.id });
  return updated !== undefined;
}

export class PersistentQueue {
  private readonly dispatcher: WebhookDispatcher;
  private readonly maxAttempts: number;
  private readonly batchSize: number;

  constructor(
    dispatcher = new WebhookDispatcher({ maxRetries: 0 }),
    options: PersistentQueueOptions = {},
  ) {
    this.dispatcher = dispatcher;
    this.maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    this.batchSize = options.batchSize ?? 50;
  }

  /**
   * Enqueue a webhook delivery to the database.
   * Returns the delivery ID.
   */
  async enqueue(event: WebhookEvent, webhook: WebhookConfig | string): Promise<string> {
    const db = getDb();
    // Persist the receiver-visible identity before the row becomes available to workers.
    const deliveryId = randomUUID();
    const signedAt =
      typeof event.signedAt === "number" && Number.isFinite(event.signedAt)
        ? Math.floor(event.signedAt)
        : Math.floor(Date.now() / 1000);
    const persistedEvent: WebhookEvent = { ...event, deliveryId, signedAt };
    const url = typeof webhook === "string" ? webhook : webhook.url;
    const webhookConfigId = typeof webhook === "string" ? null : (webhook.id ?? null);
    const secret = typeof webhook === "string" ? null : encryptWebhookSecret(webhook.secret);
    const events = typeof webhook === "string" ? null : (webhook.events ?? []);

    const [row] = await db
      .insert(webhookDeliveries)
      .values({
        id: deliveryId,
        tenantId: event.tenantId,
        webhookConfigId,
        agentId: event.agentId,
        eventType: event.type,
        payload: persistedEvent as unknown as Record<string, unknown>,
        url,
        secret,
        events,
        status: "pending",
        attempts: 0,
        maxAttempts: this.maxAttempts,
        nextRetryAt: new Date(),
      })
      .returning();

    return row.id;
  }

  /**
   * Process pending and retryable deliveries.
   * Picks up rows where status is 'pending' or 'failed' and nextRetryAt <= now.
   */
  async processQueue(): Promise<WebhookDeliveryResult[]> {
    const db = getDb();
    const now = new Date();
    const claimToken = randomUUID();
    const results: WebhookDeliveryResult[] = [];

    // Atomically claim due deliveries before dispatch. The temporary
    // nextRetryAt push acts as a visibility timeout if a worker crashes mid-send.
    const claimed = (await db.transaction(async (tx) => {
      // Claiming consumes an attempt. Once an abandoned claim has expired at
      // its durable limit, terminalize it without another external send.
      await tx.execute(sql`
        UPDATE ${webhookDeliveries}
        SET
          "status" = 'dead',
          "claim_token" = NULL,
          "last_error" = COALESCE("last_error", 'Max attempts exceeded')
        WHERE (
          ${webhookDeliveries.status} in ('pending', 'failed')
          OR ${webhookDeliveries.status} = 'processing'
        )
          AND ${webhookDeliveries.nextRetryAt} <= ${now.toISOString()}
          AND ${webhookDeliveries.attempts} >= ${webhookDeliveries.maxAttempts}
      `);

      // A dependent success event must never overtake a predecessor that can
      // no longer be delivered. Resolve the chain terminally instead of
      // leaving an undeliverable row pending forever.
      await tx.execute(sql`
        UPDATE ${webhookDeliveries} AS dependent
        SET
          "status" = 'dead',
          "claim_token" = NULL,
          "last_error" = 'Predecessor webhook delivery is dead'
        FROM ${webhookDeliveries} AS predecessor
        WHERE dependent."predecessor_delivery_id" = predecessor."id"
          AND predecessor."status" = 'dead'
          AND dependent."status" in ('pending', 'failed', 'processing')
      `);
      return tx.execute(sql`
        UPDATE ${webhookDeliveries}
        SET
          "status" = 'processing',
          "claim_token" = ${claimToken},
          "attempts" = "attempts" + 1,
          "next_retry_at" = ${new Date(now.getTime() + CLAIM_VISIBILITY_TIMEOUT_MS).toISOString()},
          "payload" = jsonb_set(
            jsonb_set(
              "payload",
              '{deliveryId}',
              CASE
                WHEN jsonb_typeof("payload"->'deliveryId') = 'string'
                  AND length("payload"->>'deliveryId') > 0
                THEN "payload"->'deliveryId'
                ELSE to_jsonb("id"::text)
              END,
              true
            ),
            '{signedAt}',
            CASE
              WHEN jsonb_typeof("payload"->'signedAt') = 'number'
                THEN "payload"->'signedAt'
              ELSE to_jsonb(floor(extract(epoch from "created_at"))::bigint)
            END,
            true
          )
        WHERE "id" IN (
          SELECT candidate."id"
          FROM ${webhookDeliveries} AS candidate
          WHERE (
            candidate."status" in ('pending', 'failed')
            OR candidate."status" = 'processing'
          )
            AND candidate."next_retry_at" <= ${now.toISOString()}
            AND candidate."attempts" < candidate."max_attempts"
            AND (
              candidate."predecessor_delivery_id" IS NULL
              OR EXISTS (
                SELECT 1
                FROM ${webhookDeliveries} AS predecessor
                WHERE predecessor."id" = candidate."predecessor_delivery_id"
                  AND predecessor."status" = 'delivered'
              )
            )
          ORDER BY candidate."next_retry_at" ASC, candidate."created_at" ASC, candidate."id" ASC
          FOR UPDATE SKIP LOCKED
          LIMIT ${this.batchSize}
        )
        RETURNING
          "id",
          "tenant_id" AS "tenantId",
          "webhook_config_id" AS "webhookConfigId",
          "agent_id" AS "agentId",
          "event_type" AS "eventType",
          "predecessor_delivery_id" AS "predecessorDeliveryId",
          "replayed_from_delivery_id" AS "replayedFromDeliveryId",
          "payload",
          "url",
          "secret",
          "events",
          "status",
          "attempts",
          "max_attempts" AS "maxAttempts",
          "next_retry_at" AS "nextRetryAt",
          "claim_token" AS "claimToken",
          "last_error" AS "lastError",
          "created_at" AS "createdAt",
          "delivered_at" AS "deliveredAt"
      `);
    })) as unknown;
    const claimedRows =
      typeof claimed === "object" &&
      claimed !== null &&
      "rows" in claimed &&
      Array.isArray((claimed as { rows?: unknown }).rows)
        ? (claimed as { rows: unknown[] }).rows
        : [];
    const deliveries = (
      Array.isArray(claimed) ? claimed : claimedRows
    ) as (typeof webhookDeliveries.$inferSelect)[];

    for (const delivery of deliveries) {
      if (!delivery.claimToken) continue;
      const event = delivery.payload as unknown as WebhookEvent;
      // The atomic claim consumes the attempt before external I/O.
      const newAttempts = delivery.attempts;
      if (!delivery.webhookConfigId || !delivery.secret) {
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: "Webhook delivery is missing original configuration snapshot",
        });
        if (!settled) continue;
        results.push({
          success: false,
          attempts: newAttempts,
          error: "Webhook delivery is missing original configuration snapshot",
        });
        continue;
      }

      const [webhook] = await db
        .select({
          id: webhookConfigs.id,
          url: webhookConfigs.url,
          events: webhookConfigs.events,
        })
        .from(webhookConfigs)
        .where(
          and(
            eq(webhookConfigs.tenantId, delivery.tenantId),
            eq(webhookConfigs.id, delivery.webhookConfigId),
            eq(webhookConfigs.enabled, true),
          ),
        )
        .limit(1);

      if (!webhook) {
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: "Webhook configuration is disabled or deleted",
        });
        if (!settled) continue;
        results.push({
          success: false,
          attempts: newAttempts,
          error: "Webhook configuration is disabled or deleted",
        });
        continue;
      }
      if (webhook.url !== delivery.url) {
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: "Webhook delivery URL no longer matches its original configuration",
        });
        if (!settled) continue;
        results.push({
          success: false,
          attempts: newAttempts,
          error: "Webhook delivery URL no longer matches its original configuration",
        });
        continue;
      }
      if (webhook.events.length > 0 && !webhook.events.includes(delivery.eventType)) {
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: "Webhook configuration no longer subscribes to this event",
        });
        if (!settled) continue;
        results.push({
          success: false,
          attempts: newAttempts,
          error: "Webhook configuration no longer subscribes to this event",
        });
        continue;
      }

      // A poisoned row must not reject the whole batch: an undecryptable
      // secret (e.g. after STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY rotation, or
      // a malformed stwd_whsec_v1: payload) throws deterministically, and an
      // un-wrapped throw would reclaim the row forever and block every later
      // delivery in the batch. Dead-letter it (attempts incremented) and move
      // on — the row never becomes deliverable again on its own.
      let result: WebhookDeliveryResult;
      try {
        result = await this.dispatcher.dispatch(event, {
          id: webhook.id,
          url: delivery.url,
          secret: decryptWebhookSecret(delivery.secret),
          events: delivery.events ?? undefined,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown webhook delivery error";
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: `Webhook delivery failed deterministically: ${message}`,
        });
        if (!settled) continue;
        results.push({
          success: false,
          attempts: newAttempts,
          error: message,
        });
        continue;
      }

      // dispatch() mutates `event` with a stable deliveryId + signedAt; persist it
      // so retries reuse the same id/timestamp/signature instead of re-signing fresh.
      const persistedPayload = event as unknown as Record<string, unknown>;

      if (result.success) {
        // Mark as delivered
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "delivered",
          attempts: newAttempts,
          deliveredAt: new Date(),
          lastError: null,
          payload: persistedPayload,
        });
        if (!settled) continue;

        results.push({ ...result, attempts: newAttempts });
        continue;
      }

      // Failed — check if we should retry or mark dead
      if (newAttempts >= delivery.maxAttempts) {
        // Dead letter
        const settled = await settleClaim(delivery.id, delivery.claimToken, {
          status: "dead",
          attempts: newAttempts,
          lastError: result.error ?? "Max attempts exceeded",
          payload: persistedPayload,
        });
        if (!settled) continue;

        results.push({ ...result, attempts: newAttempts });
        continue;
      }

      // Schedule retry with exponential backoff
      const delayIndex = Math.min(newAttempts - 1, RETRY_DELAYS_MS.length - 1);
      const delayMs = RETRY_DELAYS_MS[delayIndex];
      const nextRetryAt = new Date(Date.now() + delayMs);

      const settled = await settleClaim(delivery.id, delivery.claimToken, {
        status: "failed",
        attempts: newAttempts,
        nextRetryAt,
        lastError: result.error ?? "Delivery failed",
        payload: persistedPayload,
      });
      if (!settled) continue;

      results.push({ ...result, attempts: newAttempts });
    }

    return results;
  }

  /**
   * Get queue statistics from the database.
   */
  async getStats(): Promise<PersistentQueueStats> {
    const db = getDb();

    const [stats] = await db
      .select({
        pending: sql<number>`count(*) filter (where ${webhookDeliveries.status} = 'pending')`,
        delivered: sql<number>`count(*) filter (where ${webhookDeliveries.status} = 'delivered')`,
        failed: sql<number>`count(*) filter (where ${webhookDeliveries.status} = 'failed')`,
        dead: sql<number>`count(*) filter (where ${webhookDeliveries.status} = 'dead')`,
      })
      .from(webhookDeliveries);

    return {
      pending: Number(stats?.pending ?? 0),
      delivered: Number(stats?.delivered ?? 0),
      failed: Number(stats?.failed ?? 0),
      dead: Number(stats?.dead ?? 0),
    };
  }

  /**
   * Get a specific delivery by ID (useful for checking status).
   */
  async getDelivery(id: string) {
    const db = getDb();
    const [delivery] = await db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, id));
    return delivery ?? null;
  }
}

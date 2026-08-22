import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants, webhookConfigs, webhookDeliveries } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { PersistentQueue } from "@stwd/webhooks";
import { eq, sql } from "drizzle-orm";

const tenantId = `persistent-order-${crypto.randomUUID()}`;
const triggerName = `fail_webhook_ack_${crypto.randomUUID().replaceAll("-", "")}`;

describe("persistent webhook dependency ordering", () => {
  beforeAll(async () => {
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    await getDb().insert(tenants).values({ id: tenantId, name: tenantId, apiKeyHash: tenantId });
  });

  afterAll(async () => {
    await closeDb();
  });

  it("orders dependent effects and exposes stable receiver dedupe after a lost database ack", async () => {
    const [config] = await getDb()
      .insert(webhookConfigs)
      .values({
        tenantId,
        url: "https://receiver.example.test/intent-effects",
        secret: "test-secret",
        events: [],
      })
      .returning();
    const walletDeliveryId = crypto.randomUUID();
    const intentDeliveryId = crypto.randomUUID();
    const now = new Date();
    const payload = (id: string, type: string) => ({
      type,
      tenantId,
      agentId: "ordering-agent",
      data: { intent_id: "ordering-intent" },
      timestamp: now,
      deliveryId: id,
      webhookConfigId: config.id,
      signedAt: Math.floor(now.getTime() / 1_000),
    });
    await getDb()
      .insert(webhookDeliveries)
      .values([
        {
          id: walletDeliveryId,
          tenantId,
          webhookConfigId: config.id,
          agentId: "ordering-agent",
          eventType: "wallet_action.transfer.succeeded",
          payload: payload(walletDeliveryId, "wallet_action.transfer.succeeded"),
          url: config.url,
          secret: config.secret,
          events: [],
          status: "pending",
          attempts: 0,
          maxAttempts: 2,
          nextRetryAt: now,
        },
        {
          id: intentDeliveryId,
          tenantId,
          webhookConfigId: config.id,
          agentId: "ordering-agent",
          eventType: "intent.executed",
          predecessorDeliveryId: walletDeliveryId,
          payload: payload(intentDeliveryId, "intent.executed"),
          url: config.url,
          secret: config.secret,
          events: [],
          status: "pending",
          attempts: 0,
          maxAttempts: 2,
          nextRetryAt: now,
        },
      ]);

    const attempts: Array<{ type: string; deliveryId: string }> = [];
    const receiverEffects = new Set<string>();
    const queue = new PersistentQueue(
      {
        async dispatch(event: { type: string; deliveryId?: string }) {
          const deliveryId = String(event.deliveryId);
          attempts.push({ type: event.type, deliveryId });
          receiverEffects.add(deliveryId);
          return { success: true, attempts: 1, deliveredAt: new Date() };
        },
      } as never,
      { batchSize: 50 },
    );

    await getDb().execute(
      sql.raw(`
        CREATE FUNCTION "${triggerName}"() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.status = 'delivered' AND OLD.id = '${walletDeliveryId}' THEN
            RAISE EXCEPTION 'lost delivery database acknowledgement';
          END IF;
          RETURN NEW;
        END
        $$
      `),
    );
    await getDb().execute(
      sql.raw(`
        CREATE TRIGGER "${triggerName}"
        BEFORE UPDATE ON webhook_deliveries
        FOR EACH ROW EXECUTE FUNCTION "${triggerName}"()
      `),
    );
    await expect(queue.processQueue()).rejects.toThrow();
    expect(attempts).toEqual([
      { type: "wallet_action.transfer.succeeded", deliveryId: walletDeliveryId },
    ]);
    expect(receiverEffects.size).toBe(1);

    await getDb().execute(sql.raw(`DROP TRIGGER "${triggerName}" ON webhook_deliveries`));
    await getDb().execute(sql.raw(`DROP FUNCTION "${triggerName}"()`));
    await getDb()
      .update(webhookDeliveries)
      .set({ nextRetryAt: new Date() })
      .where(eq(webhookDeliveries.id, walletDeliveryId));

    expect(await queue.processQueue()).toHaveLength(1);
    expect(attempts[1]).toEqual({
      type: "wallet_action.transfer.succeeded",
      deliveryId: walletDeliveryId,
    });
    expect(receiverEffects.size).toBe(1);

    expect(await queue.processQueue()).toHaveLength(1);
    expect(attempts[2]).toEqual({ type: "intent.executed", deliveryId: intentDeliveryId });
    expect(receiverEffects.size).toBe(2);
  });

  it("fences an expired worker from overwriting the successor claim", async () => {
    const [config] = await getDb()
      .insert(webhookConfigs)
      .values({
        tenantId,
        url: "https://receiver.example.test/lease-fence",
        secret: "lease-secret",
        events: [],
      })
      .returning();
    const deliveryId = crypto.randomUUID();
    const now = new Date();
    await getDb()
      .insert(webhookDeliveries)
      .values({
        id: deliveryId,
        tenantId,
        webhookConfigId: config.id,
        agentId: "lease-agent",
        eventType: "intent.executed",
        payload: {
          type: "intent.executed",
          tenantId,
          agentId: "lease-agent",
          data: {},
          timestamp: now,
          deliveryId,
          webhookConfigId: config.id,
          signedAt: Math.floor(now.getTime() / 1_000),
        },
        url: config.url,
        secret: config.secret,
        events: [],
        status: "pending",
        attempts: 0,
        maxAttempts: 1,
        nextRetryAt: now,
      });

    let releaseExpired!: () => void;
    const expiredRelease = new Promise<void>((resolve) => {
      releaseExpired = resolve;
    });
    let expiredStarted!: () => void;
    const started = new Promise<void>((resolve) => {
      expiredStarted = resolve;
    });
    const expiredWorker = new PersistentQueue(
      {
        async dispatch() {
          expiredStarted();
          await expiredRelease;
          return { success: false, attempts: 1, error: "expired worker failure" };
        },
      } as never,
      { batchSize: 1 },
    );
    const successorWorker = new PersistentQueue(
      {
        async dispatch() {
          return { success: true, attempts: 1, deliveredAt: new Date() };
        },
      } as never,
      { batchSize: 1 },
    );

    const expiredRun = expiredWorker.processQueue();
    await started;
    const [expiredClaim] = await getDb()
      .select({ claimToken: webhookDeliveries.claimToken })
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, deliveryId));
    expect(expiredClaim.claimToken).toEqual(expect.any(String));

    await getDb()
      .update(webhookDeliveries)
      .set({ nextRetryAt: new Date(Date.now() - 1) })
      .where(eq(webhookDeliveries.id, deliveryId));
    expect(await successorWorker.processQueue()).toHaveLength(1);

    releaseExpired();
    expect(await expiredRun).toHaveLength(0);
    const [finalDelivery] = await getDb()
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.id, deliveryId));
    expect(finalDelivery).toMatchObject({
      status: "delivered",
      attempts: 1,
      claimToken: null,
      lastError: null,
    });
  });
});

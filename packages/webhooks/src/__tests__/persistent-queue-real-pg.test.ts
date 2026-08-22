import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { closeDb, getDb, tenants, webhookConfigs, webhookDeliveries } from "@stwd/db";
import type { WebhookEvent } from "@stwd/shared";
import { and, eq } from "drizzle-orm";
import { WebhookDispatcher } from "../dispatcher";
import { PersistentQueue } from "../persistent-queue";
import type { WebhookConfig, WebhookDeliveryResult } from "../types";

const HAS_REAL_PG =
  Boolean(process.env.DATABASE_URL) && process.env.STEWARD_PGLITE_MEMORY !== "true";
const describeWithPostgres = HAS_REAL_PG ? describe : describe.skip;
setDefaultTimeout(30_000);

process.env.STEWARD_WEBHOOK_SECRET_ENCRYPTION_KEY ??=
  "persistent-queue-real-pg-encryption-key-0123456789abcdef";

const cleanupTenants = new Set<string>();

type DispatchCall = {
  event: WebhookEvent;
  config: WebhookConfig;
};

function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function eventFor(tenantId: string): WebhookEvent {
  return {
    type: "tx_signed",
    tenantId,
    agentId: `agent-${randomUUID().slice(0, 8)}`,
    data: { txHash: `0x${randomUUID().replaceAll("-", "")}` },
    timestamp: new Date(),
  };
}

async function seedConfig(overrides: Partial<typeof webhookConfigs.$inferInsert> = {}) {
  const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
  const tenantId = `queue-pg-${suffix}`;
  cleanupTenants.add(tenantId);
  await getDb()
    .insert(tenants)
    .values({
      id: tenantId,
      name: `Queue PG ${suffix}`,
      apiKeyHash: `hash-${suffix}`,
    });
  const [config] = await getDb()
    .insert(webhookConfigs)
    .values({
      tenantId,
      url: `https://receiver-${suffix}.example.test/hook`,
      secret: `database-secret-${suffix}`,
      events: ["tx_signed"],
      enabled: true,
      ...overrides,
    })
    .returning();
  if (!config) throw new Error("failed to seed webhook config");
  return { tenantId, config };
}

function queueWithDispatcher(
  dispatch: (event: WebhookEvent, config: WebhookConfig) => Promise<WebhookDeliveryResult>,
  options: { maxAttempts?: number; batchSize?: number } = {},
) {
  return new PersistentQueue({ dispatch } as unknown as WebhookDispatcher, options);
}

async function enqueueSnapshot(
  queue: PersistentQueue,
  tenantId: string,
  config: typeof webhookConfigs.$inferSelect,
  secret = `snapshot-secret-${randomUUID()}`,
) {
  const event = eventFor(tenantId);
  const deliveryId = await queue.enqueue(event, {
    id: config.id,
    url: config.url,
    secret,
    events: config.events,
  });
  return { deliveryId, event, secret };
}

async function dueNow(deliveryId: string) {
  await getDb()
    .update(webhookDeliveries)
    .set({ nextRetryAt: new Date(Date.now() - 1_000) })
    .where(eq(webhookDeliveries.id, deliveryId));
}

type CapturedRequest = {
  headers: IncomingMessage["headers"];
  body: string;
};

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function startReceiver(statuses: number[]) {
  const requests: CapturedRequest[] = [];
  const server = createServer(async (req, res) => {
    requests.push({ headers: req.headers, body: await readBody(req) });
    const status = statuses[requests.length - 1] ?? statuses.at(-1) ?? 200;
    res.writeHead(status);
    res.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => (error ? reject(error) : resolve()));
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/hook`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function startDeduplicatingReceiver() {
  const requests: CapturedRequest[] = [];
  const acceptedDeliveryIds = new Set<string>();
  const firstAccepted = deferred();
  const server = createServer(async (req, res) => {
    const body = await readBody(req);
    requests.push({ headers: req.headers, body });
    const deliveryId = String(req.headers["x-steward-delivery-id"] ?? "");
    const duplicate = acceptedDeliveryIds.has(deliveryId);
    if (!duplicate) acceptedDeliveryIds.add(deliveryId);
    firstAccepted.resolve();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ accepted: !duplicate, duplicate }));
  });
  await new Promise<void>((resolve, reject) => {
    server.listen(0, "127.0.0.1", (error?: Error) => (error ? reject(error) : resolve()));
  });
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/hook`,
    requests,
    acceptedDeliveryIds,
    firstAccepted: firstAccepted.promise,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

afterAll(async () => {
  if (!HAS_REAL_PG) return;
  for (const tenantId of cleanupTenants) {
    await getDb().delete(webhookDeliveries).where(eq(webhookDeliveries.tenantId, tenantId));
    await getDb().delete(webhookConfigs).where(eq(webhookConfigs.tenantId, tenantId));
    await getDb().delete(tenants).where(eq(tenants.id, tenantId));
  }
  await closeDb();
});

describeWithPostgres("PersistentQueue authority on real PostgreSQL", () => {
  test("two workers claim one due delivery and send it exactly once", async () => {
    const { tenantId, config } = await seedConfig();
    const entered = deferred();
    const release = deferred();
    const calls: DispatchCall[] = [];
    const dispatch = async (event: WebhookEvent, webhook: WebhookConfig) => {
      calls.push({ event, config: webhook });
      entered.resolve();
      await release.promise;
      return { success: true, attempts: 1, deliveredAt: new Date() };
    };
    const firstWorker = queueWithDispatcher(dispatch, { batchSize: 1 });
    const secondWorker = queueWithDispatcher(dispatch, { batchSize: 1 });
    const { deliveryId } = await enqueueSnapshot(firstWorker, tenantId, config);

    const runs = [firstWorker.processQueue(), secondWorker.processQueue()];
    await entered.promise;
    const idleWorker = await Promise.race(runs);
    expect(idleWorker).toEqual([]);
    expect(calls).toHaveLength(1);
    release.resolve();
    const results = await Promise.all(runs);
    expect(results.map((result) => result.length).sort()).toEqual([0, 1]);
    expect(calls).toHaveLength(1);
    expect(await firstWorker.getDelivery(deliveryId)).toMatchObject({
      status: "delivered",
      attempts: 1,
    });
  });

  test("a crashed claim stays hidden until visibility expiry", async () => {
    const { tenantId, config } = await seedConfig();
    const calls: DispatchCall[] = [];
    const queue = queueWithDispatcher(async (event, webhook) => {
      calls.push({ event, config: webhook });
      return { success: true, attempts: 1, deliveredAt: new Date() };
    });
    const { deliveryId } = await enqueueSnapshot(queue, tenantId, config);
    await getDb()
      .update(webhookDeliveries)
      .set({ status: "processing", nextRetryAt: new Date(Date.now() + 60_000) })
      .where(eq(webhookDeliveries.id, deliveryId));

    expect(await queue.processQueue()).toEqual([]);
    expect(calls).toHaveLength(0);
    await dueNow(deliveryId);
    expect(await queue.processQueue()).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(await queue.getDelivery(deliveryId)).toMatchObject({
      status: "delivered",
      attempts: 1,
    });
  });

  test("receiver dedup reuses the durable identity after a worker disappears post-accept", async () => {
    const receiver = await startDeduplicatingReceiver();
    try {
      const { tenantId, config } = await seedConfig({ url: receiver.url });
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 2_000,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const dispatchReturned = deferred();
      const abandonedWorker = new Promise<never>(() => undefined);
      const crashingQueue = queueWithDispatcher(async (event, webhook) => {
        const result = await dispatcher.dispatch(event, webhook);
        dispatchReturned.resolve();
        // Model abrupt worker loss after the receiver accepted the request but
        // before processQueue can persist the dispatch result. This promise has
        // no active handle, just as the vanished worker has no future DB write.
        await abandonedWorker;
        return result;
      });
      const recoveryQueue = new PersistentQueue(dispatcher, { maxAttempts: 3 });
      const { deliveryId, event } = await enqueueSnapshot(crashingQueue, tenantId, config);

      // New work is born with its row identity and original timestamp in the
      // same insert. Also simulate a row queued by the previous build to prove
      // the atomic claim repairs legacy payloads before external I/O.
      expect(await recoveryQueue.getDelivery(deliveryId)).toMatchObject({
        status: "pending",
        payload: { deliveryId, signedAt: expect.any(Number) },
      });
      await getDb()
        .update(webhookDeliveries)
        .set({ payload: event as unknown as Record<string, unknown> })
        .where(eq(webhookDeliveries.id, deliveryId));

      void crashingQueue.processQueue();
      await receiver.firstAccepted;
      await dispatchReturned.promise;
      expect(receiver.requests).toHaveLength(1);
      expect(receiver.requests[0]?.headers["x-steward-delivery-id"]).toBe(deliveryId);
      expect(await recoveryQueue.getDelivery(deliveryId)).toMatchObject({
        status: "processing",
        attempts: 1,
        payload: { deliveryId, signedAt: expect.any(Number) },
      });

      // The visibility lease still fences an early recovery attempt.
      expect(await recoveryQueue.processQueue()).toEqual([]);
      expect(receiver.requests).toHaveLength(1);

      // Once visibility expires, a new worker transmits with a fresh signature
      // timestamp but the same durable delivery identity/body. The receiver's
      // idempotency set accepts the logical delivery only once.
      await new Promise((resolve) => setTimeout(resolve, 1_100));
      await dueNow(deliveryId);
      expect(await recoveryQueue.processQueue()).toMatchObject([
        { success: true, attempts: 2, deliveryId },
      ]);
      expect(receiver.requests).toHaveLength(2);
      const [first, retry] = receiver.requests;
      expect(retry?.headers["x-steward-delivery-id"]).toBe(deliveryId);
      expect(retry?.headers["x-steward-delivery-id"]).toBe(
        first?.headers["x-steward-delivery-id"],
      );
      expect(retry?.headers["x-steward-sent-at"]).not.toBe(first?.headers["x-steward-sent-at"]);
      expect(retry?.headers["x-steward-signature"]).not.toBe(
        first?.headers["x-steward-signature"],
      );
      expect(JSON.parse(retry?.body ?? "{}")).toEqual(JSON.parse(first?.body ?? "{}"));
      expect(receiver.acceptedDeliveryIds).toEqual(new Set([deliveryId]));
      expect(await recoveryQueue.getDelivery(deliveryId)).toMatchObject({
        status: "delivered",
        attempts: 2,
        payload: { deliveryId, signedAt: expect.any(Number) },
      });
    } finally {
      await receiver.close();
    }
  });

  test("post-accept crashes consume the durable maximum before another send", async () => {
    const receiver = await startDeduplicatingReceiver();
    try {
      const { tenantId, config } = await seedConfig({ url: receiver.url });
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 2_000,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const crashAfterAccept = () => {
        const dispatchReturned = deferred();
        const abandonedWorker = new Promise<never>(() => undefined);
        return {
          dispatchReturned: dispatchReturned.promise,
          queue: queueWithDispatcher(
            async (event, webhook) => {
              const result = await dispatcher.dispatch(event, webhook);
              dispatchReturned.resolve();
              await abandonedWorker;
              return result;
            },
            { maxAttempts: 2 },
          ),
        };
      };

      const firstWorker = crashAfterAccept();
      const { deliveryId } = await enqueueSnapshot(firstWorker.queue, tenantId, config);
      void firstWorker.queue.processQueue();
      await firstWorker.dispatchReturned;
      expect(receiver.requests).toHaveLength(1);
      expect(await firstWorker.queue.getDelivery(deliveryId)).toMatchObject({
        status: "processing",
        attempts: 1,
      });

      const secondWorker = crashAfterAccept();
      await dueNow(deliveryId);
      void secondWorker.queue.processQueue();
      await secondWorker.dispatchReturned;
      expect(receiver.requests).toHaveLength(2);
      expect(await secondWorker.queue.getDelivery(deliveryId)).toMatchObject({
        status: "processing",
        attempts: 2,
      });

      // The next expired-claim scan terminalizes the row without a third POST.
      await dueNow(deliveryId);
      const recoveryQueue = new PersistentQueue(dispatcher, { maxAttempts: 2 });
      expect(await recoveryQueue.processQueue()).toEqual([]);
      expect(receiver.requests).toHaveLength(2);
      expect(receiver.acceptedDeliveryIds).toEqual(new Set([deliveryId]));
      expect(await recoveryQueue.getDelivery(deliveryId)).toMatchObject({
        status: "dead",
        attempts: 2,
        lastError: "Max attempts exceeded",
      });
    } finally {
      await receiver.close();
    }
  });

  test("durable retries keep one delivery id, refresh signatures, and do not retry internally", async () => {
    const receiver = await startReceiver([500, 200]);
    try {
      const { tenantId, config } = await seedConfig({ url: receiver.url });
      const dispatcher = new WebhookDispatcher({
        maxRetries: 0,
        timeoutMs: 2_000,
        allowPrivateNetwork: true,
        allowInsecureHttp: true,
      });
      const queue = new PersistentQueue(dispatcher, { maxAttempts: 3 });
      const { deliveryId } = await enqueueSnapshot(queue, tenantId, config);

      const first = await queue.processQueue();
      expect(first).toHaveLength(1);
      expect(first[0]).toMatchObject({ success: false, attempts: 1 });
      expect(receiver.requests).toHaveLength(1);
      expect(await queue.processQueue()).toEqual([]);
      expect(receiver.requests).toHaveLength(1);

      await new Promise((resolve) => setTimeout(resolve, 1_100));
      await dueNow(deliveryId);
      const second = await queue.processQueue();
      expect(second[0]).toMatchObject({ success: true, attempts: 2 });
      expect(receiver.requests).toHaveLength(2);
      const [a, b] = receiver.requests;
      expect(a?.headers["x-steward-delivery-id"]).toBe(b?.headers["x-steward-delivery-id"]);
      expect(a?.headers["x-steward-sent-at"]).not.toBe(b?.headers["x-steward-sent-at"]);
      expect(a?.headers["x-steward-signature"]).not.toBe(b?.headers["x-steward-signature"]);
      expect(JSON.parse(a?.body ?? "{}")).toEqual(JSON.parse(b?.body ?? "{}"));
      expect(await queue.getDelivery(deliveryId)).toMatchObject({
        status: "delivered",
        attempts: 2,
      });
    } finally {
      await receiver.close();
    }
  });

  test("attempts stop at the durable maximum and persist terminal failure", async () => {
    const { tenantId, config } = await seedConfig();
    let calls = 0;
    const queue = queueWithDispatcher(
      async () => {
        calls += 1;
        return { success: false, attempts: 1, error: "receiver unavailable" };
      },
      { maxAttempts: 2 },
    );
    const { deliveryId } = await enqueueSnapshot(queue, tenantId, config);

    expect((await queue.processQueue())[0]).toMatchObject({ success: false, attempts: 1 });
    expect(await queue.processQueue()).toEqual([]);
    await dueNow(deliveryId);
    expect((await queue.processQueue())[0]).toMatchObject({ success: false, attempts: 2 });
    await dueNow(deliveryId);
    expect(await queue.processQueue()).toEqual([]);
    expect(calls).toBe(2);
    expect(await queue.getDelivery(deliveryId)).toMatchObject({
      status: "dead",
      attempts: 2,
      lastError: "receiver unavailable",
    });
  });

  test("configuration changes cannot replace a delivery's URL, event, or secret snapshot", async () => {
    const calls: DispatchCall[] = [];
    const queue = queueWithDispatcher(async (event, webhook) => {
      calls.push({ event, config: webhook });
      return { success: true, attempts: 1, deliveredAt: new Date() };
    });

    const secretCase = await seedConfig();
    const secretSnapshot = await enqueueSnapshot(
      queue,
      secretCase.tenantId,
      secretCase.config,
      "original-delivery-secret",
    );
    await getDb()
      .update(webhookConfigs)
      .set({ secret: "replacement-database-secret" })
      .where(eq(webhookConfigs.id, secretCase.config.id));
    expect(await queue.processQueue()).toHaveLength(1);
    expect(calls.at(-1)?.config.secret).toBe("original-delivery-secret");

    for (const mutation of ["disabled", "url", "events", "deleted"] as const) {
      const seeded = await seedConfig();
      const { deliveryId } = await enqueueSnapshot(queue, seeded.tenantId, seeded.config);
      if (mutation === "disabled") {
        await getDb()
          .update(webhookConfigs)
          .set({ enabled: false })
          .where(eq(webhookConfigs.id, seeded.config.id));
      } else if (mutation === "url") {
        await getDb()
          .update(webhookConfigs)
          .set({ url: `https://changed-${randomUUID()}.example.test/hook` })
          .where(eq(webhookConfigs.id, seeded.config.id));
      } else if (mutation === "events") {
        await getDb()
          .update(webhookConfigs)
          .set({ events: ["tx_confirmed"] })
          .where(eq(webhookConfigs.id, seeded.config.id));
      } else {
        await getDb().delete(webhookConfigs).where(eq(webhookConfigs.id, seeded.config.id));
        await getDb()
          .insert(webhookConfigs)
          .values({
            tenantId: seeded.tenantId,
            url: seeded.config.url,
            secret: "replacement-config-secret",
            events: ["tx_signed"],
            enabled: true,
          });
      }
      const before = calls.length;
      const [result] = await queue.processQueue();
      expect(result).toMatchObject({ success: false, attempts: 1 });
      expect(calls).toHaveLength(before);
      expect(await queue.getDelivery(deliveryId)).toMatchObject({ status: "dead", attempts: 1 });
    }

    const deliveredRows = await getDb()
      .select({ id: webhookDeliveries.id })
      .from(webhookDeliveries)
      .where(
        and(
          eq(webhookDeliveries.tenantId, secretCase.tenantId),
          eq(webhookDeliveries.status, "delivered"),
        ),
      );
    expect(deliveredRows).toHaveLength(1);
    expect(secretSnapshot.deliveryId).toBe(deliveredRows[0]?.id);
  });
});

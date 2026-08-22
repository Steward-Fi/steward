import { describe, expect, it, mock } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";

// PersistentQueue talks to the DB through @stwd/db + drizzle-orm; mock both so
// poison-pill isolation remains runnable without a live database. Run this
// file in its own Bun isolate so its process-wide module mocks cannot replace
// the real-PostgreSQL authority suite's database module.
const webhookConfigRow = { id: "cfg-1", url: "https://receiver.example.com/hook", events: [] };
const updateSets: Record<string, unknown>[] = [];

const claimedRows = [
  {
    id: "delivery-poison",
    tenantId: "tenant-1",
    webhookConfigId: "cfg-1",
    agentId: "agent-1",
    eventType: "tx_signed",
    payload: {
      type: "tx_signed",
      tenantId: "tenant-1",
      agentId: "agent-1",
      data: {},
      timestamp: new Date("2026-05-30T09:00:00.000Z"),
    } satisfies WebhookEvent,
    url: webhookConfigRow.url,
    // Undecryptable: valid prefix, garbage payload (e.g. post key-rotation row).
    secret: "stwd_whsec_v1:{not-json",
    events: null,
    status: "processing",
    attempts: 1,
    maxAttempts: 5,
    nextRetryAt: new Date(),
  },
  {
    id: "delivery-good",
    tenantId: "tenant-1",
    webhookConfigId: "cfg-1",
    agentId: "agent-1",
    eventType: "tx_signed",
    payload: {
      type: "tx_signed",
      tenantId: "tenant-1",
      agentId: "agent-1",
      data: {},
      timestamp: new Date("2026-05-30T09:00:00.000Z"),
    } satisfies WebhookEvent,
    url: webhookConfigRow.url,
    secret: "whsec_plaintext",
    events: null,
    status: "processing",
    attempts: 1,
    maxAttempts: 5,
    nextRetryAt: new Date(),
  },
];

const db = {
  transaction: async (fn: (tx: { execute: () => Promise<unknown> }) => Promise<unknown>) =>
    fn({ execute: async () => claimedRows }),
  select: () => ({
    from: () => ({
      where: () => ({
        limit: () => Promise.resolve([webhookConfigRow]),
      }),
    }),
  }),
  update: () => ({
    set: (value: Record<string, unknown>) => {
      updateSets.push(value);
      return { where: () => Promise.resolve([{ id: "delivery-1", ...value }]) };
    },
  }),
};

mock.module("@stwd/db", () => ({
  getDb: () => db,
  webhookConfigs: { id: "id", tenantId: "tenantId", url: "url", events: "events", enabled: "on" },
  webhookDeliveries: {
    id: "id",
    status: "status",
    attempts: "attempts",
    nextRetryAt: "nextRetryAt",
    tenantId: "tenantId",
  },
}));
mock.module("drizzle-orm", () => ({
  and: () => true,
  eq: () => true,
  sql: () => ({}),
}));

const dispatchCalls: { url: string; secret: string }[] = [];
const stubDispatcher = {
  dispatch: async (_event: WebhookEvent, config: { url: string; secret: string }) => {
    dispatchCalls.push({ url: config.url, secret: config.secret });
    return { success: true, attempts: 1, deliveredAt: new Date() };
  },
};

const { PersistentQueue } = await import("../persistent-queue");
const { WebhookDispatcher } = await import("../dispatcher");

describe("PersistentQueue poison-pill isolation", () => {
  it("dead-letters an undecryptable secret and still processes the rest of the batch", async () => {
    const queue = new PersistentQueue(
      stubDispatcher as unknown as InstanceType<typeof WebhookDispatcher>,
      { batchSize: 10 },
    );

    // Without per-delivery isolation the decrypt throw rejects processQueue().
    const results = await queue.processQueue();

    expect(results).toHaveLength(2);
    const [poison, good] = results;
    expect(poison).toMatchObject({ success: false, attempts: 1 });
    expect(poison?.error).toBeDefined();
    expect(good).toMatchObject({ success: true, attempts: 1 });

    // The poisoned row is dead-lettered with its attempts incremented…
    const deadUpdate = updateSets.find((set) => set.status === "dead");
    expect(deadUpdate).toMatchObject({ attempts: 1 });
    expect(String(deadUpdate?.lastError)).toContain("failed deterministically");
    // …and a delivered update is recorded for the healthy row.
    expect(updateSets.some((set) => set.status === "delivered" && set.attempts === 1)).toBe(true);

    // The poisoned row never reaches the dispatcher; the healthy one does.
    expect(dispatchCalls).toHaveLength(1);
    expect(dispatchCalls[0]?.secret).toBe("whsec_plaintext");
  });
});

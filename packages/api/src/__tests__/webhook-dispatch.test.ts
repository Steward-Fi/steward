import { beforeEach, describe, expect, it, mock } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";

type StoredWebhookConfig = {
  tenantId: string;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
  maxRetries: number;
  retryBackoffMs: number;
};

type DispatchRecord = {
  event: WebhookEvent;
  webhook: { url: string; secret: string; events?: string[] } | string;
};
type DispatcherOptions = { maxRetries?: number; retryDelayMs?: number };
type DispatchResult = {
  success: boolean;
  attempts: number;
  deliveredAt?: Date;
  error?: string;
};

const webhookRows: StoredWebhookConfig[] = [];
const insertedDeliveries: Record<string, unknown>[] = [];
const updatedDeliveries: Record<string, unknown>[] = [];
const dispatches: DispatchRecord[] = [];
const dispatcherOptions: DispatcherOptions[] = [];
let nextDispatchResult: DispatchResult = {
  success: true,
  attempts: 1,
  deliveredAt: new Date("2026-05-20T00:00:00Z"),
};

const db = {
  select: () => ({
    from: () => ({
      where: () => Promise.resolve(webhookRows.filter((row) => row.enabled)),
    }),
  }),
  insert: () => ({
    values: (value: Record<string, unknown>) => {
      insertedDeliveries.push(value);
      return { returning: () => Promise.resolve([{ id: "delivery-1" }]) };
    },
  }),
  update: () => ({
    set: (value: Record<string, unknown>) => {
      updatedDeliveries.push(value);
      return { where: () => Promise.resolve([]) };
    },
  }),
};

mock.module("../services/context", () => ({ db }));
mock.module("@stwd/db", () => ({
  and: () => true,
  eq: () => true,
  webhookConfigs: { tenantId: "tenantId", enabled: "enabled" },
  webhookDeliveries: { id: "id" },
}));
mock.module("@stwd/webhooks", () => ({
  decryptWebhookSecret: (secret: string) => secret,
  encryptWebhookSecret: (secret: string) => secret,
  isEncryptedWebhookSecret: () => true,
  WebhookDispatcher: class {
    constructor(options: DispatcherOptions) {
      dispatcherOptions.push(options);
    }

    async dispatch(
      event: WebhookEvent,
      webhook: { url: string; secret: string; events?: string[] } | string,
    ) {
      dispatches.push({ event, webhook });
      return nextDispatchResult;
    }
  },
}));

const { dispatchWebhook } = await import("../services/webhook-dispatch");

beforeEach(() => {
  webhookRows.length = 0;
  insertedDeliveries.length = 0;
  updatedDeliveries.length = 0;
  dispatches.length = 0;
  dispatcherOptions.length = 0;
  nextDispatchResult = {
    success: true,
    attempts: 1,
    deliveredAt: new Date("2026-05-20T00:00:00Z"),
  };
});

describe("dispatchWebhook", () => {
  it("dispatches subscribed persisted webhook configs with their own secret", async () => {
    webhookRows.push(
      {
        tenantId: "tenant-1",
        url: "https://example.com/signed",
        secret: "whsec_signed",
        events: ["tx.signed"],
        enabled: true,
        maxRetries: 2,
        retryBackoffMs: 1000,
      },
      {
        tenantId: "tenant-1",
        url: "https://example.com/pending",
        secret: "whsec_pending",
        events: ["tx.pending"],
        enabled: true,
        maxRetries: 2,
        retryBackoffMs: 1000,
      },
    );

    dispatchWebhook("tenant-1", "agent-1", "tx_signed", { txId: "tx-1" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches).toHaveLength(1);
    expect(dispatcherOptions[0]).toEqual({ maxRetries: 0, retryDelayMs: 0 });
    expect(dispatches[0]?.event.type).toBe("tx.signed");
    expect(dispatches[0]?.event.deliveryId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(dispatches[0]?.webhook).toMatchObject({
      url: "https://example.com/signed",
      secret: "whsec_signed",
    });
    expect(insertedDeliveries[0]).toMatchObject({
      tenantId: "tenant-1",
      agentId: "agent-1",
      eventType: "tx.signed",
      url: "https://example.com/signed",
      status: "processing",
      id: dispatches[0]?.event.deliveryId,
      payload: expect.objectContaining({ deliveryId: dispatches[0]?.event.deliveryId }),
    });
    expect(insertedDeliveries[0]?.nextRetryAt).toBeInstanceOf(Date);
    expect((insertedDeliveries[0]?.nextRetryAt as Date).getTime()).toBeGreaterThan(Date.now());
    expect(updatedDeliveries[0]).toMatchObject({
      status: "delivered",
      attempts: 1,
      lastError: null,
    });
  });

  it("does not sleep through configured retries in the API dispatch path", async () => {
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/fails",
      secret: "whsec_fails",
      events: ["tx.signed"],
      enabled: true,
      maxRetries: 10,
      retryBackoffMs: 3_600_000,
    });
    nextDispatchResult = {
      success: false,
      attempts: 1,
      error: "Webhook responded with status 500",
    };

    const before = Date.now();
    dispatchWebhook("tenant-1", "agent-1", "tx_signed", { txId: "tx-1" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatcherOptions[0]).toEqual({ maxRetries: 0, retryDelayMs: 0 });
    expect(updatedDeliveries[0]).toMatchObject({
      status: "pending",
      attempts: 1,
      lastError: "Webhook responded with status 500",
    });
    expect(updatedDeliveries[0]?.nextRetryAt).toBeInstanceOf(Date);
    expect((updatedDeliveries[0]?.nextRetryAt as Date).getTime()).toBeGreaterThanOrEqual(
      before + 3_600_000,
    );
  });

  it("dispatches unsupported legacy events only to tenant-wide persisted webhooks", async () => {
    webhookRows.push(
      {
        tenantId: "tenant-1",
        url: "https://example.com/specific",
        secret: "whsec_specific",
        events: ["tx.signed"],
        enabled: true,
        maxRetries: 2,
        retryBackoffMs: 1000,
      },
      {
        tenantId: "tenant-1",
        url: "https://tenant-config.example.com/hook",
        secret: "whsec_legacy",
        events: [],
        enabled: true,
        maxRetries: 2,
        retryBackoffMs: 1000,
      },
    );

    dispatchWebhook("tenant-1", "agent-1", "unknown.event" as never, { txId: "tx-1" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]?.event.type).toBe("unknown.event");
    expect(dispatches[0]?.webhook).toMatchObject({
      url: "https://tenant-config.example.com/hook",
      secret: "whsec_legacy",
    });
    expect(insertedDeliveries[0]).toMatchObject({
      eventType: "unknown.event",
      url: "https://tenant-config.example.com/hook",
    });
  });

  it("maps legacy failed and confirmed events to configured transaction lifecycle events", async () => {
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/transactions",
      secret: "whsec_transactions",
      events: ["transaction.failed", "transaction.confirmed"],
      enabled: true,
      maxRetries: 2,
      retryBackoffMs: 1000,
    });

    dispatchWebhook("tenant-1", "agent-1", "tx_failed", { txId: "tx-1" });
    dispatchWebhook("tenant-1", "agent-1", "tx_confirmed", { txId: "tx-2" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches.map((record) => record.event.type)).toEqual([
      "transaction.failed",
      "transaction.confirmed",
    ]);
    expect(insertedDeliveries.map((delivery) => delivery.eventType)).toEqual([
      "transaction.failed",
      "transaction.confirmed",
    ]);
  });

  it("dispatches newly cataloged events to matching configured subscriptions", async () => {
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/actions",
      secret: "whsec_actions",
      events: ["wallet_action.swap.succeeded"],
      enabled: true,
      maxRetries: 2,
      retryBackoffMs: 1000,
    });

    dispatchWebhook("tenant-1", "agent-1", "wallet_action.swap.succeeded", {
      walletActionId: "action-1",
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]?.event.type).toBe("wallet_action.swap.succeeded");
    expect(insertedDeliveries[0]).toMatchObject({
      eventType: "wallet_action.swap.succeeded",
      url: "https://example.com/actions",
    });
  });
});

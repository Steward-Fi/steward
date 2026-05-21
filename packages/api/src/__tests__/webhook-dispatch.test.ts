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

const webhookRows: StoredWebhookConfig[] = [];
const insertedDeliveries: Record<string, unknown>[] = [];
const updatedDeliveries: Record<string, unknown>[] = [];
const dispatches: DispatchRecord[] = [];
const tenantConfigs = new Map<string, { webhookUrl?: string }>();

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

mock.module("../services/context", () => ({ db, tenantConfigs }));
mock.module("@stwd/db", () => ({
  and: () => true,
  eq: () => true,
  webhookConfigs: { tenantId: "tenantId", enabled: "enabled" },
  webhookDeliveries: { id: "id" },
}));
mock.module("@stwd/webhooks", () => ({
  WebhookDispatcher: class {
    async dispatch(
      event: WebhookEvent,
      webhook: { url: string; secret: string; events?: string[] } | string,
    ) {
      dispatches.push({ event, webhook });
      return { success: true, attempts: 1, deliveredAt: new Date("2026-05-20T00:00:00Z") };
    }
  },
}));

const { dispatchWebhook } = await import("../services/webhook-dispatch");

beforeEach(() => {
  webhookRows.length = 0;
  insertedDeliveries.length = 0;
  updatedDeliveries.length = 0;
  dispatches.length = 0;
  tenantConfigs.clear();
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
    expect(dispatches[0]?.event.type).toBe("tx.signed");
    expect(dispatches[0]?.webhook).toMatchObject({
      url: "https://example.com/signed",
      secret: "whsec_signed",
    });
    expect(insertedDeliveries[0]).toMatchObject({
      tenantId: "tenant-1",
      agentId: "agent-1",
      eventType: "tx.signed",
      url: "https://example.com/signed",
      status: "pending",
    });
    expect(updatedDeliveries[0]).toMatchObject({
      status: "delivered",
      attempts: 1,
      lastError: null,
    });
  });

  it("preserves tenant config webhook dispatch for unsupported configured events", async () => {
    tenantConfigs.set("tenant-1", { webhookUrl: "https://tenant-config.example.com/hook" });

    dispatchWebhook("tenant-1", "agent-1", "tx_failed", { txId: "tx-1" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(insertedDeliveries).toHaveLength(0);
    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]?.event.type).toBe("tx_failed");
    expect(dispatches[0]?.webhook).toBe("https://tenant-config.example.com/hook");
  });
});

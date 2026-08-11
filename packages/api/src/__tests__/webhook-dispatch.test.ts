import { afterAll, beforeEach, describe, expect, it, mock } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";
// Captured before mock.module replaces @stwd/webhooks, so these hold the REAL
// secret-codec functions; the mock re-exports them so dispatched secrets keep
// the real `stwd_whsec_v1:` envelope format.
import {
  decryptWebhookSecret,
  encryptWebhookSecret,
  isEncryptedWebhookSecret,
} from "@stwd/webhooks";

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
const tenantConfigs = new Map<string, { webhookUrl?: string }>();
let nextDispatchResult: DispatchResult = {
  success: true,
  attempts: 1,
  deliveredAt: new Date("2026-05-20T00:00:00Z"),
};

process.env.STEWARD_MASTER_PASSWORD = "webhook-dispatch-test-master-password";

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
      // `.where()` is awaited directly in some paths and chained with
      // `.returning()` in others (delivery status updates), so support both.
      const rows = [{ id: "delivery-1", ...value }];
      return {
        where: () => {
          const result = Promise.resolve(rows) as Promise<typeof rows> & {
            returning: () => Promise<typeof rows>;
          };
          result.returning = () => Promise.resolve(rows);
          return result;
        },
      };
    },
  }),
};

// webhook-dispatch.ts imports `{ db, tenantConfigs }` from context — the mock
// must provide both, or the named-export load fails.
mock.module("../services/context", () => ({ db, tenantConfigs }));
mock.module("@stwd/db", () => ({
  and: () => true,
  eq: () => true,
  webhookConfigs: { tenantId: "tenantId", enabled: "enabled" },
  webhookDeliveries: { id: "id" },
}));
// NOTE: bun's mock.module replaces the ENTIRE module and is sticky per-process,
// so this mock must re-export every binding the module-under-test (and any
// sibling test running in the same process) imports from @stwd/webhooks.
// Omitting the secret-codec helpers previously cascaded into "export not found"
// failures across the webhook + approvals API suites. We mock only the
// dispatcher and pass the real secret-codec functions through.
mock.module("@stwd/webhooks", () => ({
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
  decryptWebhookSecret,
  encryptWebhookSecret,
  isEncryptedWebhookSecret,
}));

const { dispatchWebhook } = await import("../services/webhook-dispatch");
const { webhookEventRegistry } = await import("../services/webhook-events");

beforeEach(() => {
  webhookRows.length = 0;
  insertedDeliveries.length = 0;
  updatedDeliveries.length = 0;
  dispatches.length = 0;
  dispatcherOptions.length = 0;
  tenantConfigs.clear();
  nextDispatchResult = {
    success: true,
    attempts: 1,
    deliveredAt: new Date("2026-05-20T00:00:00Z"),
  };
});

afterAll(() => {
  delete process.env.STEWARD_MASTER_PASSWORD;
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
    // New delivery lifecycle: the row is inserted as "processing" first, then
    // updated to "delivered" after the dispatcher returns. The persisted secret is
    // re-encrypted at rest (stwd_whsec_v1 envelope) even when the config supplied
    // a plaintext secret.
    expect(insertedDeliveries[0]).toMatchObject({
      tenantId: "tenant-1",
      agentId: "agent-1",
      eventType: "tx.signed",
      url: "https://example.com/signed",
      status: "processing",
      attempts: 0,
      id: dispatches[0]?.event.deliveryId,
      payload: expect.objectContaining({ deliveryId: dispatches[0]?.event.deliveryId }),
    });
    expect(insertedDeliveries[0]?.secret).toMatch(/^stwd_whsec_v1:/);
    expect(insertedDeliveries[0]?.nextRetryAt).toBeInstanceOf(Date);
    expect((insertedDeliveries[0]?.nextRetryAt as Date).getTime()).toBeGreaterThan(Date.now());
    // The new code issues two updates: one to re-encrypt the config secret at rest
    // and one to mark the delivery delivered. Assert against the delivery-status
    // update specifically rather than a positional index.
    const deliveredUpdate = updatedDeliveries.find((u) => u.status === "delivered");
    expect(deliveredUpdate).toMatchObject({
      status: "delivered",
      attempts: 1,
      lastError: null,
    });
  });

  it("routes aliased failed transaction lifecycle events to configured subscribers and redacts payloads", async () => {
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/failed",
      secret: "whsec_failed",
      events: ["transaction.failed"],
      enabled: true,
      maxRetries: 2,
      retryBackoffMs: 1000,
    });
    tenantConfigs.set("tenant-1", { webhookUrl: "https://tenant-config.example.com/hook" });

    dispatchWebhook("tenant-1", "agent-1", "tx_failed", {
      txId: "tx-1",
      transaction_id: "tx-1",
      status: "failed",
      error: {
        message: "provider rejected",
        privateKey: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      },
      replacement: {
        secret: "should-not-leak",
      },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(insertedDeliveries).toHaveLength(1);
    expect(dispatches).toHaveLength(2);
    expect(insertedDeliveries[0]).toMatchObject({
      tenantId: "tenant-1",
      agentId: "agent-1",
      eventType: "transaction.failed",
      url: "https://example.com/failed",
    });
    expect(insertedDeliveries[0]?.payload).toMatchObject({
      type: "transaction.failed",
      data: {
        txId: "tx-1",
        transaction_id: "tx-1",
        status: "failed",
        error: {
          message: "provider rejected",
          privateKey: "[REDACTED]",
        },
        replacement: {
          secret: "[REDACTED]",
        },
      },
    });
    const configuredDispatch = dispatches.find(
      (dispatch) => dispatch.event.type === "transaction.failed",
    );
    const legacyDispatch = dispatches.find((dispatch) => dispatch.event.type === "tx_failed");
    expect(configuredDispatch?.event).toMatchObject({
      type: "transaction.failed",
      data: {
        error: { privateKey: "[REDACTED]" },
        replacement: { secret: "[REDACTED]" },
      },
    });
    expect(legacyDispatch?.event).toMatchObject({
      type: "tx_failed",
      data: {
        error: { privateKey: "[REDACTED]" },
        replacement: { secret: "[REDACTED]" },
      },
    });
    expect(JSON.stringify(insertedDeliveries)).not.toContain(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    expect(JSON.stringify(dispatches)).not.toContain("should-not-leak");
  });

  it("preserves tenant config webhook dispatch when no configured webhook accepts an event", async () => {
    tenantConfigs.set("tenant-1", { webhookUrl: "https://tenant-config.example.com/hook" });

    dispatchWebhook("tenant-1", "agent-1", "tx_unknown_state", { txId: "tx-1" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches).toHaveLength(1);
    expect(dispatches[0]?.event.type).toBe("tx_unknown_state");
    expect(dispatches[0]?.webhook).toBe("https://tenant-config.example.com/hook");
  });

  // ── Phase 2b: plugin-declared event emission ───────────────────────────────
  it("emits a PLUGIN-declared event to a config that subscribes to it", async () => {
    // a plugin registered this event name into the runtime registry at compose
    // time (host.register merges StewardPlugin.webhookEvents). The core's closed
    // union never enumerates it, but the configured fan-out must still deliver it
    // to a subscriber that lists it.
    webhookEventRegistry.registerPluginEvents("demo-plugin", ["demo.thing.happened"]);
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/plugin-sub",
      secret: "whsec_plugin",
      events: ["demo.thing.happened"],
      enabled: true,
      maxRetries: 0,
      retryBackoffMs: 0,
    });

    // cast: the typed API widens to (string & {}); a real plugin caller passes the
    // declared event name. it is registry-valid so it must be delivered.
    dispatchWebhook("tenant-1", "agent-1", "demo.thing.happened" as never, { foo: "bar" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    const pluginDispatch = dispatches.find((d) => d.event.type === "demo.thing.happened");
    expect(pluginDispatch).toBeDefined();
    expect(pluginDispatch?.webhook).toMatchObject({ url: "https://example.com/plugin-sub" });
  });

  it("does NOT deliver a plugin event to a config that does not subscribe to it", async () => {
    webhookEventRegistry.registerPluginEvents("demo-plugin", ["demo.thing.happened"]);
    webhookRows.push({
      tenantId: "tenant-1",
      url: "https://example.com/other-sub",
      secret: "whsec_other",
      events: ["tx.signed"], // subscribes to a different (core) event only
      enabled: true,
      maxRetries: 0,
      retryBackoffMs: 0,
    });

    dispatchWebhook("tenant-1", "agent-1", "demo.thing.happened" as never, { foo: "bar" });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(dispatches.find((d) => d.event.type === "demo.thing.happened")).toBeUndefined();
  });
});

import { describe, expect, it, mock, beforeEach } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";
import { RetryQueue } from "../queue";
import { WebhookDispatcher } from "../dispatcher";

const makeEvent = (overrides: Partial<WebhookEvent> = {}): WebhookEvent => ({
  type: "tx_signed",
  tenantId: "test-tenant",
  agentId: "test-agent",
  data: { txHash: "0xabc" },
  timestamp: new Date(),
  ...overrides,
});

const WEBHOOK = { url: "https://example.com/hook", secret: "test-secret" };

describe("RetryQueue", () => {
  it("should enqueue and process a delivery", async () => {
    // Create a dispatcher that always succeeds
    const dispatcher = new WebhookDispatcher({ maxRetries: 0, timeoutMs: 1000 });

    // Mock fetch to simulate success
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(() =>
      Promise.resolve(new Response("ok", { status: 200 }))
    ) as any;

    try {
      const queue = new RetryQueue(dispatcher, { maxRetries: 3, retryDelayMs: 100 });
      const event = makeEvent();

      const id = queue.enqueue(event, WEBHOOK);
      expect(id).toBeTruthy();

      const stats = queue.getStats();
      expect(stats.pending).toBe(1);
      expect(stats.delivered).toBe(0);

      const results = await queue.processQueue();
      expect(results.length).toBe(1);
      expect(results[0].success).toBe(true);

      const statsAfter = queue.getStats();
      expect(statsAfter.pending).toBe(0);
      expect(statsAfter.delivered).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should retry failed deliveries up to maxRetries", async () => {
    const dispatcher = new WebhookDispatcher({ maxRetries: 0, timeoutMs: 100 });

    // Mock fetch to always fail
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(() =>
      Promise.resolve(new Response("error", { status: 500 }))
    ) as any;

    try {
      const queue = new RetryQueue(dispatcher, { maxRetries: 2, retryDelayMs: 10 });
      const event = makeEvent();

      queue.enqueue(event, WEBHOOK);

      // First attempt — fails, retries scheduled
      let results = await queue.processQueue();
      expect(results[0].success).toBe(false);
      expect(queue.getStats().pending).toBe(1);

      // Wait for retry delay
      await new Promise((r) => setTimeout(r, 20));

      // Second attempt — still fails, exhausted
      results = await queue.processQueue();
      expect(results[0].success).toBe(false);

      const stats = queue.getStats();
      expect(stats.pending).toBe(0);
      expect(stats.failed).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should not process deliveries before their retry time", async () => {
    const dispatcher = new WebhookDispatcher({ maxRetries: 0, timeoutMs: 100 });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(() =>
      Promise.resolve(new Response("error", { status: 500 }))
    ) as any;

    try {
      const queue = new RetryQueue(dispatcher, { maxRetries: 3, retryDelayMs: 5000 });
      const event = makeEvent();

      queue.enqueue(event, WEBHOOK);

      // First attempt fails
      await queue.processQueue();
      expect(queue.getStats().pending).toBe(1);

      // Immediate second process — should skip because retryDelay is 5s
      const results = await queue.processQueue();
      expect(results.length).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("should handle multiple enqueued events", async () => {
    const dispatcher = new WebhookDispatcher({ maxRetries: 0, timeoutMs: 1000 });

    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock(() =>
      Promise.resolve(new Response("ok", { status: 200 }))
    ) as any;

    try {
      const queue = new RetryQueue(dispatcher, { maxRetries: 3 });

      queue.enqueue(makeEvent({ agentId: "agent-1" }), WEBHOOK);
      queue.enqueue(makeEvent({ agentId: "agent-2" }), WEBHOOK);
      queue.enqueue(makeEvent({ agentId: "agent-3" }), WEBHOOK);

      expect(queue.getStats().pending).toBe(3);

      const results = await queue.processQueue();
      expect(results.length).toBe(3);
      expect(results.every((r) => r.success)).toBe(true);

      expect(queue.getStats().delivered).toBe(3);
      expect(queue.getStats().pending).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

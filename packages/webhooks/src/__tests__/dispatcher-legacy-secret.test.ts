import { describe, expect, it } from "bun:test";
import type { WebhookEvent } from "@stwd/shared";
import { WebhookDispatcher } from "../dispatcher";

const makeEvent = (tenantId: string): WebhookEvent => ({
  type: "tx_signed",
  tenantId,
  agentId: "agent-a",
  data: { txHash: "0xabc" },
  timestamp: new Date("2026-05-30T09:00:00.000Z"),
});

describe("WebhookDispatcher legacy string-URL configuration (SEC-101)", () => {
  it("rejects a bare URL before network access even when the old master secret is set", async () => {
    const original = process.env.STEWARD_WEBHOOK_SECRET;
    process.env.STEWARD_WEBHOOK_SECRET = "legacy-global-master";
    let lookupCalls = 0;
    const dispatcher = new WebhookDispatcher({
      maxRetries: 3,
      lookup: (_hostname, _options, callback) => {
        lookupCalls += 1;
        callback(null, "203.0.113.10", 4);
      },
    });
    try {
      await expect(
        dispatcher.dispatch(makeEvent("tenant-a"), "https://example.com/hook"),
      ).rejects.toThrow("Legacy string webhook configuration is not supported");
      expect(lookupCalls).toBe(0);
    } finally {
      if (original === undefined) delete process.env.STEWARD_WEBHOOK_SECRET;
      else process.env.STEWARD_WEBHOOK_SECRET = original;
    }
  });
});

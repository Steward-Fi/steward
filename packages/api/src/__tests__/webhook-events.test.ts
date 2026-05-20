import { describe, expect, it } from "bun:test";
import {
  acceptsConfiguredWebhookEvent,
  toConfiguredWebhookEventType,
} from "../services/webhook-events";

describe("webhook event routing", () => {
  it("keeps public configured event names unchanged", () => {
    expect(toConfiguredWebhookEventType("tx.pending")).toBe("tx.pending");
    expect(toConfiguredWebhookEventType("tx.approved")).toBe("tx.approved");
    expect(toConfiguredWebhookEventType("tx.denied")).toBe("tx.denied");
    expect(toConfiguredWebhookEventType("tx.signed")).toBe("tx.signed");
    expect(toConfiguredWebhookEventType("policy.violation")).toBe("policy.violation");
  });

  it("maps vault event aliases to the configured webhook contract", () => {
    expect(toConfiguredWebhookEventType("approval_required")).toBe("tx.pending");
    expect(toConfiguredWebhookEventType("tx_signed")).toBe("tx.signed");
    expect(toConfiguredWebhookEventType("tx_rejected")).toBe("policy.violation");
  });

  it("does not invent configured events for unsupported vault states", () => {
    expect(toConfiguredWebhookEventType("tx_failed")).toBeNull();
    expect(toConfiguredWebhookEventType("tx_confirmed")).toBeNull();
  });

  it("treats an empty subscription list as all events", () => {
    expect(acceptsConfiguredWebhookEvent([], "tx.signed")).toBe(true);
  });

  it("filters configured subscriptions by event type", () => {
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.pending")).toBe(true);
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.signed")).toBe(false);
  });
});

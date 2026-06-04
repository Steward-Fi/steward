import { describe, expect, it } from "bun:test";
import {
  acceptsConfiguredWebhookEvent,
  CONFIGURED_WEBHOOK_EVENT_TYPES,
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

  it("exposes Privy-like event categories as configurable subscriptions", () => {
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("user.created");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("mfa.enabled");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("private_key.exported");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet.recovery_setup");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet.recovered");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet.raw_signature.created");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet.funds_deposited");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet.funds_withdrawn");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("transaction.broadcasted");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("transaction.still_pending");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("user_operation.completed");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("user_operation.failed");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("intent.authorized");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet_action.transfer.succeeded");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet_action.send_calls.created");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet_action.swap.failed");
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("wallet_action.earn_deposit.rejected");
  });

  it("maps vault event aliases to the configured webhook contract", () => {
    expect(toConfiguredWebhookEventType("approval_required")).toBe("tx.pending");
    expect(toConfiguredWebhookEventType("tx_signed")).toBe("tx.signed");
    expect(toConfiguredWebhookEventType("tx_confirmed")).toBe("transaction.confirmed");
    expect(toConfiguredWebhookEventType("tx_failed")).toBe("transaction.failed");
    expect(toConfiguredWebhookEventType("tx_rejected")).toBe("policy.violation");
  });

  it("maps tx_failed and tx_confirmed to their configured webhook events", () => {
    // Wave D added explicit mappings for these vault states.
    expect(toConfiguredWebhookEventType("tx_failed")).toBe("transaction.failed");
    expect(toConfiguredWebhookEventType("tx_confirmed")).toBe("transaction.confirmed");
  });

  it("returns null for genuinely unsupported vault states", () => {
    expect(toConfiguredWebhookEventType("tx_unknown_state")).toBeNull();
    expect(toConfiguredWebhookEventType("")).toBeNull();
  });

  it("treats an empty subscription list as all events", () => {
    expect(acceptsConfiguredWebhookEvent([], "tx.signed")).toBe(true);
  });

  it("filters configured subscriptions by event type", () => {
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.pending")).toBe(true);
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.signed")).toBe(false);
  });
});

import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  acceptsConfiguredWebhookEvent,
  CONFIGURED_WEBHOOK_EVENT_TYPES,
  toConfiguredWebhookEventType,
} from "../services/webhook-events";

const authSource = readFileSync(join(import.meta.dir, "..", "routes", "auth.ts"), "utf8");

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
    expect(CONFIGURED_WEBHOOK_EVENT_TYPES).toContain("user.wallet_created");
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

  it("treats an empty subscription list as all events", () => {
    expect(acceptsConfiguredWebhookEvent([], "tx.signed")).toBe(true);
  });

  it("filters configured subscriptions by event type", () => {
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.pending")).toBe(true);
    expect(acceptsConfiguredWebhookEvent(["tx.pending"], "tx.signed")).toBe(false);
  });

  it("denies user-id auth-abuse policy before successful login audit and webhook dispatch", () => {
    const functionStart = authSource.indexOf("async function buildAuthOrMfaResponse");
    expect(functionStart).toBeGreaterThanOrEqual(0);
    const functionEnd = authSource.indexOf("function authExchangeJson", functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const body = authSource.slice(functionStart, functionEnd);

    const policyCheck = body.indexOf("validateUserAbusePolicy(userId, authAbuseConfig)");
    const denialReturn = body.indexOf("return { ok: false, status: 403, error: userPolicyError }");
    const successAudit = body.indexOf('action: "auth.login"');
    const sessionIssue = body.indexOf("const token = await createSessionToken");
    const authenticatedWebhook = body.indexOf("dispatchUserAuthenticated(");

    expect(policyCheck).toBeGreaterThanOrEqual(0);
    expect(denialReturn).toBeGreaterThan(policyCheck);
    expect(successAudit).toBeGreaterThan(denialReturn);
    expect(sessionIssue).toBeGreaterThan(denialReturn);
    expect(authenticatedWebhook).toBeGreaterThan(denialReturn);
  });
});

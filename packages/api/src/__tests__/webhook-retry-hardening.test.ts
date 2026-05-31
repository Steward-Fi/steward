import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const apiRoot = join(import.meta.dir, "..");
const webhookRoutesSource = readFileSync(join(apiRoot, "routes", "webhooks.ts"), "utf8");
const tenantRoutesSource = readFileSync(join(apiRoot, "routes", "tenants.ts"), "utf8");
const webhookDispatchSource = readFileSync(
  join(apiRoot, "services", "webhook-dispatch.ts"),
  "utf8",
);
const apiIndexSource = readFileSync(join(apiRoot, "index.ts"), "utf8");
const webhookRetrySchedulerSource = readFileSync(
  join(apiRoot, "services", "webhook-retry-scheduler.ts"),
  "utf8",
);

describe("webhook retry hardening", () => {
  it("does not allow manual retries after the webhook URL has changed", () => {
    const retryStart = webhookRoutesSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryStart).toBeGreaterThanOrEqual(0);
    const urlSelect = webhookRoutesSource.indexOf("url: webhookConfigs.url", retryStart);
    const urlMismatch = webhookRoutesSource.indexOf(
      "activeWebhook.url !== delivery.url",
      retryStart,
    );
    const mutation = webhookRoutesSource.indexOf(".update(webhookDeliveries)", retryStart);
    expect(urlSelect).toBeGreaterThan(retryStart);
    expect(urlMismatch).toBeGreaterThan(urlSelect);
    expect(urlMismatch).toBeLessThan(mutation);
  });

  it("does not allow manual retries after the webhook unsubscribes from the event", () => {
    const retryStart = webhookRoutesSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryStart).toBeGreaterThanOrEqual(0);
    const eventsSelect = webhookRoutesSource.indexOf("events: webhookConfigs.events", retryStart);
    const subscriptionCheck = webhookRoutesSource.indexOf(
      "currentWebhookAcceptsDelivery(activeWebhook.events, delivery.eventType)",
      retryStart,
    );
    const mutation = webhookRoutesSource.indexOf(".update(webhookDeliveries)", retryStart);
    expect(eventsSelect).toBeGreaterThan(retryStart);
    expect(subscriptionCheck).toBeGreaterThan(eventsSelect);
    expect(subscriptionCheck).toBeLessThan(mutation);
    expect(webhookRoutesSource).toContain(
      "Delivery cannot be retried because the webhook no longer subscribes to this event",
    );
  });

  it("does not allow manual retries after the retry budget is exhausted", () => {
    const retryStart = webhookRoutesSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryStart).toBeGreaterThanOrEqual(0);
    const exhausted = webhookRoutesSource.indexOf(
      "delivery.attempts >= delivery.maxAttempts",
      retryStart,
    );
    const mutation = webhookRoutesSource.indexOf(".update(webhookDeliveries)", retryStart);
    expect(exhausted).toBeGreaterThan(retryStart);
    expect(exhausted).toBeLessThan(mutation);
    expect(webhookRoutesSource).toContain("Delivery retry budget has been exhausted");
  });

  it("does not allow manual retries while a delivery is claimed by a worker", () => {
    const retryStart = webhookRoutesSource.indexOf('webhookRoutes.post("/deliveries/:id/retry"');
    expect(retryStart).toBeGreaterThanOrEqual(0);
    const inFlightCheck = webhookRoutesSource.indexOf(
      'delivery.status === "processing"',
      retryStart,
    );
    const mutation = webhookRoutesSource.indexOf(".update(webhookDeliveries)", retryStart);
    expect(inFlightCheck).toBeGreaterThan(retryStart);
    expect(inFlightCheck).toBeLessThan(mutation);
    expect(webhookRoutesSource).toContain("Delivery is currently in flight");
    expect(webhookRoutesSource).toContain("${webhookDeliveries.status} = 'processing'");
  });

  it("writes webhook creation authorization before insert and enables only after create audit", () => {
    const createStart = webhookRoutesSource.indexOf('webhookRoutes.post("/",');
    expect(createStart).toBeGreaterThanOrEqual(0);
    const authorized = webhookRoutesSource.indexOf(
      'action: "webhook.create.authorized"',
      createStart,
    );
    const insert = webhookRoutesSource.indexOf(".insert(webhookConfigs)", createStart);
    const disabledInsert = webhookRoutesSource.indexOf("enabled: false", insert);
    const created = webhookRoutesSource.indexOf('action: "webhook.create"', insert);
    const enable = webhookRoutesSource.indexOf(".update(webhookConfigs)", created);
    expect(authorized).toBeGreaterThan(createStart);
    expect(authorized).toBeLessThan(insert);
    expect(disabledInsert).toBeGreaterThan(insert);
    expect(created).toBeGreaterThan(insert);
    expect(enable).toBeGreaterThan(created);
  });

  it("encrypts legacy tenant webhook secrets before storing them", () => {
    expect(tenantRoutesSource).toContain('import { encryptWebhookSecret } from "@stwd/webhooks"');
    expect(tenantRoutesSource).toContain("secret: encryptWebhookSecret(generateWebhookSecret())");
    expect(tenantRoutesSource).not.toContain("secret: generateWebhookSecret()");
  });

  it("does not copy legacy plaintext webhook secrets into delivery snapshots", () => {
    expect(webhookDispatchSource).toContain("isEncryptedWebhookSecret(config.secret)");
    expect(webhookDispatchSource).toContain("encryptWebhookSecret(signingSecret)");
    const insertSnapshot = webhookDispatchSource.slice(
      webhookDispatchSource.indexOf(".insert(webhookDeliveries)"),
      webhookDispatchSource.indexOf("const dispatcher = new WebhookDispatcher"),
    );
    expect(insertSnapshot).toContain("secret: encryptedSecret");
    expect(insertSnapshot).not.toContain("secret: config.secret");
  });

  it("starts a persistent webhook retry scheduler in the long-lived API runtime", () => {
    expect(apiIndexSource).toContain("import { startWebhookRetryScheduler }");
    expect(apiIndexSource).toContain("cancelWebhookRetryScheduler = startWebhookRetryScheduler()");
    expect(apiIndexSource).toContain(
      "if (cancelWebhookRetryScheduler) cancelWebhookRetryScheduler()",
    );
    expect(webhookRetrySchedulerSource).toContain("new PersistentQueue");
    expect(webhookRetrySchedulerSource).toContain(".processQueue()");
    expect(webhookRetrySchedulerSource).toContain("STEWARD_WEBHOOK_RETRY_WORKER");
  });
});

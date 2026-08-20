import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type WebhookDelivery = {
  id: string;
  eventType: string;
  replayedFromDeliveryId?: string | null;
  status: "pending" | "processing" | "delivered" | "failed" | "dead";
  attempts: number;
  maxAttempts: number;
  nextRetryAt: string | null;
  hasError: boolean;
  createdAt: string;
  deliveredAt: string | null;
};

type WebhookConfig = {
  id: string;
  tenantId: string;
  url: string;
  events: string[];
  enabled: boolean;
  maxRetries: number;
  retryBackoffMs: number;
  description: string | null;
  secret?: string;
  createdAt: string;
  updatedAt: string;
};

test.describe("Dashboard webhook delivery history", () => {
  test.setTimeout(120_000);

  test("authenticated users can inspect and retry webhook deliveries", async ({
    page,
    request,
  }, testInfo) => {
    const email = `webhooks-${Date.now()}@example.test`;
    const webhooks: WebhookConfig[] = [
      {
        id: "webhook-1",
        tenantId: "e2e-tenant",
        url: "https://example.test/steward-webhooks",
        events: ["user.created", "transaction.confirmed"],
        enabled: true,
        maxRetries: 5,
        retryBackoffMs: 60000,
        description: "Production event sink",
        createdAt: "2026-05-28T10:00:00.000Z",
        updatedAt: "2026-05-28T10:00:00.000Z",
      },
    ];
    let deliveries: WebhookDelivery[] = [
      {
        id: "delivery-failed",
        eventType: "user.created",
        status: "failed",
        attempts: 1,
        maxAttempts: 6,
        nextRetryAt: "2026-05-28T12:30:00.000Z",
        hasError: true,
        createdAt: "2026-05-28T12:00:00.000Z",
        deliveredAt: null,
      },
      {
        id: "delivery-ok",
        eventType: "transaction.confirmed",
        status: "delivered",
        attempts: 1,
        maxAttempts: 6,
        nextRetryAt: null,
        hasError: false,
        createdAt: "2026-05-28T11:45:00.000Z",
        deliveredAt: "2026-05-28T11:45:01.000Z",
      },
    ];
    let lastDeliveryQuery = "";
    let webhookListRequestCount = 0;
    const deliveryRequestCounts = new Map<string, number>();
    let createPayload: { url: string; events: string[]; description?: string } | null = null;
    let deletedEndpointId = "";

    await page.route(`${API}/webhooks`, async (route) => {
      if (route.request().method() === "POST") {
        const body = route.request().postDataJSON() as {
          url: string;
          events: string[];
          description?: string;
        };
        createPayload = body;
        const created = {
          id: "webhook-created",
          tenantId: "e2e-tenant",
          url: body.url,
          events: body.events,
          enabled: true,
          maxRetries: 6,
          retryBackoffMs: 60000,
          description: body.description ?? null,
          secret: "whsec_created_once",
          createdAt: "2026-05-28T12:15:00.000Z",
          updatedAt: "2026-05-28T12:15:00.000Z",
        };
        webhooks.unshift(created);
        await route.fulfill({ json: { ok: true, data: created } });
        return;
      }
      if (route.request().method() === "GET") webhookListRequestCount += 1;
      await route.fulfill({
        json: {
          ok: true,
          data: webhooks,
        },
      });
    });

    await page.route(`${API}/webhooks/webhook-created`, async (route) => {
      if (route.request().method() === "DELETE") {
        deletedEndpointId = "webhook-created";
        const index = webhooks.findIndex((row) => row.id === "webhook-created");
        if (index >= 0) webhooks.splice(index, 1);
        await route.fulfill({ json: { ok: true } });
        return;
      }
      const body = route.request().postDataJSON() as { enabled?: boolean };
      const webhook = webhooks.find((row) => row.id === "webhook-created");
      if (webhook && typeof body.enabled === "boolean") webhook.enabled = body.enabled;
      await route.fulfill({ json: { ok: true, data: webhook } });
    });

    await page.route(`${API}/webhooks/webhook-1/deliveries**`, async (route) => {
      const params = new URL(route.request().url()).searchParams;
      if (new URL(route.request().url()).pathname.endsWith("/deliveries/export")) {
        lastDeliveryQuery = params.toString();
        await route.fulfill({
          status: 200,
          headers: {
            "content-type": "text/csv; charset=utf-8",
            "content-disposition": 'attachment; filename="webhook-deliveries-webhook-1.csv"',
          },
          body: 'id,eventType,status\n"delivery-failed","user.created","failed"\n',
        });
        return;
      }
      if (route.request().method() === "GET") {
        deliveryRequestCounts.set("webhook-1", (deliveryRequestCounts.get("webhook-1") ?? 0) + 1);
      }
      lastDeliveryQuery = params.toString();
      const status = params.get("status");
      const eventType = params.get("eventType");
      const hasError = params.get("hasError");
      const filtered = deliveries.filter((delivery) => {
        if (status && delivery.status !== status) return false;
        if (eventType && delivery.eventType !== eventType) return false;
        if (hasError === "true" && !delivery.hasError) return false;
        if (hasError === "false" && delivery.hasError) return false;
        return true;
      });
      await route.fulfill({ json: { ok: true, data: filtered } });
    });
    await page.route(`${API}/webhooks/webhook-created/deliveries**`, async (route) => {
      if (route.request().method() === "GET") {
        deliveryRequestCounts.set(
          "webhook-created",
          (deliveryRequestCounts.get("webhook-created") ?? 0) + 1,
        );
      }
      await route.fulfill({ json: { ok: true, data: [] } });
    });

    await page.route(`${API}/webhooks/deliveries/delivery-failed/retry`, async (route) => {
      let updated: WebhookDelivery | undefined;
      deliveries = deliveries.map((delivery) =>
        delivery.id === "delivery-failed"
          ? (updated = {
              ...delivery,
              status: "pending",
              nextRetryAt: "2026-05-28T12:35:00.000Z",
              hasError: false,
            })
          : delivery,
      );
      await route.fulfill({ json: { ok: true, data: updated } });
    });
    await page.route(`${API}/webhooks/deliveries/delivery-failed/replay`, async (route) => {
      const replayed: WebhookDelivery = {
        id: "delivery-replay",
        eventType: "user.created",
        replayedFromDeliveryId: "delivery-failed",
        status: "delivered",
        attempts: 1,
        maxAttempts: 6,
        nextRetryAt: null,
        hasError: false,
        createdAt: "2026-05-28T12:10:00.000Z",
        deliveredAt: "2026-05-28T12:10:01.000Z",
      };
      deliveries = [replayed, ...deliveries.filter((row) => row.id !== replayed.id)];
      await route.fulfill({ status: 202, json: { ok: true, data: replayed } });
    });
    await page.route(`${API}/webhooks/webhook-1/test`, async (route) => {
      const testDelivery: WebhookDelivery = {
        id: "delivery-test",
        eventType: "webhook.test",
        status: "delivered",
        attempts: 1,
        maxAttempts: 1,
        nextRetryAt: null,
        hasError: false,
        createdAt: "2026-05-28T12:20:00.000Z",
        deliveredAt: "2026-05-28T12:20:01.000Z",
      };
      deliveries = [testDelivery, ...deliveries.filter((row) => row.id !== testDelivery.id)];
      await route.fulfill({ status: 202, json: { ok: true, data: testDelivery } });
    });

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/webhooks`);
    await expect(page.getByRole("heading", { name: "Webhooks" })).toBeVisible();
    await expect(page.getByText("https://example.test/steward-webhooks").first()).toBeVisible();
    await expect(page.getByText("user.created").first()).toBeVisible();
    await expect(page.getByText("transaction.confirmed").first()).toBeVisible();
    expect(webhookListRequestCount).toBe(1);
    expect(deliveryRequestCounts.get("webhook-1")).toBe(1);

    await page
      .getByPlaceholder("https://api.example.com/webhooks/steward")
      .fill("https://hooks.example.test/steward");
    await page.getByPlaceholder("Production event sink").fill("Webhook page create test");
    await page.getByLabel("Events").fill("wallet.recovery_setup\nmfa.enabled");
    await page.getByRole("button", { name: "Add Endpoint" }).click();
    expect(createPayload).toEqual({
      url: "https://hooks.example.test/steward",
      description: "Webhook page create test",
      events: ["wallet.recovery_setup", "mfa.enabled"],
    });
    await expect(page.getByText("whsec_created_once")).toBeVisible();
    await expect(page.getByText("https://hooks.example.test/steward").first()).toBeVisible();
    await expect(page.getByText("wallet.recovery_setup, mfa.enabled")).toBeVisible();
    await expect.poll(() => deliveryRequestCounts.get("webhook-created")).toBe(1);
    expect(webhookListRequestCount).toBe(1);
    await page.getByRole("button", { name: "Disable" }).first().click();
    await expect(page.getByText("disabled").first()).toBeVisible();
    await page.getByText("https://example.test/steward-webhooks").first().click();
    await expect.poll(() => deliveryRequestCounts.get("webhook-1")).toBe(2);
    expect(webhookListRequestCount).toBe(1);

    await page.getByLabel("Delivery status").selectOption("failed");
    await expect.poll(() => deliveryRequestCounts.get("webhook-1") ?? 0).toBe(3);
    await expect.poll(() => lastDeliveryQuery).toContain("status=failed");
    await page.getByLabel("Delivery event type").fill("user.created");
    await expect.poll(() => deliveryRequestCounts.get("webhook-1") ?? 0).toBe(4);
    await expect.poll(() => lastDeliveryQuery).toContain("eventType=user.created");
    await page.getByLabel("Delivery error state").selectOption("with_error");
    await expect.poll(() => deliveryRequestCounts.get("webhook-1") ?? 0).toBe(5);
    await expect.poll(() => lastDeliveryQuery).toContain("hasError=true");
    expect(webhookListRequestCount).toBe(1);
    await expect(page.getByRole("button", { name: /user\.created failed/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /transaction\.confirmed/ })).toHaveCount(0);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-webhook-management-filters.png"),
      fullPage: true,
    });

    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain("webhook-deliveries-webhook-1");
    await expect.poll(() => lastDeliveryQuery).toContain("status=failed");
    await expect.poll(() => lastDeliveryQuery).toContain("eventType=user.created");
    await expect.poll(() => lastDeliveryQuery).toContain("hasError=true");
    await page.getByLabel("Delivery status").selectOption("all");
    await page.getByLabel("Delivery event type").fill("");
    await page.getByLabel("Delivery error state").selectOption("all");
    await expect(page.getByRole("button", { name: /user\.created/ })).toBeVisible();
    await page.getByRole("button", { name: /user\.created/ }).click();
    await expect(page.getByText("Last error")).toBeVisible();
    page.once("dialog", async (dialog) => {
      expect(dialog.message()).toContain("Replay this event");
      await dialog.accept();
    });
    await page.getByRole("button", { name: "Replay Delivery" }).click();
    await expect(page.getByText("delivery-failed").first()).toBeVisible();
    await page.getByRole("button", { name: /user\.created failed/ }).click();
    await page.getByRole("button", { name: "Retry Delivery" }).click();
    await expect(page.getByRole("button", { name: /user\.created pending/ })).toBeVisible();
    await page.getByRole("button", { name: "Send Test" }).nth(1).click();
    await expect(page.getByText("webhook.test")).toBeVisible();

    page.once("dialog", async (dialog) => {
      expect(dialog.message()).toContain("Delete webhook endpoint");
      await dialog.accept();
    });
    const firstWebhookRequestsBeforeDelete = deliveryRequestCounts.get("webhook-1") ?? 0;
    await page.getByRole("button", { name: "Delete" }).first().click();
    expect(deletedEndpointId).toBe("webhook-created");
    await expect(page.getByText("https://hooks.example.test/steward")).toHaveCount(0);
    await expect(page.getByText("https://example.test/steward-webhooks").first()).toBeVisible();
    await expect(page.getByRole("button", { name: /user\.created pending/ })).toBeVisible();
    expect(deliveryRequestCounts.get("webhook-1") ?? 0).toBe(firstWebhookRequestsBeforeDelete);
    expect(webhookListRequestCount).toBe(1);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-webhook-delivery-history.png"),
      fullPage: true,
    });
  });

  test("summary counters never retain rows owned by an old endpoint or filter", async ({
    page,
    request,
  }) => {
    const email = `webhook-summary-ownership-${Date.now()}@example.test`;
    const now = "2026-05-28T12:00:00.000Z";
    const webhooks: WebhookConfig[] = [
      {
        id: "webhook-a",
        tenantId: "e2e-tenant",
        url: "https://a.example.test/webhooks",
        events: ["user.created"],
        enabled: true,
        maxRetries: 5,
        retryBackoffMs: 60000,
        description: "Endpoint A",
        createdAt: now,
        updatedAt: now,
      },
      {
        id: "webhook-b",
        tenantId: "e2e-tenant",
        url: "https://b.example.test/webhooks",
        events: ["transaction.confirmed"],
        enabled: true,
        maxRetries: 5,
        retryBackoffMs: 60000,
        description: "Endpoint B",
        createdAt: now,
        updatedAt: now,
      },
    ];
    const delivered = (id: string): WebhookDelivery => ({
      id,
      eventType: "transaction.confirmed",
      status: "delivered",
      attempts: 1,
      maxAttempts: 6,
      nextRetryAt: null,
      hasError: false,
      createdAt: now,
      deliveredAt: now,
    });
    const failed = (id: string): WebhookDelivery => ({
      id,
      eventType: "user.created",
      status: "failed",
      attempts: 1,
      maxAttempts: 6,
      nextRetryAt: now,
      hasError: true,
      createdAt: now,
      deliveredAt: null,
    });
    const endpointARows = [
      delivered("a-delivered-1"),
      delivered("a-delivered-2"),
      failed("a-failed"),
    ];
    const endpointBRows = [delivered("b-delivered"), failed("b-failed")];

    let releaseEndpointB: (() => void) | undefined;
    const endpointBGate = new Promise<void>((resolve) => {
      releaseEndpointB = resolve;
    });
    let markEndpointBStarted: (() => void) | undefined;
    const endpointBStarted = new Promise<void>((resolve) => {
      markEndpointBStarted = resolve;
    });
    let releaseFailedFilter: (() => void) | undefined;
    const failedFilterGate = new Promise<void>((resolve) => {
      releaseFailedFilter = resolve;
    });
    let markFailedFilterStarted: (() => void) | undefined;
    const failedFilterStarted = new Promise<void>((resolve) => {
      markFailedFilterStarted = resolve;
    });

    await page.route(`${API}/webhooks`, async (route) => {
      await route.fulfill({ json: { ok: true, data: webhooks } });
    });
    await page.route(`${API}/webhooks/webhook-a/deliveries**`, async (route) => {
      await route.fulfill({ json: { ok: true, data: endpointARows } });
    });
    await page.route(`${API}/webhooks/webhook-b/deliveries**`, async (route) => {
      const status = new URL(route.request().url()).searchParams.get("status");
      if (status === "failed") {
        markFailedFilterStarted?.();
        await failedFilterGate;
        await route.fulfill({
          json: { ok: true, data: endpointBRows.filter((row) => row.status === status) },
        });
        return;
      }
      markEndpointBStarted?.();
      await endpointBGate;
      await route.fulfill({ json: { ok: true, data: endpointBRows } });
    });

    await loginWithMagicLink(page, request, email);
    await page.goto(`${WEB}/dashboard/webhooks`);

    const deliveredSummary = page.getByTestId("webhook-delivery-summary-delivered");
    const failedSummary = page.getByTestId("webhook-delivery-summary-failed");
    const retryableSummary = page.getByTestId("webhook-delivery-summary-retryable");
    await expect(deliveredSummary).toHaveText("2");
    await expect(failedSummary).toHaveText("1");
    await expect(retryableSummary).toHaveText("1");

    await page.getByText("https://b.example.test/webhooks").first().click();
    await endpointBStarted;
    await expect(page.getByText("https://b.example.test/webhooks").last()).toBeVisible();
    await expect(deliveredSummary).toHaveText("0");
    await expect(failedSummary).toHaveText("0");
    await expect(retryableSummary).toHaveText("0");
    releaseEndpointB?.();
    await expect(deliveredSummary).toHaveText("1");
    await expect(failedSummary).toHaveText("1");
    await expect(retryableSummary).toHaveText("1");

    await page.getByLabel("Delivery status").selectOption("failed");
    await failedFilterStarted;
    await expect(deliveredSummary).toHaveText("0");
    await expect(failedSummary).toHaveText("0");
    await expect(retryableSummary).toHaveText("0");
    releaseFailedFilter?.();
    await expect(deliveredSummary).toHaveText("0");
    await expect(failedSummary).toHaveText("1");
    await expect(retryableSummary).toHaveText("1");
  });
});

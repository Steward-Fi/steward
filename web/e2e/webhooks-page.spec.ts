import { expect, test } from "@playwright/test";

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

    await page.route(`${API}/webhooks`, async (route) => {
      if (route.request().method() === "POST") {
        const body = route.request().postDataJSON() as {
          url: string;
          events: string[];
          description?: string;
        };
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
      await route.fulfill({
        json: {
          ok: true,
          data: webhooks,
        },
      });
    });

    await page.route(`${API}/webhooks/webhook-created`, async (route) => {
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

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/webhooks`);
    await expect(page.getByRole("heading", { name: "Webhooks" })).toBeVisible();
    await expect(page.getByText("https://example.test/steward-webhooks").first()).toBeVisible();
    await expect(page.getByText("user.created").first()).toBeVisible();
    await expect(page.getByText("transaction.confirmed").first()).toBeVisible();

    await page
      .getByPlaceholder("https://api.example.com/webhooks/steward")
      .fill("https://hooks.example.test/steward");
    await page.getByPlaceholder("Production event sink").fill("Webhook page create test");
    await page.getByRole("button", { name: "Add Endpoint" }).click();
    await expect(page.getByText("whsec_created_once")).toBeVisible();
    await expect(page.getByText("https://hooks.example.test/steward").first()).toBeVisible();
    await page.getByRole("button", { name: "Disable" }).first().click();
    await expect(page.getByText("disabled").first()).toBeVisible();
    await page.getByText("https://example.test/steward-webhooks").first().click();

    await page.getByLabel("Delivery status").selectOption("failed");
    await expect.poll(() => lastDeliveryQuery).toContain("status=failed");
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain("webhook-deliveries-webhook-1");
    await expect.poll(() => lastDeliveryQuery).toContain("status=failed");
    await page.getByLabel("Delivery status").selectOption("all");
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

    await page.screenshot({
      path: testInfo.outputPath("dashboard-webhook-delivery-history.png"),
      fullPage: true,
    });
  });
});

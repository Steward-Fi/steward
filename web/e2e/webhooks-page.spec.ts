import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type WebhookDelivery = {
  id: string;
  eventType: string;
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
      await route.fulfill({ json: { ok: true, data: deliveries } });
    });
    await page.route(`${API}/webhooks/webhook-created/deliveries**`, async (route) => {
      await route.fulfill({ json: { ok: true, data: [] } });
    });

    await page.route(`${API}/webhooks/deliveries/delivery-failed/retry`, async (route) => {
      deliveries = deliveries.map((delivery) =>
        delivery.id === "delivery-failed"
          ? {
              ...delivery,
              status: "pending",
              nextRetryAt: "2026-05-28T12:35:00.000Z",
              hasError: false,
            }
          : delivery,
      );
      await route.fulfill({ json: { ok: true, data: deliveries[0] } });
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

    await page.getByRole("button", { name: /user\.created/ }).click();
    await expect(page.getByText("Last error")).toBeVisible();
    await page.getByRole("button", { name: "Retry Delivery" }).click();
    await expect(page.getByText("pending")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-webhook-delivery-history.png"),
      fullPage: true,
    });
  });
});

import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Dashboard app origin controls", () => {
  test("authenticated users can see app origin settings", async ({ page, request }, testInfo) => {
    const email = `origins-${Date.now()}@example.test`;

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/settings`);
    await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "App Origins" })).toBeVisible();
    await expect(page.getByText(/OAuth redirect allowlisting/i)).toBeVisible();
    await expect(page.getByRole("button", { name: "Save Origins" })).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-app-origins.png"),
      fullPage: true,
    });
  });
});

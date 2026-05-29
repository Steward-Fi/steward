import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Dashboard account management", () => {
  test("authenticated users can review login methods and linked accounts", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-${Date.now()}@example.test`;

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Primary Login Methods" })).toBeVisible();
    await expect(page.getByRole("main").getByText(email)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Linked Accounts" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Embedded Wallets" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account.png"),
      fullPage: true,
    });
  });
});

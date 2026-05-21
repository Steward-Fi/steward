import { expect, test } from "@playwright/test";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Login page UI", () => {
  test("renders all enabled providers", async ({ page }) => {
    await page.goto(`${WEB}/login`);
    await expect(page.getByLabel("email")).toBeVisible();
    await expect(page.getByRole("button", { name: /email me a link/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /passkey/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Google$/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Discord$/i })).toBeVisible();
  });

  test("blank email input shows inline error when 'email me a link' clicked", async ({ page }) => {
    await page.goto(`${WEB}/login`);
    await page.getByRole("button", { name: /email me a link/i }).click();
    await expect(page.getByRole("alert")).toBeVisible();
  });
});

import { expect, test } from "@playwright/test";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Login page UI", () => {
  test("renders all enabled providers", async ({ page }) => {
    await page.goto(`${WEB}/login`);
    await expect(page.getByLabel("email")).toBeVisible();
    await expect(page.getByRole("button", { name: /email me a link/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /passkey/i })).toBeVisible();
    await expect(page.getByTestId("stwd-login-wallets")).toBeVisible();
    await expect(page.getByRole("heading", { name: /^ethereum$/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: /^solana$/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Google$/i })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Discord$/i })).toBeVisible();
  });

  test("blank email input shows inline error when 'email me a link' clicked", async ({ page }) => {
    await page.goto(`${WEB}/login`);
    // The login form is client-rendered only after an async API-reachability
    // probe resolves (the page shows a spinner first). Wait for the form to
    // mount before interacting so the click is delivered to a hydrated button.
    const emailLinkButton = page.getByRole("button", { name: /email me a link/i });
    await expect(emailLinkButton).toBeVisible();
    // Scope to the login form's own alert: a bare getByRole("alert") also matches
    // Next.js's always-present (empty) #__next-route-announcer__, which is a
    // strict-mode violation. The login error is a <p role="alert"> with this class.
    const loginError = page.locator("[role='alert'].stwd-login__error");
    // Retry the click+assert as a unit: the very first click can occasionally
    // land during the spinner→form swap (layout shift / event-binding window)
    // and be dropped, leaving no error. toPass re-clicks until it registers.
    await expect(async () => {
      await emailLinkButton.click();
      await expect(loginError).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 15_000 });
  });
});

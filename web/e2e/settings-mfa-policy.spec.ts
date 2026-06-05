import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Dashboard MFA policy controls", () => {
  test("authenticated admins can edit tenant MFA policy", async ({ page, request }, testInfo) => {
    const email = `mfa-policy-${Date.now()}@example.test`;
    let savedAuthAbuseConfig: Record<string, unknown> = {
      loginMethods: { email: true, passkey: true },
      mfa: {
        maxAgeSeconds: 300,
        requireFor: {
          vaultSigning: true,
          keyImport: true,
          keyExport: true,
          recoveryCodes: true,
          tenantAdmin: true,
        },
        allowDelegatedSignerAutomation: true,
        allowKeyQuorumAutomation: true,
      },
    };

    await page.route(/\/tenants\/[^/]+\/config$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            allowedOrigins: ["https://app.example.com"],
            allowedRedirectUrls: ["https://app.example.com/auth/callback"],
            appClients: [],
          },
        },
      });
    });
    await page.route(/\/tenants\/[^/]+\/auth-abuse-config$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({
          json: { ok: true, data: { authAbuseConfig: savedAuthAbuseConfig } },
        });
        return;
      }
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as { authAbuseConfig?: Record<string, unknown> };
        savedAuthAbuseConfig = body.authAbuseConfig ?? {};
        await route.fulfill({
          json: { ok: true, data: { authAbuseConfig: savedAuthAbuseConfig } },
        });
        return;
      }
      await route.fallback();
    });
    await page.route(/\/tenants\/[^/]+\/security-checklist$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            tenantId: "personal-test",
            generatedAt: "2026-05-29T00:00:00.000Z",
            summary: { pass: 7, warning: 0, fail: 0 },
            items: [],
          },
        },
      });
    });

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/settings`);
    const form = page.locator("form").filter({
      has: page.getByRole("heading", { name: "Login Controls" }),
    });
    await expect(form).toBeVisible();
    await expect(form.getByLabel("MFA Max Age Seconds")).toHaveValue("300");
    await expect(form.getByLabel("MFA Max Age Seconds")).toHaveAttribute("min", "30");
    await expect(form.getByLabel("MFA Max Age Seconds")).toHaveAttribute("max", "3600");
    await expect(form.getByLabel("MFA Max Age Seconds")).toHaveAttribute("step", "30");

    await form.getByLabel("MFA Max Age Seconds").fill("900");
    await form.getByLabel("Require MFA for vault signing").uncheck();
    await form.getByLabel("Require MFA for key import").uncheck();
    await form.getByLabel("Require MFA for key export").uncheck();
    await form.getByLabel("Require MFA for recovery codes").uncheck();
    await form.getByLabel("Require MFA for tenant admin changes").uncheck();
    await form.getByLabel("Allow delegated signer automation").uncheck();
    await form.getByLabel("Allow key quorum automation").uncheck();
    await form.getByRole("button", { name: "Save Controls" }).click();
    await expect(form.getByText("Saved")).toBeVisible();

    expect(savedAuthAbuseConfig).toMatchObject({
      mfa: {
        maxAgeSeconds: 900,
        allowDelegatedSignerAutomation: false,
        allowKeyQuorumAutomation: false,
        requireFor: {
          vaultSigning: false,
          keyImport: false,
          keyExport: false,
          recoveryCodes: false,
          tenantAdmin: false,
        },
      },
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-mfa-policy.png"),
      fullPage: true,
    });
  });
});

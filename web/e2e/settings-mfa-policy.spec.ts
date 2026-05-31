import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
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
    const form = page.locator("form").filter({
      has: page.getByRole("heading", { name: "Login Controls" }),
    });
    await expect(form).toBeVisible();
    await expect(form.getByLabel("MFA Max Age Seconds")).toHaveValue("300");

    await form.getByLabel("MFA Max Age Seconds").fill("120");
    await form.getByLabel("Delegated signer automation").uncheck();
    await form.getByLabel("Key quorum automation").uncheck();
    await form.getByRole("button", { name: "Save Controls" }).click();
    await expect(form.getByText("Saved")).toBeVisible();

    expect(savedAuthAbuseConfig).toMatchObject({
      mfa: {
        maxAgeSeconds: 120,
        allowDelegatedSignerAutomation: false,
        allowKeyQuorumAutomation: false,
        requireFor: {
          vaultSigning: true,
          keyImport: true,
          keyExport: true,
          recoveryCodes: true,
          tenantAdmin: true,
        },
      },
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-mfa-policy.png"),
      fullPage: true,
    });
  });
});

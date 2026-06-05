import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Dashboard wallet sign-in policy controls", () => {
  test("authenticated admins can edit third-party wallet allow and block lists", async ({
    page,
    request,
  }, testInfo) => {
    const email = `wallet-policy-${Date.now()}@example.test`;
    let savedAuthAbuseConfig: Record<string, unknown> = {
      loginMethods: { email: true, siwe: true, siws: true },
      wallet: {
        allowedWallets: ["0x0000000000000000000000000000000000000001"],
        blockedWallets: ["solana:11111111111111111111111111111111"],
        restrictToOneThirdPartyWallet: false,
      },
    };
    let savedFeatureFlags: Record<string, unknown> = {
      embeddedWallets: { createOnLogin: "users-without-wallets" },
    };

    await page.route(/\/tenants\/[^/]+\/config$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as { featureFlags?: Record<string, unknown> };
        savedFeatureFlags = body.featureFlags ?? savedFeatureFlags;
      }
      await route.fulfill({
        json: {
          ok: true,
          data: {
            allowedOrigins: ["https://app.example.com"],
            allowedRedirectUrls: ["https://app.example.com/auth/callback"],
            appClients: [],
            featureFlags: savedFeatureFlags,
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
            generatedAt: "2026-06-04T00:00:00.000Z",
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
    await expect(
      form.getByRole("heading", { name: "Third-Party Wallet Sign-In Policy" }),
    ).toBeVisible();

    const allowlist = form.getByLabel("Third-party Wallet Allowlist");
    const blocklist = form.getByLabel("Third-party Wallet Blocklist");
    const oneWalletToggle = form.getByLabel("Restrict users to one linked wallet");
    await expect(allowlist).toHaveValue("0x0000000000000000000000000000000000000001");
    await expect(blocklist).toHaveValue("solana:11111111111111111111111111111111");
    await expect(oneWalletToggle).not.toBeChecked();

    await allowlist.fill(
      "0x0000000000000000000000000000000000000003\nsolana:33333333333333333333333333333333",
    );
    await blocklist.fill("0x0000000000000000000000000000000000000004");
    await oneWalletToggle.check();
    await form.getByRole("button", { name: "Save Controls" }).click();
    await expect(form.getByText("Saved")).toBeVisible();

    expect(savedAuthAbuseConfig).toMatchObject({
      wallet: {
        allowedWallets: [
          "0x0000000000000000000000000000000000000003",
          "solana:33333333333333333333333333333333",
        ],
        blockedWallets: ["0x0000000000000000000000000000000000000004"],
        restrictToOneThirdPartyWallet: true,
      },
      loginMethods: {
        siwe: true,
        siws: true,
      },
    });

    const embeddedWalletForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "Embedded Wallet Creation" }),
    });
    await expect(embeddedWalletForm).toBeVisible();
    const createOnLogin = embeddedWalletForm.getByLabel("Create on Login");
    await expect(createOnLogin).toHaveValue("users-without-wallets");
    await createOnLogin.selectOption("all-users");
    await embeddedWalletForm.getByRole("button", { name: "Save Wallet Creation" }).click();
    await expect(embeddedWalletForm.getByText("Saved")).toBeVisible();
    expect(savedFeatureFlags).toMatchObject({
      embeddedWallets: {
        createOnLogin: "all-users",
      },
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-wallet-policy.png"),
      fullPage: true,
    });
  });
});

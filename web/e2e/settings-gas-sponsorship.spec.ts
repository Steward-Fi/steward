import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type GasSponsorshipConfig = {
  enabled?: boolean;
  provider?: "custom_evm_paymaster" | "custom_bundler" | "solana_fee_payer" | "mock";
  mode?: "erc4337" | "eip7702" | "solana_fee_payer";
  allowedChainIds?: number[];
  maxPerTxUsd?: number;
  allowClientSponsorship?: boolean;
  requireSimulation?: boolean;
  circuitBreakerEnabled?: boolean;
};

test.describe("Dashboard gas sponsorship settings", () => {
  test("authenticated users can update tenant gas sponsorship controls", async ({
    page,
    request,
  }, testInfo) => {
    const email = `gas-sponsorship-${Date.now()}@example.test`;
    let gasSponsorshipConfig: GasSponsorshipConfig = {
      enabled: false,
      provider: "mock",
      mode: "erc4337",
      allowedChainIds: [8453],
      maxPerTxUsd: 1,
      allowClientSponsorship: false,
      requireSimulation: true,
      circuitBreakerEnabled: false,
    };

    await page.route(/\/tenants\/[^/]+\/gas-sponsorship$/, async (route) => {
      const request = route.request();
      if (request.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { gasSponsorshipConfig } } });
        return;
      }
      if (request.method() === "PATCH") {
        const body = request.postDataJSON() as {
          gasSponsorshipConfig: GasSponsorshipConfig;
        };
        gasSponsorshipConfig = body.gasSponsorshipConfig;
        await route.fulfill({ json: { ok: true, data: { gasSponsorshipConfig } } });
        return;
      }
      await route.fallback();
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
    await expect(page.getByRole("heading", { name: "Gas Sponsorship" })).toBeVisible();

    const sponsorship = page.locator("form").filter({
      has: page.getByRole("heading", { name: "Gas Sponsorship" }),
    });
    await expect(sponsorship.getByLabel("Provider")).toHaveValue("mock");
    await expect(sponsorship.getByLabel("Mode")).toHaveValue("erc4337");

    await sponsorship.getByLabel("Enabled").check();
    await sponsorship.getByLabel("Provider").selectOption("custom_bundler");
    await sponsorship.getByLabel("Mode").selectOption("eip7702");
    await sponsorship.getByLabel("Allowed Chain IDs").fill("8453\n42161");
    await sponsorship.getByLabel("Max USD Per Tx").fill("2.50");
    await sponsorship.getByLabel("Client requests").check();
    await sponsorship.getByLabel("Require simulation").uncheck();
    await sponsorship.getByLabel("Circuit breaker").check();
    await sponsorship.getByRole("button", { name: "Save Sponsorship" }).click();

    await expect(sponsorship.getByText("Saved")).toBeVisible();
    expect(gasSponsorshipConfig).toEqual({
      enabled: true,
      provider: "custom_bundler",
      mode: "eip7702",
      allowedChainIds: [8453, 42161],
      maxPerTxUsd: 2.5,
      allowClientSponsorship: true,
      requireSimulation: false,
      circuitBreakerEnabled: true,
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-gas-sponsorship.png"),
      fullPage: true,
    });
  });
});

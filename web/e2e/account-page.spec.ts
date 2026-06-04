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
    await expect(page.getByRole("heading", { name: "Portfolio" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Spend and Capabilities" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Linked Accounts" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Recovery", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Global Wallet Grants" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Embedded Wallets" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account.png"),
      fullPage: true,
    });
  });

  test("recovery panel handles one-time wallet and MFA recovery secrets", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-recovery-${Date.now()}@example.test`;
    let hasWallet = false;
    let recoveryRemaining = 4;

    await page.route(/\/user\/me\/accounts$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            user: { id: "user-recovery", email },
            primaryLoginMethods: [{ provider: "email", providerAccountId: email }],
            accounts: [],
          },
        },
      });
    });
    await page.route(/\/user\/me\/account(\?.*)?$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            id: "user-recovery",
            type: "user",
            userId: "user-recovery",
            tenantId: "personal-user-recovery",
            email,
            emailVerified: true,
            name: null,
            image: null,
            walletAddress: hasWallet ? "0x00000000000000000000000000000000000000ab" : null,
            walletChain: hasWallet ? "evm" : null,
            customMetadata: {},
            linkedAccounts: [],
            primaryLoginMethods: [{ provider: "email", providerAccountId: email }],
            wallet: hasWallet
              ? {
                  id: "wallet-recovery",
                  agentId: "user-wallet-recovery",
                  walletAddress: "0x00000000000000000000000000000000000000ab",
                  walletAddresses: { evm: "0x00000000000000000000000000000000000000ab" },
                  createdAt: "2026-05-31T00:00:00.000Z",
                }
              : null,
            walletAddresses: hasWallet ? { evm: "0x00000000000000000000000000000000000000ab" } : {},
            wallets: hasWallet
              ? [
                  {
                    id: "wallet-recovery",
                    chainFamily: "evm",
                    address: "0x00000000000000000000000000000000000000ab",
                    venue: null,
                    purpose: "User wallet",
                    createdAt: "2026-05-31T00:00:00.000Z",
                  },
                ]
              : [],
            balances: { evm: null, unavailableReason: "mocked" },
            portfolio: {
              chainId: 8453,
              walletAddress: hasWallet ? "0x00000000000000000000000000000000000000ab" : null,
              native: null,
              tokens: [],
              totalUsd: null,
              totalUsdText: null,
              unavailableReason: "mocked",
            },
            spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
            capabilities: [],
            sponsorship: { enabled: false },
            createdAt: "2026-05-31T00:00:00.000Z",
            updatedAt: "2026-05-31T00:00:00.000Z",
          },
        },
      });
    });
    await page.route(/\/global-wallet\/consents$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: { consents: [] } } });
    });
    await page.route(/\/auth\/mfa\/recovery-codes\/status$/, async (route) => {
      await route.fulfill({
        json: { ok: true, enabled: true, remaining: recoveryRemaining },
      });
    });
    await page.route(/\/auth\/mfa\/recovery-codes\/regenerate$/, async (route) => {
      recoveryRemaining = 10;
      await route.fulfill({
        json: { ok: true, recoveryCodes: ["AAAAA-BBBBB", "CCCCC-DDDDD"] },
      });
    });
    await page.route(/\/user\/me\/wallet\/recovery\/setup$/, async (route) => {
      hasWallet = true;
      await route.fulfill({
        status: 201,
        json: {
          ok: true,
          data: {
            wallet: {
              agentId: "user-wallet-recovery",
              walletAddress: "0x00000000000000000000000000000000000000ab",
              recoverable: true,
            },
            recovery: {
              type: "bip39",
              mnemonic:
                "abandon ability able about above absent absorb abstract absurd abuse access accident",
              warning: "This recovery phrase is shown once. Steward does not store it.",
            },
          },
        },
      });
    });
    await page.route(/\/audit\/events(\?.*)?$/, async (route) => {
      const url = new URL(route.request().url());
      await route.fulfill({
        json: {
          ok: true,
          data: {
            data: [
              {
                id: `event-${url.searchParams.get("action") ?? "recovery"}`,
                seq: 7,
                actor_type: "user",
                actor_id: "user-recovery",
                action: url.searchParams.get("action") ?? "user.wallet.recovery_setup",
                resource_type: "wallet",
                resource_id: "user-wallet-recovery",
                metadata: { method: "bip39", recoveryCodesIssued: 10 },
                created_at: "2026-05-31T00:00:00.000Z",
              },
            ],
            pagination: { page: 1, limit: 5, total: 1, totalPages: 1 },
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

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Recovery", exact: true })).toBeVisible();
    await expect(page.getByText("4 left")).toBeVisible();
    await expect(page.getByRole("button", { name: "Set Up Recoverable Wallet" })).toBeDisabled();

    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Set Up Recoverable Wallet" }).click();
    await expect(page.getByTestId("one-time-wallet-secret")).toBeVisible();
    await expect(page.getByText("1. abandon")).toBeVisible();
    await expect(page.getByText("Existing wallet detected")).toBeVisible();

    await page.getByLabel("Authenticator Code").fill("123456");
    await page.getByRole("button", { name: "Regenerate Codes" }).click();
    await expect(page.getByTestId("one-time-mfa-secret")).toBeVisible();
    await expect(page.getByText("AAAAA-BBBBB")).toBeVisible();
    await expect(page.getByText("MFA recovery codes regenerated")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account-recovery.png"),
      fullPage: true,
    });
  });
});

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
    await page.route(/\/user\/me\/wallet\/recovery\/restore$/, async (route) => {
      const body = route.request().postDataJSON() as { mnemonic?: string };
      expect(body.mnemonic).toContain("abandon ability");
      hasWallet = true;
      await route.fulfill({
        status: 200,
        json: {
          ok: true,
          data: {
            wallet: {
              agentId: "user-wallet-recovery",
              walletAddress: "0x00000000000000000000000000000000000000ab",
              recoverable: true,
              restoredExisting: true,
            },
            recovery: { type: "bip39", restored: true },
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
    await expect(page.getByRole("button", { name: "Restore Wallet" })).toBeDisabled();

    await page.getByLabel(/I understand this phrase is displayed once/).check();
    await page.getByRole("button", { name: "Set Up Recoverable Wallet" }).click();
    await expect(page.getByTestId("one-time-wallet-secret")).toBeVisible();
    await expect(page.getByText("1. abandon")).toBeVisible();
    await expect(page.getByText("Existing wallet detected")).toBeVisible();

    await page
      .getByLabel("Recovery Phrase")
      .fill("abandon ability able about above absent absorb abstract absurd abuse access accident");
    await page.getByLabel(/I understand this phrase is sent once over the current session/).check();
    await page.getByRole("button", { name: "Restore Wallet" }).click();
    await expect(
      page.getByText("Wallet recovery phrase verified and existing wallet restored"),
    ).toBeVisible();
    await expect(page.getByLabel("Recovery Phrase")).toHaveValue("");

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

  test("pregenerated wallet panel shows inventory and one-time distribution controls", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-pregen-${Date.now()}@example.test`;
    const futureExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const expiredAt = Date.now() - 60_000;
    const newExpiry = "2026-06-10T00:00:00.000Z";
    let createPayload: { count?: number; namePrefix?: string; claimExpiresInSeconds?: number } =
      {};
    const agents = [
      {
        id: "pregen-unclaimed",
        tenantId: "tenant-pregen",
        name: "Import batch #1",
        walletAddress: "0x00000000000000000000000000000000000000aa",
        walletAddresses: { evm: "0x00000000000000000000000000000000000000aa" },
        platformId: `pregenerated:${"a".repeat(64)}:${futureExpiry}`,
        createdAt: "2026-06-01T00:00:00.000Z",
      },
      {
        id: "pregen-expired",
        tenantId: "tenant-pregen",
        name: "Import batch #2",
        walletAddress: "0x00000000000000000000000000000000000000bb",
        walletAddresses: { evm: "0x00000000000000000000000000000000000000bb" },
        platformId: `pregenerated:${"b".repeat(64)}:${expiredAt}`,
        createdAt: "2026-06-01T00:00:00.000Z",
      },
      {
        id: "pregen-claimed",
        tenantId: "tenant-pregen",
        name: "Claimed import",
        walletAddress: "0x00000000000000000000000000000000000000cc",
        walletAddresses: { evm: "0x00000000000000000000000000000000000000cc" },
        platformId: `claimed:${"c".repeat(64)}`,
        createdAt: "2026-06-01T00:00:00.000Z",
      },
    ];

    await page.route(/\/user\/me\/accounts$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            user: { id: "user-pregen", email },
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
            id: "user-pregen",
            type: "user",
            userId: "user-pregen",
            tenantId: "tenant-pregen",
            email,
            emailVerified: true,
            name: null,
            image: null,
            walletAddress: null,
            walletChain: null,
            customMetadata: {},
            linkedAccounts: [],
            primaryLoginMethods: [{ provider: "email", providerAccountId: email }],
            wallet: null,
            walletAddresses: {},
            wallets: [],
            balances: { evm: null, unavailableReason: "mocked" },
            portfolio: {
              chainId: 8453,
              walletAddress: null,
              native: null,
              tokens: [],
              totalUsd: null,
              totalUsdText: null,
              unavailableReason: "mocked",
            },
            spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
            capabilities: [],
            sponsorship: { enabled: false },
            createdAt: "2026-06-01T00:00:00.000Z",
            updatedAt: "2026-06-01T00:00:00.000Z",
          },
        },
      });
    });
    await page.route(/\/global-wallet\/consents$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: { consents: [] } } });
    });
    await page.route(/\/auth\/mfa\/recovery-codes\/status$/, async (route) => {
      await route.fulfill({ json: { ok: true, enabled: false, remaining: 0 } });
    });
    await page.route(/\/audit\/events(\?.*)?$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: { data: [], pagination: { page: 1, limit: 5, total: 0, totalPages: 0 } },
        },
      });
    });
    await page.route(/\/agents\/pregenerated$/, async (route) => {
      createPayload = route.request().postDataJSON() as typeof createPayload;
      const created = [
        {
          id: "pregen-new-1",
          tenantId: "tenant-pregen",
          name: "VIP import #1",
          walletAddress: "0x00000000000000000000000000000000000000dd",
          walletAddresses: { evm: "0x00000000000000000000000000000000000000dd" },
          platformId: `pregenerated:${"d".repeat(64)}:${Date.parse(newExpiry)}`,
          createdAt: "2026-06-03T00:00:00.000Z",
        },
        {
          id: "pregen-new-2",
          tenantId: "tenant-pregen",
          name: "VIP import #2",
          walletAddress: "0x00000000000000000000000000000000000000ee",
          walletAddresses: { evm: "0x00000000000000000000000000000000000000ee" },
          platformId: `pregenerated:${"e".repeat(64)}:${Date.parse(newExpiry)}`,
          createdAt: "2026-06-03T00:00:00.000Z",
        },
      ];
      agents.unshift(...created);
      await route.fulfill({
        status: 201,
        json: {
          ok: true,
          data: {
            warning: "Claim tokens are shown once. Store them before leaving this page.",
            wallets: created.map((agent, index) => ({
              agent,
              claimToken: `claim-token-${index + 1}`,
              claimExpiresAt: newExpiry,
            })),
          },
        },
      });
    });
    await page.route(/\/agents$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: agents } });
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
    await expect(
      page.getByRole("heading", { name: "Pregenerated User Wallets" }),
    ).toBeVisible();
    await expect(page.getByTestId("pregenerated-inventory").getByText("pregen-unclaimed")).toBeVisible();
    await expect(page.getByTestId("pregenerated-inventory").getByText("pregen-expired")).toBeVisible();
    await expect(page.getByTestId("pregenerated-inventory").getByText("pregen-claimed")).toBeVisible();
    await expect(page.getByText("Ready to distribute")).toBeVisible();
    await expect(page.getByText("Needs replacement")).toBeVisible();

    await page.getByLabel("Count").fill("2");
    await page.getByLabel("Name Prefix").fill("VIP import");
    await page.getByLabel("Claim Expiry Days").fill("1");
    await page.getByRole("button", { name: "Create Claim Tokens" }).click();

    expect(createPayload).toEqual({
      count: 2,
      namePrefix: "VIP import",
      claimExpiresInSeconds: 86_400,
    });
    await expect(page.getByTestId("pregenerated-distribution")).toBeVisible();
    await expect(page.getByText("claim-token-1")).toBeVisible();
    await expect(page.getByText("claim-token-2")).toBeVisible();
    await expect(page.getByText("Tokens below are not recoverable after refresh")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account-pregenerated-wallets.png"),
      fullPage: true,
    });
  });
});

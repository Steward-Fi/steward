import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Dashboard agent account aggregation", () => {
  test("agent detail page shows portfolio, wallets, sponsorship, and capabilities", async ({
    page,
    request,
  }, testInfo) => {
    const email = `agent-account-${Date.now()}@example.test`;
    const agentId = "agent-account-e2e";
    const walletAddress = "0x1111111111111111111111111111111111111111";

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === `/agents/${agentId}`,
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              id: agentId,
              tenantId: "personal-test",
              name: "Portfolio Agent",
              walletAddress,
              walletAddresses: { evm: walletAddress },
              platformId: "portfolio-platform",
              createdAt: "2026-05-29T12:00:00.000Z",
            },
          },
        });
      },
    );

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === `/agents/${agentId}/policies`,
      async (route) => {
        await route.fulfill({ json: { ok: true, data: [] } });
      },
    );

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === `/vault/${agentId}/history`,
      async (route) => {
        await route.fulfill({ json: { ok: true, data: [] } });
      },
    );

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === `/agents/${agentId}/balance`,
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              agentId,
              walletAddress,
              balances: {
                native: "2500000000000000000",
                nativeFormatted: "2.5",
                chainId: 8453,
                symbol: "ETH",
              },
            },
          },
        });
      },
    );

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === `/agents/${agentId}/account`,
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              id: agentId,
              type: "agent",
              agentId,
              tenantId: "personal-test",
              name: "Portfolio Agent",
              walletAddress,
              walletAddresses: { evm: walletAddress },
              wallets: [
                {
                  id: "wallet_evm",
                  chainFamily: "evm",
                  address: walletAddress,
                  venue: null,
                  purpose: "trading wallet",
                  createdAt: "2026-05-29T12:00:00.000Z",
                },
              ],
              balances: {
                evm: {
                  native: "2500000000000000000",
                  nativeFormatted: "2.5",
                  chainId: 8453,
                  symbol: "ETH",
                  walletAddress,
                },
              },
              portfolio: {
                chainId: 8453,
                walletAddress,
                native: {
                  token: "native",
                  symbol: "ETH",
                  balance: "2500000000000000000",
                  formatted: "2.5",
                  decimals: 18,
                  usdPrice: 3000,
                  usdValue: 7500,
                  usdPriceText: "3000",
                  usdValueText: "7500",
                },
                tokens: [
                  {
                    token: "0x2222222222222222222222222222222222222222",
                    symbol: "USDC",
                    balance: "42000000",
                    formatted: "42",
                    decimals: 6,
                    usdPrice: 1,
                    usdValue: 42,
                    usdPriceText: "1",
                    usdValueText: "42",
                  },
                ],
                totalUsd: 7542,
                totalUsdText: "7542",
              },
              spend: {
                todayWei: "0",
                weekWei: "0",
                monthWei: "0",
              },
              capabilities: ["sign_transaction", "send_calls", "transfer"],
              sponsorship: {
                enabled: true,
                mode: "tenant",
                policyId: "gas-policy",
              },
              createdAt: "2026-05-29T12:00:00.000Z",
            },
          },
        });
      },
    );

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/agents/${agentId}`);
    await expect(page.getByRole("heading", { name: "Portfolio Agent" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Account Portfolio" })).toBeVisible();
    await expect(page.getByText("Gas sponsorship enabled")).toBeVisible();
    await expect(page.getByText("$7,542.00")).toBeVisible();
    await expect(page.getByText("2.5 ETH").first()).toBeVisible();
    await expect(page.getByText("USDC", { exact: true })).toBeVisible();
    await expect(page.getByText("sign_transaction")).toBeVisible();
    await expect(page.getByText("send_calls")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-agent-account.png"),
      fullPage: true,
    });
  });
});

import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type MockSigner = Record<string, unknown> & {
  id: string;
};

test.describe("Dashboard agent account aggregation", () => {
  test("agent detail page shows portfolio, wallets, sponsorship, and capabilities", async ({
    page,
    request,
  }, testInfo) => {
    const email = `agent-account-${Date.now()}@example.test`;
    const agentId = "agent-account-e2e";
    const walletAddress = "0x1111111111111111111111111111111111111111";
    const p256PublicKey = "BASE64_SPKI_P256_PUBLIC_KEY";
    let latestSignerUpdate: Record<string, unknown> | null = null;
    let signers: MockSigner[] = [
      {
        id: "signer-p256",
        tenantId: "personal-test",
        agentId,
        signerType: "delegated",
        subjectType: "external",
        subjectId: "ops-key-1",
        keyType: "p256",
        publicKey: p256PublicKey,
        address: null,
        chainFamily: null,
        label: "Ops P-256",
        permissions: ["sign_message", "sign_transaction"],
        policyIds: ["policy_daily_limit"],
        metadata: {},
        hasCredential: false,
        status: "active",
        createdBy: "admin-user",
        createdAt: "2026-05-29T12:00:00.000Z",
        updatedAt: "2026-05-29T12:00:00.000Z",
      },
    ];

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
        await route.fulfill({
          json: {
            ok: true,
            data: [
              {
                id: "policy_daily_limit",
                type: "spending-limit",
                enabled: true,
                config: { maxPerTx: "1000000000000000000", maxPerDay: "5000000000000000000" },
              },
              {
                id: "policy_manual_review",
                type: "auto-approve-threshold",
                enabled: true,
                config: { threshold: "100000000000000000" },
              },
            ],
          },
        });
      },
    );

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname.startsWith(`/agents/${agentId}/signers`),
      async (route) => {
        const request = route.request();
        const method = request.method();
        const url = new URL(request.url());

        if (url.pathname === `/agents/${agentId}/signers` && method === "GET") {
          await route.fulfill({ json: { ok: true, data: { signers } } });
          return;
        }

        if (url.pathname === `/agents/${agentId}/signers` && method === "POST") {
          const body = request.postDataJSON() as Record<string, unknown>;
          const created: MockSigner = {
            id: "signer-created",
            tenantId: "personal-test",
            agentId,
            signerType: body.signerType,
            subjectType: body.subjectType,
            subjectId: body.subjectId,
            keyType: body.keyType,
            publicKey: body.publicKey,
            address: null,
            chainFamily: null,
            label: body.label,
            permissions: body.permissions,
            policyIds: body.policyIds,
            metadata: {},
            hasCredential: false,
            status: "active",
            createdBy: "admin-user",
            createdAt: "2026-05-29T12:00:00.000Z",
            updatedAt: "2026-05-29T12:00:00.000Z",
          };
          signers = [created, ...signers];
          await route.fulfill({ json: { ok: true, data: created } });
          return;
        }

        if (url.pathname === `/agents/${agentId}/signers/signer-p256` && method === "PATCH") {
          latestSignerUpdate = request.postDataJSON() as Record<string, unknown>;
          signers = signers.map((signer) =>
            signer.id === "signer-p256"
              ? {
                  ...signer,
                  status: latestSignerUpdate?.status ?? signer.status,
                  policyIds: latestSignerUpdate?.policyIds ?? signer.policyIds,
                }
              : signer,
          );
          await route.fulfill({
            json: { ok: true, data: signers.find((signer) => signer.id === "signer-p256") },
          });
          return;
        }

        await route.fulfill({ status: 404, json: { ok: false, error: "not found" } });
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

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/agents/${agentId}`);
    await expect(page.getByRole("heading", { name: "Portfolio Agent" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Account Portfolio" })).toBeVisible();
    await expect(page.getByText("Gas sponsorship enabled")).toBeVisible();
    await expect(page.getByText("$7,542.00")).toBeVisible();
    await expect(page.getByText("2.5 ETH").first()).toBeVisible();
    await expect(page.getByText("USDC", { exact: true })).toBeVisible();
    await expect(page.getByText("sign_transaction")).toBeVisible();
    await expect(page.getByText("send_calls")).toBeVisible();

    await page.getByRole("button", { name: /Signers/ }).click();
    await expect(page.getByText("Ops P-256")).toBeVisible();
    await expect(page.getByText("external:ops-key-1")).toBeVisible();
    await expect(page.locator("#signer-policies-signer-p256")).toHaveValue("policy_daily_limit");

    await page.getByLabel("Subject ID").fill("ops-key-2");
    await page.getByLabel("Public Key").fill(p256PublicKey);
    await page.locator("#policy-ids").fill("policy_daily_limit");
    await page.getByRole("button", { name: "Create Signer" }).click();
    await expect(page.getByText("ops-key-2", { exact: true })).toBeVisible();

    await page
      .locator("#signer-policies-signer-p256")
      .fill("policy_daily_limit, policy_manual_review");
    await page.getByRole("button", { name: "Save signer ops-key-1" }).click();
    await expect(page.locator("#signer-policies-signer-p256")).toHaveValue(
      "policy_daily_limit, policy_manual_review",
    );
    expect(latestSignerUpdate).toMatchObject({
      policyIds: ["policy_daily_limit", "policy_manual_review"],
      status: "active",
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-agent-account.png"),
      fullPage: true,
    });
  });
});

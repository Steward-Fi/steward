import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import type { UserWalletSigner } from "@stwd/sdk";
import { loginWithMagicLink } from "./fixtures/auth";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";
const accountPageSource = readFileSync("src/app/dashboard/account/page.tsx", "utf8");

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");
}

test.describe("Dashboard account management", () => {
  test("account dashboard delegates private-key import to the encrypted component", () => {
    expect(accountPageSource).toContain("<StewardUserWalletKeyImport");
    expect(accountPageSource).not.toContain("/user/me/wallet/import/submit");
    expect(accountPageSource).not.toContain("submitEncryptedUserWalletKeyImport(");
    expect(accountPageSource).not.toContain("initializeEncryptedUserWalletKeyImport(");
  });

  test("authenticated users can review login methods and linked accounts", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-${Date.now()}@example.test`;

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Account", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Primary Login Methods" })).toBeVisible();
    await expect(page.getByRole("main").getByText(email)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Portfolio" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Spend and Capabilities" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Private Key Import" })).toBeVisible();
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
    let setupRecoveryBody: Record<string, unknown> | null = null;
    let restoreRecoveryBody: Record<string, unknown> | null = null;

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
      setupRecoveryBody = route.request().postDataJSON() as Record<string, unknown>;
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
              walletIndex: 2,
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
      const body = route.request().postDataJSON() as { mnemonic?: string; walletIndex?: number };
      restoreRecoveryBody = body;
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
              walletIndex: 2,
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

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Recovery", exact: true })).toBeVisible();
    await expect(page.getByText("4 left")).toBeVisible();
    await expect(page.getByRole("button", { name: "Set Up Recoverable Wallet" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Restore Wallet" })).toBeDisabled();
    await page.getByLabel("Recovery Wallet Index").fill("2");
    await expect(page.getByText("Indexed wallet slot")).toBeVisible();

    await page.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Set Up Recoverable Wallet" }).click();
    expect(setupRecoveryBody).toMatchObject({ walletIndex: 2 });
    await expect(page.getByTestId("one-time-wallet-secret")).toBeVisible();
    await expect(page.getByText("1. abandon")).toBeVisible();
    await expect(page.getByText("Existing wallet detected")).toBeVisible();

    await page
      .getByLabel("Recovery Phrase")
      .fill("abandon ability able about above absent absorb abstract absurd abuse access accident");
    await page.getByLabel(/I understand this phrase is sent once over the current session/).check();
    await page.getByRole("button", { name: "Restore Wallet" }).click();
    expect(restoreRecoveryBody).toMatchObject({ walletIndex: 2 });
    await expect(
      page.getByText(
        "Wallet recovery phrase verified and existing wallet restored at walletIndex 2",
      ),
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

  test("private key import creates an encrypted envelope without submitting plaintext", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-key-import-${Date.now()}@example.test`;
    const importedWalletAddress = "0x00000000000000000000000000000000000000cd";
    const { publicKey } = generateKeyPairSync("x25519");
    const serverPublicKey = base64UrlEncode(
      publicKey.export({ type: "spki", format: "der" }) as Uint8Array,
    );
    let hasImportedWallet = false;
    let initPayload: Record<string, unknown> | null = null;
    let submitPayload: Record<string, unknown> | null = null;

    await page.route(/\/user\/me\/accounts$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            user: { id: "user-key-import", email },
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
            id: "user-key-import",
            type: "user",
            userId: "user-key-import",
            tenantId: "personal-user-key-import",
            email,
            emailVerified: true,
            name: null,
            image: null,
            walletAddress: hasImportedWallet ? importedWalletAddress : null,
            walletChain: hasImportedWallet ? "evm" : null,
            customMetadata: {},
            linkedAccounts: [],
            primaryLoginMethods: [{ provider: "email", providerAccountId: email }],
            wallet: hasImportedWallet
              ? {
                  id: "wallet-key-import",
                  agentId: "user-wallet-key-import",
                  walletAddress: importedWalletAddress,
                  walletAddresses: { evm: importedWalletAddress },
                  createdAt: "2026-06-05T00:00:00.000Z",
                }
              : null,
            walletAddresses: hasImportedWallet ? { evm: importedWalletAddress } : {},
            wallets: hasImportedWallet
              ? [
                  {
                    id: "wallet-key-import",
                    chainFamily: "evm",
                    address: importedWalletAddress,
                    venue: null,
                    purpose: "Imported user wallet",
                    metadata: {},
                    createdAt: "2026-06-05T00:00:00.000Z",
                  },
                ]
              : [],
            balances: { evm: null, unavailableReason: "mocked" },
            portfolio: {
              chainId: 8453,
              walletAddress: hasImportedWallet ? importedWalletAddress : null,
              native: null,
              tokens: [],
              totalUsd: null,
              totalUsdText: null,
              unavailableReason: "mocked",
            },
            spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
            capabilities: [],
            sponsorship: { enabled: false },
            createdAt: "2026-06-05T00:00:00.000Z",
            updatedAt: "2026-06-05T00:00:00.000Z",
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
    await page.route(/\/agents$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: [] } });
    });
    await page.route(/\/user\/me\/wallet\/signers(\?.*)?$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: { signers: [] } } });
    });
    await page.route(/\/user\/me\/wallet\/import\/init$/, async (route) => {
      initPayload = route.request().postDataJSON() as Record<string, unknown>;
      await route.fulfill({
        json: {
          ok: true,
          data: {
            importSessionId: "uwimp_dashboard",
            publicKey: serverPublicKey,
            algorithm: "X25519-HKDF-SHA256-AES-256-GCM",
            expiresAt: "2026-06-05T12:00:00.000Z",
            aad: {
              importSessionId: "uwimp_dashboard",
              tenantId: "personal-user-key-import",
              userId: "user-key-import",
              agentId: "user-wallet-key-import-2",
              chain: "evm",
              walletIndex: 2,
              appClientId: null,
            },
          },
        },
      });
    });
    await page.route(/\/user\/me\/wallet\/import\/submit$/, async (route) => {
      submitPayload = route.request().postDataJSON() as Record<string, unknown>;
      hasImportedWallet = true;
      await route.fulfill({
        status: 201,
        json: {
          ok: true,
          data: {
            agentId: "user-wallet-key-import-2",
            walletAddress: importedWalletAddress,
            chain: "evm",
            walletIndex: 2,
            imported: true,
          },
        },
      });
    });

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Private Key Import" })).toBeVisible();
    const importForm = page.getByTestId("stwd-user-wallet-key-import");
    await importForm.getByLabel("Wallet Index").fill("2");
    await importForm.getByLabel("Private Key").fill("0xsuper-secret-import-key");
    await importForm.getByRole("button", { name: "Import Private Key" }).click();

    await expect(page.getByText("Wallet import completed")).toBeVisible();
    expect(initPayload).toEqual({ chain: "evm", walletIndex: 2 });
    expect(submitPayload).toMatchObject({
      importSessionId: "uwimp_dashboard",
      walletIndex: 2,
    });
    expect(JSON.stringify(submitPayload)).not.toContain("super-secret-import-key");
    expect(submitPayload).toHaveProperty("ephemeralPublicKey");
    expect(submitPayload).toHaveProperty("ciphertext");
    expect(submitPayload).toHaveProperty("tag");
    await expect(importForm.getByLabel("Private Key")).toHaveValue("");
    await expect(page.getByText("Imported user wallet")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account-key-import.png"),
      fullPage: true,
    });
  });

  test("user wallet signer credentials are walletIndex-scoped and one-time secret only", async ({
    page,
    request,
  }, testInfo) => {
    const email = `account-signers-${Date.now()}@example.test`;
    const walletAddress = "0x00000000000000000000000000000000000000ab";
    let createPayload: Record<string, unknown> = {};
    let revokeUrl = "";
    let signers: UserWalletSigner[] = [
      {
        id: "signer-existing",
        tenantId: "personal-user-signers",
        agentId: "user-wallet-signers-2",
        signerType: "delegated",
        subjectType: "external",
        subjectId: "device-existing",
        keyType: "hmac",
        publicKey: null,
        address: null,
        chainFamily: null,
        label: "Existing device",
        permissions: ["sign_message"],
        policyIds: [],
        metadata: { source: "test" },
        hasCredential: true,
        status: "active",
        createdBy: "user-signers",
        createdAt: "2026-06-01T00:00:00.000Z",
        updatedAt: "2026-06-01T00:00:00.000Z",
      },
    ];

    await page.route(/\/user\/me\/accounts$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            user: { id: "user-signers", email },
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
            id: "user-signers",
            type: "user",
            userId: "user-signers",
            tenantId: "personal-user-signers",
            email,
            emailVerified: true,
            name: null,
            image: null,
            walletAddress,
            walletChain: "evm",
            customMetadata: {},
            linkedAccounts: [],
            primaryLoginMethods: [{ provider: "email", providerAccountId: email }],
            wallet: {
              id: "wallet-signers",
              agentId: "user-wallet-signers",
              walletAddress,
              walletAddresses: { evm: walletAddress },
              createdAt: "2026-06-01T00:00:00.000Z",
            },
            walletAddresses: { evm: walletAddress },
            wallets: [
              {
                id: "wallet-signers",
                chainFamily: "evm",
                address: walletAddress,
                venue: null,
                purpose: "User wallet",
                metadata: {},
                createdAt: "2026-06-01T00:00:00.000Z",
              },
            ],
            balances: { evm: null, unavailableReason: "mocked" },
            portfolio: {
              chainId: 8453,
              walletAddress,
              native: null,
              tokens: [],
              totalUsd: null,
              totalUsdText: null,
              unavailableReason: "mocked",
            },
            spend: { todayWei: "0", weekWei: "0", monthWei: "0" },
            capabilities: ["sign_message", "sign_transaction"],
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
    await page.route(/\/agents$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: [] } });
    });
    await page.route(/\/user\/me\/wallet\/signers\/[^/?]+(\?.*)?$/, async (route) => {
      revokeUrl = route.request().url();
      signers = signers.map((signer) =>
        signer.id === "signer-created"
          ? { ...signer, status: "revoked", updatedAt: "2026-06-02T00:00:00.000Z" }
          : signer,
      );
      await route.fulfill({
        json: { ok: true, data: signers.find((s) => s.id === "signer-created") },
      });
    });
    await page.route(/\/user\/me\/wallet\/signers(\?.*)?$/, async (route) => {
      const url = new URL(route.request().url());
      const method = route.request().method();

      if (method === "GET") {
        await route.fulfill({
          json: {
            ok: true,
            data: { signers: url.searchParams.get("walletIndex") === "2" ? signers : [] },
          },
        });
        return;
      }

      createPayload = route.request().postDataJSON() as Record<string, unknown>;
      const created: UserWalletSigner = {
        id: "signer-created",
        tenantId: "personal-user-signers",
        agentId: "user-wallet-signers-2",
        signerType: "delegated",
        subjectType:
          createPayload.subjectType === "user" ||
          createPayload.subjectType === "wallet" ||
          createPayload.subjectType === "api_key"
            ? createPayload.subjectType
            : "external",
        subjectId: String(createPayload.subjectId ?? "device-created"),
        keyType: "hmac",
        publicKey: null,
        address: typeof createPayload.address === "string" ? createPayload.address : null,
        chainFamily:
          createPayload.chainFamily === "evm" || createPayload.chainFamily === "solana"
            ? createPayload.chainFamily
            : null,
        label: typeof createPayload.label === "string" ? createPayload.label : null,
        permissions: Array.isArray(createPayload.permissions)
          ? createPayload.permissions.map(String)
          : [],
        policyIds: [],
        metadata: { source: "dashboard", walletIndex: 2 },
        hasCredential: true,
        status: "active",
        createdBy: "user-signers",
        createdAt: "2026-06-02T00:00:00.000Z",
        updatedAt: "2026-06-02T00:00:00.000Z",
      };
      signers = [created, ...signers];
      await route.fulfill({
        status: 201,
        json: {
          ok: true,
          data: { ...created, credentialSecret: "stwd_signer_once_secret" },
        },
      });
    });

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/account`);
    await expect(
      page.getByRole("heading", { name: "User Wallet Signer Credentials" }),
    ).toBeVisible();
    const signerPanel = page.getByTestId("user-wallet-signers");
    await expect(signerPanel).toBeVisible();
    await expect(page.getByLabel("Subject ID")).toBeVisible();
    const signerWalletIndexInput = page.getByRole("textbox", {
      name: "Wallet Index",
      exact: true,
    });
    await signerWalletIndexInput.fill("2");
    await expect(signerWalletIndexInput).toHaveValue("2");
    await expect(signerPanel.getByText("Existing device")).toBeVisible();

    await page.getByLabel("Subject ID").fill("device-created");
    await expect(page.getByLabel("Subject ID")).toHaveValue("device-created");
    await page.getByLabel("Label").fill("Device signer");
    await page.getByLabel("Permissions").fill("sign_message, sign_transaction");
    await expect(page.getByRole("button", { name: "Create Signer Credential" })).toBeEnabled();
    await page.getByRole("button", { name: "Create Signer Credential" }).click();

    expect(createPayload).toMatchObject({
      walletIndex: 2,
      subjectType: "external",
      subjectId: "device-created",
      label: "Device signer",
      permissions: ["sign_message", "sign_transaction"],
    });
    expect(createPayload).not.toHaveProperty("credentialSecret");
    await expect(page.getByTestId("one-time-signer-secret")).toBeVisible();
    await expect(page.getByText("stwd_signer_once_secret")).toBeVisible();
    await expect(signerPanel.getByText("Device signer")).toBeVisible();

    await page.getByRole("button", { name: "Dismiss" }).click();
    await expect(page.getByText("stwd_signer_once_secret")).toHaveCount(0);
    await signerPanel.getByRole("button", { name: "Revoke" }).first().click();

    expect(new URL(revokeUrl).searchParams.get("walletIndex")).toBe("2");
    await expect(page.getByText("Revoked signer credential for device-created")).toBeVisible();
    await expect(signerPanel.getByText("revoked")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-account-user-wallet-signers.png"),
      fullPage: true,
    });
  });

  test("pregenerated wallet panel shows inventory and one-time distribution controls", async ({
    page,
    request,
  }, testInfo) => {
    page.on("pageerror", (error) => {
      console.log(`[pregenerated-wallets pageerror] ${error.message}`);
    });
    page.on("console", (message) => {
      if (message.type() === "error") {
        console.log(`[pregenerated-wallets console] ${message.text()}`);
      }
    });
    const email = `account-pregen-${Date.now()}@example.test`;
    const futureExpiry = Date.now() + 7 * 24 * 60 * 60 * 1000;
    const expiredAt = Date.now() - 60_000;
    const newExpiry = "2026-06-10T00:00:00.000Z";
    let createPayload: { count?: number; namePrefix?: string; claimExpiresInSeconds?: number } = {};
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

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/account`);
    await expect(page.getByRole("heading", { name: "Pregenerated User Wallets" })).toBeVisible();
    const inventory = page.getByTestId("pregenerated-inventory");
    await expect(inventory.getByText("pregen-unclaimed")).toBeVisible();
    await expect(inventory.getByText("pregen-expired")).toBeVisible();
    await expect(inventory.getByText("pregen-claimed")).toBeVisible();
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

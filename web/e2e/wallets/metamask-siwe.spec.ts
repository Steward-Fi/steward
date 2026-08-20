/**
 * Headful MetaMask SIWE login spec.
 *
 * Drives the real StewardLogin UI in chromium with the MetaMask extension
 * loaded. Clicks the EVM wallet button, approves the connect-dapp popup,
 * approves the SIWE personal_sign popup, and asserts the post-login
 * dashboard redirect.
 *
 * Prereq: cache must be built once via `bun run e2e:wallets:cache`.
 */

import { approveMetaMaskNotification, metamaskTest as test } from "./metamask-fixtures";

const { expect } = test;

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("MetaMask SIWE — headful end-to-end", () => {
  test("connects MetaMask, signs SIWE, lands on dashboard", async ({
    dappPage: page,
    metamask,
    walletContext,
  }) => {
    await page.goto(`${WEB}/login`);

    // Authorize the injected provider directly before selecting the RainbowKit
    // connector. Unpacked Chromium extensions cannot open the browser-toolbar
    // handoff RainbowKit waits for, but the EIP-1193 request reaches the same
    // MetaMask account-permission confirmation that a user approves.
    const providerRequest = page.evaluate(() =>
      (
        window as typeof window & {
          ethereum: { request(args: { method: string }): Promise<unknown> };
        }
      ).ethereum.request({ method: "eth_requestAccounts" }),
    );
    if (!metamask.extensionId) throw new Error("MetaMask extension id is unavailable");
    await approveMetaMaskNotification(walletContext, metamask.extensionId, /^connect$/i);
    await providerRequest;

    // Steward recognizes the already-authorized injected account and renders
    // the signing action directly (currently labelled "Browser Wallet").
    await page.getByRole("button", { name: /sign in with (browser wallet|metamask)/i }).click();
    await approveMetaMaskNotification(walletContext, metamask.extensionId, /confirm|sign/i);

    // Post-login: StewardLogin's onSuccess pushes router.push("/dashboard").
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

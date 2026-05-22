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

import { testWithSynpress } from "@synthetixio/synpress";
import { MetaMask, metaMaskFixtures } from "@synthetixio/synpress/playwright";
import metamaskSetup, { PASSWORD } from "./metamask.setup";

const test = testWithSynpress(metaMaskFixtures(metamaskSetup));
const { expect } = test;

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("MetaMask SIWE — headful end-to-end", () => {
  test("connects MetaMask, signs SIWE, lands on dashboard", async ({
    context,
    page,
    metamaskPage,
    extensionId,
  }) => {
    const metamask = new MetaMask(context, metamaskPage, PASSWORD, extensionId);

    await page.goto(`${WEB}/login`);
    await page.getByRole("button", { name: /ethereum/i }).click();

    // RainbowKit modal surfaces "MetaMask" as a row — click to trigger popup.
    await page
      .getByRole("button", { name: /metamask/i })
      .first()
      .click();

    // 1st popup: MetaMask asks to connect this account to the dapp.
    await metamask.connectToDapp();

    // 2nd popup: MetaMask asks the user to sign the SIWE personal_sign message.
    await metamask.confirmSignature();

    // Post-login: StewardLogin's onSuccess pushes router.push("/dashboard").
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

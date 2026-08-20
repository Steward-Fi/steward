/**
 * Headful Phantom SIWS login spec.
 *
 * Drives the real StewardLogin UI in chromium with the Phantom extension
 * loaded. Clicks the Solana wallet button, approves the connect popup,
 * approves the SIWS message-sign popup, and asserts the post-login dashboard
 * redirect.
 *
 * Prereq: cache must be built once via `bun run e2e:wallets:cache`.
 */

import { Phantom } from "@synthetixio/synpress/playwright";
import { phantomTest as test } from "./phantom-fixtures";
import { PHANTOM_PASSWORD } from "./setup/phantom/phantom.setup";

const { expect } = test;

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Phantom SIWS — headful end-to-end", () => {
  test("connects Phantom, signs SIWS, lands on dashboard", async ({
    dappPage: page,
    phantomPage,
    extensionId,
    walletContext,
  }) => {
    const phantom = new Phantom(walletContext, phantomPage, PHANTOM_PASSWORD, extensionId);

    await page.goto(`${WEB}/login`);
    await page.getByRole("button", { name: /select wallet/i }).click();

    // Solana wallet adapter modal — pick Phantom from the picker list.
    await page
      .getByRole("button", { name: /phantom/i })
      .first()
      .click();

    await phantom.connectToDapp();
    await page.getByRole("button", { name: /sign in with phantom/i }).click();
    await phantom.confirmSignature();

    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

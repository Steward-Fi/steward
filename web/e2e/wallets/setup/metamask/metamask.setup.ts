/**
 * MetaMask wallet setup for Synpress.
 *
 * Boots a fresh MetaMask extension, imports the dedicated test seed phrase, and
 * locks it with a password. Synpress caches the resulting browser-context
 * dir so subsequent test runs skip the lengthy onboarding flow.
 *
 * The dedicated MetaMask cache command points only at this setup directory so
 * Synpress cannot execute it against a different wallet extension.
 */

import { defineWalletSetup } from "@synthetixio/synpress";
import { MetaMask } from "@synthetixio/synpress/playwright";

// The collection-only command imports this module without provisioning
// credentials. Cache and execution commands run the fail-closed preflight
// before either value reaches a browser.
export const SEED_PHRASE = process.env.E2E_METAMASK_SEED_PHRASE ?? "";
export const PASSWORD = process.env.E2E_METAMASK_PASSWORD ?? "";
export const METAMASK_CACHE_ID = "steward-metamask-siwe-v6";

const metamaskSetup = defineWalletSetup(PASSWORD, async (context, walletPage) => {
  const metamask = new MetaMask(context, walletPage, PASSWORD);
  await metamask.importWallet(SEED_PHRASE);
  // MetaMask 13 leaves setup on a final "Your wallet is ready" gate. The
  // cached profile must advance into the wallet itself or later provider
  // requests have no active keyring despite the vault having been created.
  const openWallet = walletPage.getByRole("button", { name: /open wallet/i });
  if (await openWallet.isVisible()) {
    await openWallet.click();
    await walletPage.waitForTimeout(1_000).catch(() => undefined);
    const activeWalletPage =
      context
        .pages()
        .find((page) => !page.isClosed() && page.url().startsWith("chrome-extension://")) ??
      walletPage;
    if (!activeWalletPage.isClosed()) {
      const extensionUrl = new URL(activeWalletPage.url());
      const extensionOrigin = `${extensionUrl.protocol}//${extensionUrl.host}`;
      await activeWalletPage.goto(`${extensionOrigin}/home.html`);
      await activeWalletPage.getByTestId("account-menu-icon").waitFor();
    }
  }
});

// Synpress hashes Function.toString(), which differs between Bun's and
// Playwright's TypeScript transforms. A versioned ID makes both processes use
// the same cache; the cache command always forces a rebuild of this ID.
metamaskSetup.hash = METAMASK_CACHE_ID;

export default metamaskSetup;

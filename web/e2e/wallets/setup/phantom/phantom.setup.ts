/**
 * Phantom wallet setup for Synpress.
 *
 * Boots a fresh Phantom extension, imports the dedicated test seed phrase, and
 * locks it with a password. The browser-context dir is cached by Synpress so
 * subsequent runs skip onboarding.
 *
 * The dedicated Phantom cache command points only at this setup directory so
 * Synpress cannot execute it against a different wallet extension.
 */

import { defineWalletSetup } from "@synthetixio/synpress";
import { Phantom } from "@synthetixio/synpress/playwright";

export const PHANTOM_SEED = process.env.E2E_PHANTOM_SEED_PHRASE?.trim() ?? "";
export const PHANTOM_PASSWORD = process.env.E2E_PHANTOM_PASSWORD?.trim() ?? "";
export const PHANTOM_CACHE_ID = "steward-phantom-siws-v5";

const phantomSetup = defineWalletSetup(PHANTOM_PASSWORD, async (context, walletPage) => {
  const phantom = new Phantom(context, walletPage, PHANTOM_PASSWORD);
  try {
    await phantom.importWallet(PHANTOM_SEED);
  } catch (error) {
    if (!String(error).includes("All Done success screen should be visible")) {
      throw error;
    }
    // The current Chrome Web Store build inserts a username step
    // after password creation instead of Synpress's legacy success heading.
    await walletPage.getByRole("button", { name: /^suggested:/i }).click();
    await walletPage.getByTestId("onboarding-create-username-continue").click();
  }
});

// Keep the cache identity stable across Bun and Playwright transforms. The
// owning cache command force-rebuilds this versioned ID whenever it is run.
phantomSetup.hash = PHANTOM_CACHE_ID;

export default phantomSetup;

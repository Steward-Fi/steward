/**
 * Phantom wallet setup for Synpress.
 *
 * Boots a fresh Phantom extension, imports a deterministic seed phrase, and
 * locks it with a password. The browser-context dir is cached by Synpress so
 * subsequent runs skip onboarding.
 *
 * Prime the cache once via `bun run e2e:wallets:cache` (from web/).
 */

import { defineWalletSetup } from "@synthetixio/synpress";
import { Phantom } from "@synthetixio/synpress/playwright";

export const PHANTOM_SEED = "test test test test test test test test test test test junk";
export const PHANTOM_PASSWORD = "SynpressPhantom1234";

export default defineWalletSetup(PHANTOM_PASSWORD, async (context, walletPage) => {
  const phantom = new Phantom(context, walletPage, PHANTOM_PASSWORD);
  await phantom.importWallet(PHANTOM_SEED);
});

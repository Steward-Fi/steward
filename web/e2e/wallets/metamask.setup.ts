/**
 * MetaMask wallet setup for Synpress.
 *
 * Boots a fresh MetaMask extension, imports a deterministic seed phrase, and
 * locks it with a password. Synpress caches the resulting browser-context
 * dir so subsequent test runs skip the lengthy onboarding flow.
 *
 * Prime the cache once via `bun run e2e:wallets:cache` (from web/).
 */

import { defineWalletSetup } from "@synthetixio/synpress";
import { MetaMask } from "@synthetixio/synpress/playwright";

// BIP-39 standard test vector — never use for real funds.
export const SEED_PHRASE = "test test test test test test test test test test test junk";
export const PASSWORD = "SynpressIsTested1234";

export default defineWalletSetup(PASSWORD, async (context, walletPage) => {
  const metamask = new MetaMask(context, walletPage, PASSWORD);
  await metamask.importWallet(SEED_PHRASE);
});

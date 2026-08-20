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

// The collection-only command imports this module without provisioning
// credentials. Cache and execution commands run the fail-closed preflight
// before either value reaches a browser.
export const SEED_PHRASE = process.env.E2E_METAMASK_SEED_PHRASE?.trim() ?? "";
export const PASSWORD = process.env.E2E_METAMASK_PASSWORD?.trim() ?? "";
export const METAMASK_CACHE_ID = "steward-metamask-siwe-v8";

const metamaskSetup = defineWalletSetup(PASSWORD, async (_context, walletPage) => {
  // Synpress 4.1.2's importer targets newer MetaMask onboarding and attempts
  // the import button before accepting v12's terms. Drive the pinned v12.20.1
  // contract explicitly so cache construction cannot succeed only from stale
  // local state.
  await walletPage.getByTestId("onboarding-terms-checkbox").click();
  await walletPage.getByTestId("onboarding-import-wallet").click();
  await walletPage.getByTestId("metametrics-no-thanks").click();
  for (const [index, word] of SEED_PHRASE.split(" ").entries()) {
    await walletPage.getByTestId(`import-srp__srp-word-${index}`).fill(word);
  }
  await walletPage.getByTestId("import-srp-confirm").click();
  await walletPage.getByTestId("create-password-new").fill(PASSWORD);
  await walletPage.getByTestId("create-password-confirm").fill(PASSWORD);
  await walletPage.getByTestId("create-password-terms").click();
  await walletPage.getByTestId("create-password-import").click();
  await walletPage.getByRole("button", { exact: true, name: "Done" }).click();
});

// Synpress hashes Function.toString(), which differs between Bun's and
// Playwright's TypeScript transforms. A versioned ID makes both processes use
// the same cache; the cache command always forces a rebuild of this ID.
metamaskSetup.hash = METAMASK_CACHE_ID;

export default metamaskSetup;

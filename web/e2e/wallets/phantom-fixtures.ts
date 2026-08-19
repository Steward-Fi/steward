import { cp } from "node:fs/promises";
import { join } from "node:path";
import { type BrowserContext, test as base, chromium, type Page } from "@playwright/test";
import { Phantom } from "@synthetixio/synpress/playwright";
import { PHANTOM_CHROME_EXTENSION_ID, phantomExtensionPath } from "./cache-contract";
import { PHANTOM_CACHE_ID, PHANTOM_PASSWORD } from "./setup/phantom/phantom.setup";
import { withWalletBrowserProfile } from "./wallet-browser-profile";

type PhantomFixtures = {
  dappPage: Page;
  extensionId: string;
  phantomPage: Page;
  walletContext: BrowserContext;
};

export const phantomTest = base.extend<PhantomFixtures>({
  walletContext: async ({ browserName: _ }, use, testInfo) => {
    const sourceProfile = join(process.cwd(), ".cache-synpress", PHANTOM_CACHE_ID);
    const extensionPath = phantomExtensionPath();
    await withWalletBrowserProfile({
      prefix: `steward-phantom-${testInfo.workerIndex}-`,
      prepare: (profile) => cp(sourceProfile, profile, { recursive: true }),
      launch: (profile, env) =>
        chromium.launchPersistentContext(profile, {
          args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`,
          ],
          env,
          headless: false,
        }),
      use,
    });
  },
  extensionId: async ({ walletContext: _ }, use) => {
    await use(PHANTOM_CHROME_EXTENSION_ID);
  },
  phantomPage: async ({ extensionId, walletContext }, use) => {
    const page = await walletContext.newPage();
    await page.goto(`chrome-extension://${extensionId}/popup.html`);
    const phantom = new Phantom(walletContext, page, PHANTOM_PASSWORD, extensionId);
    await phantom.unlock();
    await use(page);
    await page.close();
  },
  dappPage: async ({ walletContext }, use) => {
    const page = await walletContext.newPage();
    await use(page);
    await page.close();
  },
});

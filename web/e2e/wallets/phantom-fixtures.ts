import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type BrowserContext, test as base, chromium, type Page } from "@playwright/test";
import { Phantom } from "@synthetixio/synpress/playwright";
import { PHANTOM_CHROME_EXTENSION_ID, phantomExtensionPath } from "./cache-contract";
import { PHANTOM_CACHE_ID, PHANTOM_PASSWORD } from "./setup/phantom/phantom.setup";

type PhantomFixtures = {
  dappPage: Page;
  extensionId: string;
  phantomPage: Page;
  walletContext: BrowserContext;
};

export const phantomTest = base.extend<PhantomFixtures>({
  walletContext: async ({ browserName: _ }, use, testInfo) => {
    const profile = await mkdtemp(join(tmpdir(), `steward-phantom-${testInfo.workerIndex}-`));
    const sourceProfile = join(process.cwd(), ".cache-synpress", PHANTOM_CACHE_ID);
    await cp(sourceProfile, profile, { recursive: true });

    const extensionPath = phantomExtensionPath();
    const context = await chromium.launchPersistentContext(profile, {
      args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
      headless: false,
    });
    try {
      await use(context);
    } finally {
      await context.close();
      await rm(profile, { force: true, recursive: true });
    }
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

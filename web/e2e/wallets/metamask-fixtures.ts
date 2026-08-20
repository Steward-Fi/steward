import { cp } from "node:fs/promises";
import { join } from "node:path";
import { type BrowserContext, test as base, chromium, type Page } from "@playwright/test";
import { getExtensionId, MetaMask } from "@synthetixio/synpress/playwright";
import { prepareStewardMetaMaskExtension } from "./metamask-extension";
import { METAMASK_CACHE_ID, PASSWORD } from "./setup/metamask/metamask.setup";
import { withWalletBrowserProfile } from "./wallet-browser-profile";

type MetaMaskFixtures = {
  dappPage: Page;
  metamask: MetaMask;
  walletContext: BrowserContext;
};

export async function approveMetaMaskNotification(
  context: BrowserContext,
  extensionId: string,
  buttonName: RegExp,
): Promise<void> {
  const notificationUrl = `chrome-extension://${extensionId}/notification.html`;
  const matchesNotification = (candidate: Page) => candidate.url().startsWith(notificationUrl);
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    for (const page of context.pages().filter(matchesNotification).reverse()) {
      if (page.isClosed()) continue;
      const unlockPassword = page.getByTestId("unlock-password");
      if (await unlockPassword.isVisible().catch(() => false)) {
        await unlockPassword.fill(PASSWORD).catch(() => undefined);
        await page
          .getByRole("button", { name: /^unlock$/i })
          .click()
          .catch(() => undefined);
        continue;
      }
      const button = page.getByRole("button", { name: buttonName });
      if (await button.isVisible().catch(() => false)) {
        await button.click();
        return;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`MetaMask notification action ${buttonName} did not become available`);
}

export const metamaskTest = base.extend<MetaMaskFixtures>({
  walletContext: async ({ browserName: _ }, use, testInfo) => {
    let extensionPath = "";
    await withWalletBrowserProfile({
      prefix: `steward-metamask-${testInfo.workerIndex}-`,
      prepare: async (profile) => {
        await cp(join(process.cwd(), ".cache-synpress", METAMASK_CACHE_ID), profile, {
          recursive: true,
        });
        extensionPath = await prepareStewardMetaMaskExtension();
      },
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
  metamask: async ({ walletContext }, use) => {
    const extensionId = await getExtensionId(walletContext, "MetaMask");
    const page = walletContext.pages()[0] ?? (await walletContext.newPage());
    await page.goto(`chrome-extension://${extensionId}/home.html`);
    const metamask = new MetaMask(walletContext, page, PASSWORD, extensionId);
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      if (
        await page
          .getByTestId("account-menu-icon")
          .isVisible()
          .catch(() => false)
      )
        break;
      if (
        await page
          .getByTestId("unlock-password")
          .isVisible()
          .catch(() => false)
      ) {
        await page.getByTestId("unlock-password").fill(PASSWORD);
        await page.getByTestId("unlock-submit").click({ force: true });
        await page.waitForTimeout(500);
        continue;
      }
      let acted = false;
      for (const name of [/remind me later/i, /skip|got it|confirm/i, /^done$/i, /^next$/i]) {
        const button = page.getByRole("button", { name }).first();
        if (await button.isVisible().catch(() => false)) {
          await button.click();
          acted = true;
          break;
        }
      }
      await page.waitForTimeout(acted ? 500 : 250);
    }
    await page.getByTestId("account-menu-icon").waitFor();
    await page.waitForTimeout(500);
    await use(metamask);
    if (!page.isClosed()) await page.close();
  },
  dappPage: async ({ metamask: _, walletContext }, use) => {
    const page = await walletContext.newPage();
    await use(page);
    await page.close();
  },
});

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type BrowserContext, test as base, chromium, type Page } from "@playwright/test";
import { getExtensionId, MetaMask } from "@synthetixio/synpress/playwright";
import { prepareStewardMetaMaskExtension } from "./metamask-extension";
import { PASSWORD, SEED_PHRASE } from "./setup/metamask/metamask.setup";

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
  const existing = context.pages().find(matchesNotification);
  const page =
    existing ??
    (await context.waitForEvent("page", {
      predicate: matchesNotification,
      timeout: 20_000,
    }));
  await page.waitForLoadState("domcontentloaded");
  await page.getByRole("button", { name: buttonName }).click();
}

async function importMetaMask12(page: Page): Promise<void> {
  await page.getByTestId("onboarding-terms-checkbox").click();
  await page.getByTestId("onboarding-import-wallet").click();
  await page.getByTestId("metametrics-no-thanks").click();
  for (const [index, word] of SEED_PHRASE.split(" ").entries()) {
    await page.getByTestId(`import-srp__srp-word-${index}`).fill(word);
  }
  await page.getByTestId("import-srp-confirm").click();
  await page.getByTestId("create-password-new").fill(PASSWORD);
  await page.getByTestId("create-password-confirm").fill(PASSWORD);
  await page.getByTestId("create-password-terms").click();
  await page.getByTestId("create-password-import").click();

  await page.getByRole("button", { exact: true, name: "Done" }).click();
  await page.waitForTimeout(1_500);
}

async function finishAndCloseMetaMaskOnboarding(context: BrowserContext): Promise<void> {
  for (let round = 0; round < 8; round += 1) {
    let acted = false;
    for (const page of context.pages()) {
      if (page.isClosed() || !page.url().startsWith("chrome-extension://")) continue;
      for (const name of [/remind me later/i, /skip|got it|confirm/i, /^done$/i, /^next$/i]) {
        const button = page.getByRole("button", { name }).first();
        if (await button.isVisible().catch(() => false)) {
          await button.click().catch(() => undefined);
          acted = true;
          break;
        }
      }
    }
    if (!acted) break;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  for (const page of context.pages()) {
    if (!page.isClosed() && page.url().startsWith("chrome-extension://")) {
      await page.close();
    }
  }
}

export const metamaskTest = base.extend<MetaMaskFixtures>({
  walletContext: async ({ browserName: _ }, use, testInfo) => {
    const profile = await mkdtemp(join(tmpdir(), `steward-metamask-${testInfo.workerIndex}-`));
    const extensionPath = await prepareStewardMetaMaskExtension();
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
  metamask: async ({ walletContext }, use) => {
    const extensionId = await getExtensionId(walletContext, "MetaMask");
    const onboardingPage = walletContext.pages()[0] ?? (await walletContext.newPage());
    await onboardingPage.goto(`chrome-extension://${extensionId}/home.html`);
    await importMetaMask12(onboardingPage);
    await finishAndCloseMetaMaskOnboarding(walletContext);

    // Keep the driver on a fresh page after every auto-opened onboarding tab
    // has reached a terminal state.
    const page = await walletContext.newPage();
    await page.goto(`chrome-extension://${extensionId}/home.html`);
    const metamask = new MetaMask(walletContext, page, PASSWORD, extensionId);
    if (
      await page
        .getByTestId("unlock-password")
        .isVisible()
        .catch(() => false)
    ) {
      await metamask.unlock();
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

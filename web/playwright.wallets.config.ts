/**
 * Headful wallet-extension Playwright config.
 *
 * Kept separate from playwright.config.ts because Synpress controls the
 * browser launch context itself (loads MetaMask + Phantom extensions into a
 * persistent chromium context) and is incompatible with Playwright's
 * cross-browser device emulation.
 *
 * Run:
 *   bun run e2e:wallets:cache   # one-time, primes MetaMask + Phantom
 *   bun run e2e:wallets         # executes the headful suite
 */

import { defineConfig } from "@playwright/test";

const BASE_URL = process.env.E2E_WEB_URL ?? "http://localhost:3499";

export default defineConfig({
  testDir: "./e2e/wallets",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  timeout: 120_000,
  expect: { timeout: 15_000 },

  globalSetup: require.resolve("./e2e/global-setup.ts"),
  globalTeardown: require.resolve("./e2e/global-teardown.ts"),

  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [{ name: "wallets" }],
});

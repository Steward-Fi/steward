import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.E2E_WEB_URL ?? "http://localhost:3499";

export default defineConfig({
  testDir: "./e2e",
  testIgnore: ["**/global-setup.ts", "**/global-teardown.ts", "**/fixtures/**", "**/wallets/**"],
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  // One retry absorbs inherent UI-timing flakiness in the dashboard render
  // tests (e.g. a select value or freshly-created table row not yet painted).
  // The API/auth-flow tests are deterministic and do not depend on this; a
  // genuinely broken test still fails both attempts.
  retries: 1,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  timeout: 60_000,
  expect: { timeout: 10_000 },

  globalSetup: require.resolve("./e2e/global-setup.ts"),
  globalTeardown: require.resolve("./e2e/global-teardown.ts"),

  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});

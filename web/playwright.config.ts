import { defineConfig, devices } from "@playwright/test";

const BASE_URL = process.env.E2E_WEB_URL ?? "http://localhost:3499";
const DEV_SERVER_SPECS = new Set(["intents-reviewer-mfa.spec.ts"]);

function shouldUseNextDevServer(): boolean {
  if (process.env.E2E_NEXT_DEV === "true") return true;
  return process.argv.some((arg) =>
    [...DEV_SERVER_SPECS].some((spec) => arg.endsWith(spec) || arg.includes(`/${spec}`)),
  );
}

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
    bypassCSP: shouldUseNextDevServer(),
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], bypassCSP: shouldUseNextDevServer() },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"], bypassCSP: shouldUseNextDevServer() },
    },
    { name: "webkit", use: { ...devices["Desktop Safari"], bypassCSP: shouldUseNextDevServer() } },
  ],
});

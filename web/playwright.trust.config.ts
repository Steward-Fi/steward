import { defineConfig, devices } from "@playwright/test";

const WEB = "http://127.0.0.1:3499";

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["provider-trust-ux-a11y.spec.ts", "middleware-runtime.spec.ts"],
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "list",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    ...devices["Desktop Chrome"],
    baseURL: WEB,
    bypassCSP: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command:
      "mkdir -p .next/standalone/web/.next && cp -R .next/static .next/standalone/web/.next/ && cp -R public .next/standalone/web/ && node .next/standalone/web/server.js",
    cwd: ".",
    url: `${WEB}/login`,
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      NEXT_PUBLIC_STEWARD_API_URL: "http://127.0.0.1:3299",
      E2E_ALLOW_INSECURE_HTTP: "true",
      NEXT_TELEMETRY_DISABLED: "1",
      HOSTNAME: "127.0.0.1",
      PORT: "3499",
    },
  },
  projects: [{ name: "trust-ux-chromium" }],
});

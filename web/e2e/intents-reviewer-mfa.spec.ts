import { expect, type Page, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type MockIntentStatus = "pending" | "authorized";

const apiOrigin = new URL(API);

function isApiRequest(url: string): boolean {
  const parsed = new URL(url);
  return url.startsWith(API) || parsed.port === apiOrigin.port;
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function testSessionToken(email: string): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      address: "0x0000000000000000000000000000000000000001",
      email,
      exp: now + 3600,
      iat: now,
      role: "owner",
      tenantId: "personal-test",
      tenantRole: "owner",
      userId: "reviewer-user",
    }),
    "signature",
  ].join(".");
}

async function seedDashboardSession(page: Page, email: string): Promise<void> {
  const token = testSessionToken(email);
  await page.addInitScript((sessionToken) => {
    window.sessionStorage.setItem("steward_session_token", sessionToken);
    window.sessionStorage.setItem("steward_refresh_token", "intent-reviewer-refresh-token");
  }, token);
}

function mockIntent(status: MockIntentStatus = "pending") {
  return {
    id: "intent-review",
    intent_id: "intent-review",
    tenantId: "personal-test",
    agentId: "agent-review",
    wallet_id: "agent-review",
    intentType: "wallet_update",
    intent_type: "wallet_update",
    status,
    resourceType: "agent_wallet",
    resource_id: "agent-review",
    resourceId: "agent-review",
    createdByType: "user",
    created_by_id: "creator-user",
    createdById: "creator-user",
    created_by_display_name: "creator@example.test",
    createdByDisplayName: "creator@example.test",
    authorizationDetails: [],
    authorization_details: [],
    payload: { displayName: "Treasury" },
    executionResult: null,
    execution_result: null,
    expiresAt: "2026-06-05T12:00:00.000Z",
    expires_at: 1780660800000,
    authorizedBy: status === "authorized" ? "reviewer-user" : null,
    authorized_by: status === "authorized" ? "reviewer-user" : null,
    canceledAt: null,
    canceledBy: null,
    cancellationReason: null,
    expiredAt: null,
    expiredBy: null,
    rejectedAt: null,
    rejectedBy: null,
    rejectionReason: null,
    executedBy: null,
    failedAt: null,
    failedBy: null,
    failureReason: null,
    createdAt: "2026-06-04T12:00:00.000Z",
    created_at: 1780574400000,
    updatedAt: "2026-06-04T12:00:00.000Z",
    updated_at: 1780574400000,
  };
}

async function mockIntentReviewApis(page: Page, mfaEnabled: boolean) {
  let currentIntent = mockIntent();

  const isApiPath = (url: URL, pathname: string) =>
    isApiRequest(url.href) && url.pathname === pathname;

  await page.route(
    (url) => isApiPath(url, "/auth/mfa/totp/status"),
    async (route) => {
      await route.fulfill({ json: { ok: true, enabled: mfaEnabled, pending: false } });
    },
  );
  await page.route(
    (url) => isApiPath(url, "/auth/mfa/sms/status"),
    async (route) => {
      await route.fulfill({ json: { ok: true, enabled: false, pending: false } });
    },
  );
  await page.route(
    (url) => isApiPath(url, "/intents"),
    async (route) => {
      if (route.request().method() !== "GET") {
        await route.fallback();
        return;
      }
      await route.fulfill({
        json: { ok: true, data: { intents: [currentIntent], limit: 200, offset: 0 } },
      });
    },
  );
  await page.route(
    (url) => isApiPath(url, "/intents/intent-review/approve"),
    async (route) => {
      currentIntent = mockIntent("authorized");
      await route.fulfill({ json: { ok: true, data: currentIntent } });
    },
  );
}

async function mockLegacyBootstrapApis(page: Page) {
  await page.route(
    (url) => isApiRequest(url.href),
    async (route) => {
      const url = new URL(route.request().url());
      if (url.pathname === "/health") {
        await route.fulfill({ json: { ok: true, status: "ok" } });
        return;
      }
      if (url.pathname === "/auth/providers") {
        await route.fulfill({
          json: {
            ok: true,
            email: true,
            passkey: true,
            oauth: { google: false, discord: false, github: false, twitter: false },
          },
        });
        return;
      }
      if (url.pathname === "/tenants/config") {
        await route.fulfill({ json: { ok: true, data: {} } });
        return;
      }
      if (url.pathname === "/user/me/tenants") {
        await route.fulfill({
          json: {
            ok: true,
            data: [
              {
                tenantId: "personal-test",
                tenantName: "Personal Test",
                role: "owner",
              },
            ],
          },
        });
        return;
      }
      if (url.pathname === "/user/me") {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              user: {
                id: "reviewer-user",
                email: "reviewer@example.test",
              },
              activeTenantId: "personal-test",
            },
          },
        });
        return;
      }
      await route.fallback();
    },
  );
}

test.describe("Dashboard intent reviewer MFA UX", () => {
  test.setTimeout(180_000);

  test("warns and disables review actions when reviewer MFA is not enrolled", async ({
    page,
  }, testInfo) => {
    await seedDashboardSession(page, `intent-review-mfa-missing-${Date.now()}@example.test`);
    await mockIntentReviewApis(page, false);
    await mockLegacyBootstrapApis(page);

    await expect(async () => {
      const response = await page.goto(`${WEB}/dashboard/intents`, {
        waitUntil: "domcontentloaded",
        timeout: 120_000,
      });
      expect(response?.status()).not.toBe(404);
      await expect(page.getByRole("heading", { name: "Intents" })).toBeVisible();
    }).toPass({ timeout: 120_000 });

    await expect(page.getByTestId("intent-reviewer-mfa-warning")).toContainText(
      "Reviewer MFA required",
    );
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Reject", exact: true })).toBeDisabled();
    await expect(page.getByRole("link", { name: "Open Account MFA" })).toHaveAttribute(
      "href",
      "/dashboard/account",
    );
    await page.screenshot({
      path: testInfo.outputPath("dashboard-intents-reviewer-mfa-missing.png"),
      fullPage: true,
    });
  });

  test("enables approval once reviewer MFA is enrolled", async ({ page }, testInfo) => {
    await seedDashboardSession(page, `intent-review-mfa-ready-${Date.now()}@example.test`);
    await mockIntentReviewApis(page, true);
    await mockLegacyBootstrapApis(page);

    await expect(async () => {
      const response = await page.goto(`${WEB}/dashboard/intents`, {
        waitUntil: "domcontentloaded",
        timeout: 120_000,
      });
      expect(response?.status()).not.toBe(404);
      await expect(page.getByRole("heading", { name: "Intents" })).toBeVisible();
    }).toPass({ timeout: 120_000 });

    await expect(page.getByTestId("intent-reviewer-mfa-warning")).toHaveCount(0);
    await page.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page.getByText("Approve updated")).toBeVisible();
    await expect(page.getByText("Authorized").first()).toBeVisible();
    await page.screenshot({
      path: testInfo.outputPath("dashboard-intents-reviewer-mfa-approved.png"),
      fullPage: true,
    });
  });
});

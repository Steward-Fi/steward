import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";

const API = "http://127.0.0.1:3299";
const ACTION_ID = "pa_00000000-0000-4000-8000-000000000001";
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sessionToken(): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      email: "trust-reviewer@example.test",
      exp: now + 3600,
      iat: now,
      role: "owner",
      tenantId: "tenant-trust",
      tenantRole: "owner",
      userId: "trust-reviewer",
    }),
    "test-signature",
  ].join(".");
}

async function seedSession(page: Page): Promise<void> {
  await page.addInitScript((token) => {
    window.sessionStorage.setItem("steward_session_token", token);
    window.sessionStorage.setItem("steward_refresh_token", "trust-refresh-token");
  }, sessionToken());
}

function approvalDetail(status = "pending_approval") {
  return {
    id: ACTION_ID,
    status,
    version: status === "pending_approval" ? 1 : 2,
    requestHash: HASH_A,
    actionDigest: HASH_B,
    expiresAt: "2026-08-16T23:30:00.000Z",
    safeSummary: { operation: "github.pr.comment.create", repository: "Steward-Fi/steward" },
    operationId: "operation-trust",
    providerAccountId: "account-trust",
    workspaceId: "workspace-trust",
  };
}

function caseManifest() {
  return {
    caseId: ACTION_ID,
    tenantId: "tenant-trust",
    workspaceId: "workspace-trust",
    terminalState: "succeeded",
    completeness: "complete",
    missingRequiredRoles: [],
    incompletenessReasons: [],
    actionDigest: HASH_B,
    requestHash: HASH_A,
    idempotencyKeyHash: `sha256:${"c".repeat(64)}`,
    operation: {
      id: "operation-trust",
      key: "github.pr.comment.create",
      revision: 1,
      riskClass: "consequential",
    },
    execution: {
      dispatchState: "succeeded",
      upstreamStatusCode: 201,
      reconciled: false,
      providerIdempotencyKeyHash: `sha256:${"d".repeat(64)}`,
    },
    safeSummary: { operation: "github.pr.comment.create" },
    genesisAt: "2026-08-16T22:00:00.000Z",
    terminalAt: "2026-08-16T22:01:00.000Z",
  };
}

async function mockTrustApis(page: Page): Promise<{ decisions: string[] }> {
  const decisions: string[] = [];
  let status = "pending_approval";
  await page.route(`${API}/**`, async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/health") return route.fulfill({ json: { ok: true, status: "ok" } });
    if (path === "/auth/providers") {
      return route.fulfill({ json: { ok: true, email: true, passkey: true, oauth: {} } });
    }
    if (path === "/tenants/config") return route.fulfill({ json: { ok: true, data: {} } });
    if (path === "/user/me/tenants") {
      return route.fulfill({
        json: {
          ok: true,
          data: [{ tenantId: "tenant-trust", tenantName: "Trust", role: "owner" }],
        },
      });
    }
    if (path === "/user/me") {
      return route.fulfill({
        json: {
          ok: true,
          data: {
            user: { id: "trust-reviewer", email: "trust-reviewer@example.test" },
            activeTenantId: "tenant-trust",
          },
        },
      });
    }
    if (path === `/v2/provider-actions/${ACTION_ID}/approval`) {
      if (request.method() === "GET") {
        return route.fulfill({ json: { ok: true, data: approvalDetail(status) } });
      }
      const body = request.postDataJSON() as { decision: string; reason: string };
      decisions.push(body.decision);
      status = body.decision === "approve" ? "approved" : "denied";
      return route.fulfill({ json: { id: ACTION_ID, status, version: 2 } });
    }
    if (path === `/v2/provider-actions/${ACTION_ID}/case`) {
      return route.fulfill({ json: caseManifest() });
    }
    return route.fulfill({ status: 404, json: { ok: false, error: "NOT_FOUND" } });
  });
  return { decisions };
}

async function focusWithTab(page: Page, target: Locator): Promise<void> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await page.keyboard.press("Tab");
    if (await target.evaluate((element) => document.activeElement === element)) return;
  }
  throw new Error("target was not reachable with keyboard Tab navigation");
}

async function expectWcag21Aa(page: Page, include: string): Promise<void> {
  const results = await new AxeBuilder({ page })
    .include(include)
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  const violations = results.violations.map(({ id, impact, nodes }) => ({
    id,
    impact,
    targets: nodes.map((node) => node.target),
  }));
  expect(violations).toEqual([]);
}

test.beforeEach(async ({ page }) => {
  await seedSession(page);
});

test("approval detail passes WCAG 2.1 AA and approve/deny complete keyboard-only", async ({
  browser,
  page,
}) => {
  const mocked = await mockTrustApis(page);
  await page.goto(`/dashboard/approvals/${ACTION_ID}`);
  await expect(page.getByRole("heading", { name: "Provider action approval" })).toBeVisible();
  await expectWcag21Aa(page, 'main[aria-labelledby="approval-detail-heading"]');

  const reason = page.getByLabel("Reason (required for approve and deny)");
  await focusWithTab(page, reason);
  await page.keyboard.type("Approved after exact-request review");
  await focusWithTab(page, page.getByRole("button", { name: "Approve this provider action" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText("Decision recorded: approve")).toBeVisible();
  expect(mocked.decisions).toEqual(["approve"]);

  const denyContext = await browser.newContext();
  const denyPage = await denyContext.newPage();
  await seedSession(denyPage);
  const denyMocked = await mockTrustApis(denyPage);
  await denyPage.goto(`/dashboard/approvals/${ACTION_ID}`);
  await expect(denyPage.getByRole("heading", { name: "Provider action approval" })).toBeVisible();
  const denyReason = denyPage.getByLabel("Reason (required for approve and deny)");
  await focusWithTab(denyPage, denyReason);
  await denyPage.keyboard.type("Denied after exact-request review");
  await focusWithTab(denyPage, denyPage.getByRole("button", { name: "Deny this provider action" }));
  await denyPage.keyboard.press("Enter");
  await expect(denyPage.getByText("Decision recorded: deny")).toBeVisible();
  expect(denyMocked.decisions).toEqual(["deny"]);
  await denyContext.close();
});

test("case detail passes WCAG 2.1 AA without widening the scan", async ({ page }) => {
  await mockTrustApis(page);
  await page.goto(`/dashboard/actions/${ACTION_ID}`);
  await expect(page.getByRole("heading", { name: "Provider action case" })).toBeVisible();
  await expectWcag21Aa(page, 'main[aria-labelledby="case-heading"]');
});

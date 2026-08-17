import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, test } from "@playwright/test";

const API = "http://127.0.0.1:3299";
const ACTION_ID = "pa_00000000-0000-4000-8000-000000000001";
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;

type ApprovalAttempt = {
  body: Record<string, unknown>;
  authorization: string | null;
  tenant: string | null;
  accepted: boolean;
};

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

/**
 * Browser-only fixture for accessibility and keyboard interaction. This does
 * NOT prove API authentication: real auth/MFA remains covered by API suites.
 * The fixture nevertheless fails closed on missing auth or binding mismatch so
 * the UI cannot pass while sending an incomplete approval request.
 */
async function mockAccessibilityApis(page: Page): Promise<{ attempts: ApprovalAttempt[] }> {
  const attempts: ApprovalAttempt[] = [];
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
      const body = request.postDataJSON() as Record<string, unknown>;
      const authorization = request.headers().authorization ?? null;
      const tenant = request.headers()["x-steward-tenant"] ?? null;
      const expectedIdempotencyKey =
        `decide-${body.decision}-${ACTION_ID}-${body.expectedVersion}-${body.expectedActionDigest}`.slice(
          0,
          255,
        );
      const accepted =
        (body.decision === "approve" || body.decision === "deny") &&
        typeof body.reason === "string" &&
        body.reason.trim().length > 0 &&
        body.expectedVersion === 1 &&
        body.expectedRequestHash === HASH_A &&
        body.expectedActionDigest === HASH_B &&
        body.idempotencyKey === expectedIdempotencyKey &&
        !("reasonCode" in body) &&
        authorization?.startsWith("Bearer ") === true &&
        tenant === "tenant-trust";
      attempts.push({ body, authorization, tenant, accepted });
      if (!accepted) {
        return route.fulfill({
          status: 409,
          json: { ok: false, error: { code: "APPROVAL_BINDING_MISMATCH" } },
        });
      }
      status = body.decision === "approve" ? "approved" : "denied";
      return route.fulfill({ json: { id: ACTION_ID, status, version: 2 } });
    }
    if (path === `/v2/provider-actions/${ACTION_ID}/case`) {
      return route.fulfill({ json: caseManifest() });
    }
    return route.fulfill({ status: 404, json: { ok: false, error: "NOT_FOUND" } });
  });
  return { attempts };
}

async function focusWithTab(page: Page, target: Locator): Promise<void> {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await page.keyboard.press("Tab");
    if (await target.evaluate((element) => document.activeElement === element)) return;
  }
  throw new Error("target was not reachable with keyboard Tab navigation");
}

async function expectWcag21Aa(page: Page, include: string): Promise<void> {
  const root = page.locator(include);
  await expect(root).toBeAttached();
  await expect(root).toBeVisible();
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

test("mocked-session approval detail passes WCAG 2.1 AA and complete binding is keyboard-only", async ({
  browser,
  page,
}) => {
  const mocked = await mockAccessibilityApis(page);
  await page.goto(`/dashboard/approvals/${ACTION_ID}`);
  await expect(page.getByRole("heading", { name: "Provider action approval" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Exact action" })).toBeVisible();
  await expectWcag21Aa(page, 'main[aria-labelledby="approval-detail-heading"]');

  // The mock is deliberately fail-closed: a stale/mismatched commitment must
  // be rejected and must not alter the pending approval state.
  const mismatchStatus = await page.evaluate(
    async ({ api, actionId, hashB }) => {
      const token = window.sessionStorage.getItem("steward_session_token");
      const response = await fetch(`${api}/v2/provider-actions/${actionId}/approval`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          "X-Steward-Tenant": "tenant-trust",
        },
        body: JSON.stringify({
          decision: "approve",
          reason: "stale binding must fail",
          expectedVersion: 1,
          expectedRequestHash: "sha256:wrong",
          expectedActionDigest: hashB,
          idempotencyKey: `decide-approve-${actionId}-1-${hashB}`,
        }),
      });
      return response.status;
    },
    { api: API, actionId: ACTION_ID, hashB: HASH_B },
  );
  expect(mismatchStatus).toBe(409);
  expect(mocked.attempts[0]).toMatchObject({ accepted: false, tenant: "tenant-trust" });

  const reason = page.getByLabel("Reason (required for approve and deny)");
  await focusWithTab(page, reason);
  await page.keyboard.type("Approved after exact-request review");
  await focusWithTab(page, page.getByRole("button", { name: "Approve this provider action" }));
  await page.keyboard.press("Enter");
  await expect(page.getByText("Decision recorded: approve")).toBeVisible();
  expect(mocked.attempts).toHaveLength(2);
  expect(mocked.attempts[1]).toMatchObject({
    accepted: true,
    tenant: "tenant-trust",
    body: {
      decision: "approve",
      reason: "Approved after exact-request review",
      expectedVersion: 1,
      expectedRequestHash: HASH_A,
      expectedActionDigest: HASH_B,
      idempotencyKey: `decide-approve-${ACTION_ID}-1-${HASH_B}`,
    },
  });
  expect(mocked.attempts[1]?.authorization).toMatch(/^Bearer /);
  expect(Object.keys(mocked.attempts[1]?.body ?? {}).sort()).toEqual(
    [
      "decision",
      "expectedActionDigest",
      "expectedRequestHash",
      "expectedVersion",
      "idempotencyKey",
      "reason",
    ].sort(),
  );

  const denyContext = await browser.newContext();
  const denyPage = await denyContext.newPage();
  await seedSession(denyPage);
  const denyMocked = await mockAccessibilityApis(denyPage);
  await denyPage.goto(`/dashboard/approvals/${ACTION_ID}`);
  await expect(denyPage.getByRole("heading", { name: "Provider action approval" })).toBeVisible();
  await expect(denyPage.getByRole("heading", { name: "Exact action" })).toBeVisible();
  const denyReason = denyPage.getByLabel("Reason (required for approve and deny)");
  await focusWithTab(denyPage, denyReason);
  await denyPage.keyboard.type("Denied after exact-request review");
  await focusWithTab(denyPage, denyPage.getByRole("button", { name: "Deny this provider action" }));
  await denyPage.keyboard.press("Enter");
  await expect(denyPage.getByText("Decision recorded: deny")).toBeVisible();
  expect(denyMocked.attempts).toHaveLength(1);
  expect(denyMocked.attempts[0]).toMatchObject({
    accepted: true,
    tenant: "tenant-trust",
    body: {
      decision: "deny",
      reason: "Denied after exact-request review",
      expectedVersion: 1,
      expectedRequestHash: HASH_A,
      expectedActionDigest: HASH_B,
      idempotencyKey: `decide-deny-${ACTION_ID}-1-${HASH_B}`,
    },
  });
  await denyContext.close();
});

test("mocked-session case detail passes WCAG 2.1 AA without widening the scan", async ({
  page,
}) => {
  await mockAccessibilityApis(page);
  await page.goto(`/dashboard/actions/${ACTION_ID}`);
  await expect(page.getByRole("heading", { name: "Provider action case" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Commitments" })).toBeVisible();
  await expectWcag21Aa(page, 'main[aria-labelledby="case-heading"]');
});

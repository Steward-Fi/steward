import { readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, type Locator, type Page, type Route, test } from "@playwright/test";

const API = "http://127.0.0.1:3299";
const ACTION_ID = "pa_00000000-0000-4000-8000-000000000001";
const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const PROVIDER_IDEMPOTENCY_HASH = `sha256:${"d".repeat(64)}`;
const RAW_CANONICAL_BYTES = "raw-canonical-provider-action-must-not-render";
const RAW_CREDENTIAL = "ghp_raw-provider-secret-must-not-render";

type ApprovalAttempt = {
  body: Record<string, unknown>;
  authorization: string | null;
  tenant: string | null;
  accepted: boolean;
};

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sessionToken(
  tenantId = "tenant-trust",
  userId = "trust-reviewer",
  expiresInSeconds = 3600,
): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      email: "trust-reviewer@example.test",
      exp: now + expiresInSeconds,
      iat: now,
      role: "owner",
      tenantId,
      tenantRole: "owner",
      userId,
    }),
    "test-signature",
  ].join(".");
}

async function seedSession(page: Page, tenantId = "tenant-trust"): Promise<string> {
  const token = sessionToken(tenantId);
  await page.addInitScript((token) => {
    window.sessionStorage.setItem("steward_session_token", token);
    window.sessionStorage.setItem("steward_refresh_token", "trust-refresh-token");
  }, token);
  return token;
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
    // Deliberately hostile extra fields prove that the reachable page renders
    // its safe projection rather than reflecting an over-broad API payload.
    canonicalBytes: RAW_CANONICAL_BYTES,
    canonicalActionBytes: RAW_CANONICAL_BYTES,
    commentBody: RAW_CANONICAL_BYTES,
    credential: { value: RAW_CREDENTIAL },
  };
}

function approvalQueueItem(tenant: "a" | "b") {
  return {
    id: `approval-${tenant}`,
    txId: `transaction-${tenant}`,
    agentId: `agent-${tenant}`,
    agentName: `Tenant ${tenant.toUpperCase()} agent`,
    status: "pending",
    requestedAt: "2026-08-16T22:00:00.000Z",
    chainId: 8453,
    toAddress: `0x${(tenant === "a" ? "1" : "2").repeat(40)}`,
    value: "1",
  };
}

function caseManifest(
  overrides: Partial<ReturnType<typeof baseCaseManifest>> & Record<string, unknown> = {},
) {
  return { ...baseCaseManifest(), ...overrides };
}

function baseCaseManifest() {
  return {
    caseId: ACTION_ID,
    tenantId: "tenant-trust",
    workspaceId: "workspace-trust",
    terminalState: "succeeded",
    completeness: "complete" as "complete" | "incomplete" | "unknown",
    missingRequiredRoles: [] as string[],
    incompletenessReasons: [] as string[],
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
      providerIdempotencyKeyHash: PROVIDER_IDEMPOTENCY_HASH,
    },
    safeSummary: { operation: "github.pr.comment.create" },
    genesisAt: "2026-08-16T22:00:00.000Z",
    terminalAt: "2026-08-16T22:01:00.000Z",
  };
}

interface TrustFixtureOptions {
  tenants?: Array<{ tenantId: string; tenantName: string; role: string }>;
  approvalStatus?: string;
  approvalErrorStatus?: number;
  approvalDecisionError?: { status: number; body: unknown };
  caseErrorStatus?: number;
  caseErrorBody?: unknown;
  manifest?: ReturnType<typeof baseCaseManifest> & Record<string, unknown>;
}

/**
 * Browser-only fixture for accessibility and keyboard interaction. This does
 * NOT prove API authentication: real auth/MFA remains covered by API suites.
 * The fixture nevertheless fails closed on missing auth or binding mismatch so
 * the UI cannot pass while sending an incomplete approval request.
 */
async function mockAccessibilityApis(
  page: Page,
  options: TrustFixtureOptions = {},
): Promise<{ attempts: ApprovalAttempt[] }> {
  const attempts: ApprovalAttempt[] = [];
  let status = options.approvalStatus ?? "pending_approval";
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
          data: options.tenants ?? [
            { tenantId: "tenant-trust", tenantName: "Trust", role: "owner" },
          ],
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
    if (path === "/approvals") {
      return route.fulfill({
        json: {
          ok: true,
          data: [
            {
              id: "approval-trust",
              txId: "transaction-trust",
              agentId: "agent-trust",
              agentName: "Trust agent",
              status: "pending",
              requestedAt: "2026-08-16T22:00:00.000Z",
              chainId: 8453,
              toAddress: `0x${"1".repeat(40)}`,
              value: "1",
            },
          ],
        },
      });
    }
    if (path === `/v2/provider-actions/${ACTION_ID}/approval`) {
      if (request.method() === "GET") {
        if (options.approvalErrorStatus) {
          return route.fulfill({
            status: options.approvalErrorStatus,
            json: { ok: false, error: { code: `PRIVATE_${options.approvalErrorStatus}` } },
          });
        }
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
      if (options.approvalDecisionError) {
        return route.fulfill({
          status: options.approvalDecisionError.status,
          json: options.approvalDecisionError.body,
        });
      }
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
      if (options.caseErrorStatus) {
        return route.fulfill({
          status: options.caseErrorStatus,
          json:
            options.caseErrorBody ?? {
              ok: false,
              error: { code: `PRIVATE_${options.caseErrorStatus}` },
            },
        });
      }
      return route.fulfill({ json: options.manifest ?? caseManifest() });
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

  const approve = page.getByRole("button", { name: "Approve this provider action" });
  const deny = page.getByRole("button", { name: "Deny this provider action" });
  await expect(page.getByLabel("Reason (required for approve and deny)")).toHaveAttribute(
    "aria-required",
    "true",
  );
  const [approveBox, denyBox] = await Promise.all([approve.boundingBox(), deny.boundingBox()]);
  expect(approveBox?.width).toBe(denyBox?.width);
  expect(approveBox?.height).toBe(denyBox?.height);
  await expect(page.getByLabel("Redacted safe summary")).toContainText(
    '"operation": "github.pr.comment.create"',
  );
  await expect(page.getByLabel("Redacted safe summary")).toContainText(
    '"repository": "Steward-Fi/steward"',
  );
  await expect(page.getByText(HASH_A)).toBeVisible();
  await expect(page.getByText(HASH_B)).toBeVisible();
  await expect(page.getByText(RAW_CANONICAL_BYTES)).toHaveCount(0);
  await expect(page.getByText(RAW_CREDENTIAL)).toHaveCount(0);

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

  await approve.click();
  await expect(
    page.getByText("A typed reason is required for both approve and deny."),
  ).toBeVisible();
  expect(mocked.attempts).toHaveLength(1);

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
  await denyPage.getByRole("button", { name: "Deny this provider action" }).click();
  await expect(
    denyPage.getByText("A typed reason is required for both approve and deny."),
  ).toBeVisible();
  expect(denyMocked.attempts).toHaveLength(0);
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
  await expect(page.getByRole("status").filter({ hasText: "Completeness: complete" })).toHaveClass(
    /border-success/,
  );
  await expectWcag21Aa(page, 'main[aria-labelledby="case-heading"]');
});

test("the approval queue loads once and exposes per-item decisions", async ({ page }) => {
  let approvalRequests = 0;
  const approvalRequestCredentials: Array<string | null> = [];
  page.on("request", (request) => {
    if (request.method() === "GET" && new URL(request.url()).pathname === "/approvals") {
      approvalRequests += 1;
      approvalRequestCredentials.push(request.headers().authorization ?? null);
    }
  });
  await mockAccessibilityApis(page);
  await page.goto("/dashboard");
  await page.waitForTimeout(1_000);
  await page.getByRole("link", { name: "Approvals", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Approval Queue" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Reject", exact: true })).toHaveCount(1);
  await expect(
    page.getByRole("button", { name: /bulk approve|approve all|select all/i }),
  ).toHaveCount(0);
  await expect(page.getByRole("checkbox", { name: /select all/i })).toHaveCount(0);
  await page.waitForTimeout(1_000);
  const installedToken = await page.evaluate(() =>
    window.sessionStorage.getItem("steward_session_token"),
  );
  expect(installedToken).not.toBeNull();
  expect(approvalRequestCredentials).toEqual([`Bearer ${installedToken}`]);
  expect(approvalRequests).toBe(1);
});

test("the approval queue remains actionable while optional wallet chunks never settle", async ({
  page,
}) => {
  const chunkRoot = join(process.cwd(), ".next", "static", "chunks");
  const walletChunkPaths = new Set<string>();
  const inspectChunks = (directory: string) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        inspectChunks(path);
        continue;
      }
      if (!entry.name.endsWith(".js")) continue;
      const chunkPath = relative(chunkRoot, path).split(sep).join("/");
      // App-router entry chunks bootstrap the page and may also contain the
      // loader callsite. Only stall the asynchronously loaded wallet chunks.
      if (chunkPath.startsWith("app/")) continue;
      const source = readFileSync(path, "utf8");
      if (source.includes("EVMWalletProvider") || source.includes("getWagmiConfig")) {
        walletChunkPaths.add(`/_next/static/chunks/${chunkPath}`);
      }
    }
  };
  inspectChunks(chunkRoot);
  expect(walletChunkPaths.size).toBeGreaterThan(0);

  let stalledOptionalChunks = 0;
  await page.route("**/_next/static/chunks/*.js", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (!walletChunkPaths.has(path)) {
      await route.continue();
      return;
    }
    stalledOptionalChunks += 1;
    // Keep the optional dynamic imports unresolved beyond the assertion
    // window. Abort afterward so Playwright can tear the route down cleanly.
    await new Promise((resolve) => setTimeout(resolve, 15_000));
    await route.abort("timedout");
  });

  await seedSession(page);
  await mockAccessibilityApis(page);
  await page.goto("/dashboard/approvals", { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: "Approval Queue" })).toBeVisible({
    timeout: 5_000,
  });
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "Reject", exact: true })).toBeEnabled();
  expect(stalledOptionalChunks).toBeGreaterThan(0);
});

test("a later same-session remount refreshes the approval queue", async ({ page }) => {
  let approvalRequests = 0;
  let queueTenant: "a" | "b" = "a";
  await mockAccessibilityApis(page);
  await page.route(`${API}/approvals**`, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    approvalRequests += 1;
    await route.fulfill({ json: { ok: true, data: [approvalQueueItem(queueTenant)] } });
  });

  await page.goto("/dashboard/approvals");
  await expect(page.getByText("Tenant A agent")).toBeVisible();
  expect(approvalRequests).toBe(1);

  await page.goto("/dashboard");
  queueTenant = "b";
  await page.getByRole("link", { name: "Approvals", exact: true }).click();
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);
  expect(approvalRequests).toBe(2);
});

test("tenant switching clears the queue and ignores a delayed prior-tenant response", async ({
  page,
}) => {
  let tenantARequests = 0;
  const delayedTenantA: { current: Route | null } = { current: null };
  const tenantBToken = sessionToken("tenant-b");

  await page.route("**/api/auth/refresh", async (route) => {
    const body = route.request().postDataJSON() as { tenantId?: string };
    expect(body.tenantId).toBe("tenant-b");
    await route.fulfill({
      json: { ok: true, token: tenantBToken, expiresIn: 3600 },
    });
  });
  await mockAccessibilityApis(page, {
    tenants: [
      { tenantId: "tenant-trust", tenantName: "Tenant A", role: "owner" },
      { tenantId: "tenant-b", tenantName: "Tenant B", role: "owner" },
    ],
  });
  await page.route(`${API}/approvals**`, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    const authorization = route.request().headers().authorization ?? null;
    if (authorization === `Bearer ${tenantBToken}`) {
      await route.fulfill({ json: { ok: true, data: [approvalQueueItem("b")] } });
      return;
    }
    tenantARequests += 1;
    if (tenantARequests === 1) {
      await route.fulfill({
        status: 503,
        json: { ok: false, error: { code: "TEMPORARY", message: "try again" } },
      });
      return;
    }
    // Deliberately leave the retried tenant-A request pending. Returning from
    // the handler lets tenant-list, refresh, and tenant-B requests continue.
    delayedTenantA.current = route;
  });

  await page.goto("/dashboard/approvals");
  await expect(page.getByText("Failed to load approvals")).toBeVisible();
  await page.getByRole("button", { name: "Retry" }).click();
  await expect.poll(() => delayedTenantA.current !== null).toBe(true);
  await page.getByRole("button", { name: "trust-reviewer@example.test" }).click();
  await page.getByRole("menuitem", { name: "Tenant B" }).click();
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);

  await delayedTenantA.current?.fulfill({ json: { ok: true, data: [approvalQueueItem("a")] } });
  await page.waitForTimeout(250);
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);
});

test("tenant rotation waits for the matching session credential before loading", async ({
  page,
}) => {
  const tenantBToken = sessionToken("tenant-b");
  let releaseRefresh = () => {};
  let refreshStarted = false;
  let approvalRequests = 0;
  const refreshGate = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });

  await page.route("**/api/auth/refresh", async (route) => {
    refreshStarted = true;
    await refreshGate;
    await route.fulfill({ json: { ok: true, token: tenantBToken, expiresIn: 3600 } });
  });
  await mockAccessibilityApis(page, {
    tenants: [
      { tenantId: "tenant-trust", tenantName: "Tenant A", role: "owner" },
      { tenantId: "tenant-b", tenantName: "Tenant B", role: "owner" },
    ],
  });
  await page.route(`${API}/approvals**`, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    approvalRequests += 1;
    const authorization = route.request().headers().authorization ?? null;
    const tenant = authorization === `Bearer ${tenantBToken}` ? "b" : "a";
    await route.fulfill({ json: { ok: true, data: [approvalQueueItem(tenant)] } });
  });

  await page.goto("/dashboard/approvals");
  await expect(page.getByText("Tenant A agent")).toBeVisible();
  await page.getByRole("button", { name: "trust-reviewer@example.test" }).click();
  await page.getByRole("menuitem", { name: "Tenant B" }).click();
  await expect.poll(() => refreshStarted).toBe(true);
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);
  await page.waitForTimeout(100);
  expect(approvalRequests).toBe(1);

  releaseRefresh();
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  expect(approvalRequests).toBe(2);
});

test("same-tenant user rotation clears the prior queue and reloads once", async ({ page }) => {
  const tenantId = "tenant-trust";
  const userBToken = sessionToken(tenantId, "trust-reviewer-b");
  let releaseRefresh = () => {};
  let refreshStarted = false;
  let approvalRequests = 0;
  const refreshGate = new Promise<void>((resolve) => {
    releaseRefresh = resolve;
  });

  await page.addInitScript(
    ({ token }) => {
      window.sessionStorage.setItem("steward_session_token", token);
    },
    { token: sessionToken(tenantId, "trust-reviewer-a", 60) },
  );
  await page.route("**/api/auth/refresh", async (route) => {
    refreshStarted = true;
    await refreshGate;
    await route.fulfill({ json: { ok: true, token: userBToken, expiresIn: 3600 } });
  });
  await mockAccessibilityApis(page);
  await page.route(`${API}/approvals**`, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    approvalRequests += 1;
    const authorization = route.request().headers().authorization ?? null;
    const user = authorization === `Bearer ${userBToken}` ? "b" : "a";
    await route.fulfill({ json: { ok: true, data: [approvalQueueItem(user)] } });
  });

  await page.goto("/dashboard/approvals");
  await expect(page.getByText("Tenant A agent")).toBeVisible();
  await expect.poll(() => refreshStarted).toBe(true);
  expect(approvalRequests).toBe(1);

  releaseRefresh();
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);
  expect(approvalRequests).toBe(2);
});

test("a prior-tenant approval completion cannot alter the rotated queue", async ({ page }) => {
  const tenantBToken = sessionToken("tenant-b");
  const delayedApproval: { current: Route | null } = { current: null };

  await page.route("**/api/auth/refresh", async (route) => {
    await route.fulfill({ json: { ok: true, token: tenantBToken, expiresIn: 3600 } });
  });
  await mockAccessibilityApis(page, {
    tenants: [
      { tenantId: "tenant-trust", tenantName: "Tenant A", role: "owner" },
      { tenantId: "tenant-b", tenantName: "Tenant B", role: "owner" },
    ],
  });
  await page.route(`${API}/approvals**`, async (route) => {
    if (route.request().method() !== "GET") {
      await route.fallback();
      return;
    }
    const authorization = route.request().headers().authorization ?? null;
    const tenant = authorization === `Bearer ${tenantBToken}` ? "b" : "a";
    await route.fulfill({ json: { ok: true, data: [approvalQueueItem(tenant)] } });
  });
  await page.route(`${API}/approvals/transaction-a/approve`, (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    delayedApproval.current = route;
  });

  await page.goto("/dashboard/approvals");
  await expect(page.getByText("Tenant A agent")).toBeVisible();
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect.poll(() => delayedApproval.current !== null).toBe(true);
  await page.getByRole("button", { name: "trust-reviewer@example.test" }).click();
  await page.getByRole("menuitem", { name: "Tenant B" }).click();
  await expect(page.getByText("Tenant B agent")).toBeVisible();

  await delayedApproval.current?.fulfill({ json: { ok: true, data: approvalQueueItem("a") } });
  await page.waitForTimeout(100);
  await expect(page.getByText("Tenant B agent")).toBeVisible();
  await expect(page.getByText("Tenant A agent")).toHaveCount(0);
  await expect(page.getByText("Transaction approved and queued for signing")).toHaveCount(0);
});

test("case detail preserves incomplete and unknown evidence without exposing raw authority", async ({
  browser,
  page,
}) => {
  await mockAccessibilityApis(page, {
    manifest: caseManifest({
      completeness: "incomplete",
      incompletenessReasons: ["provider receipt missing"],
      missingRequiredRoles: ["provider_receipt"],
      canonicalBytes: RAW_CANONICAL_BYTES,
      canonicalActionBytes: RAW_CANONICAL_BYTES,
      commentBody: RAW_CANONICAL_BYTES,
      credential: { value: RAW_CREDENTIAL },
    }),
  });
  await page.goto(`/dashboard/actions/${ACTION_ID}`);
  await expect(page.getByText("Completeness: incomplete")).toBeVisible();
  await expect(
    page.getByRole("status").filter({ hasText: "Completeness: incomplete" }),
  ).toHaveClass(/border-warning/);
  await expect(page.getByText("provider receipt missing")).toBeVisible();
  await expect(page.getByText(/Missing required roles:/)).toContainText("provider_receipt");
  await expect(page.getByText(/NOT an operator-integrity proof/)).toBeVisible();
  await expect(page.getByText(/--expected-key-fingerprint/)).toBeVisible();
  await expect(page.getByText(/verify-evidence-bundle\.mjs/)).toBeVisible();
  await expect(page.getByText(/verifying against the embedded key/)).toBeVisible();
  await expect(page.getByText(HASH_A)).toBeVisible();
  await expect(page.getByText(HASH_B)).toBeVisible();
  await expect(page.getByText(PROVIDER_IDEMPOTENCY_HASH)).toBeVisible();
  await expect(page.getByText(RAW_CANONICAL_BYTES)).toHaveCount(0);
  await expect(page.getByText(RAW_CREDENTIAL)).toHaveCount(0);

  const unknownContext = await browser.newContext();
  const unknownPage = await unknownContext.newPage();
  await seedSession(unknownPage);
  await mockAccessibilityApis(unknownPage, {
    manifest: caseManifest({ completeness: "unknown", incompletenessReasons: ["audit gap"] }),
  });
  await unknownPage.goto(`/dashboard/actions/${ACTION_ID}`);
  await expect(unknownPage.getByText("Completeness: unknown")).toBeVisible();
  await expect(
    unknownPage.getByRole("status").filter({ hasText: "Completeness: unknown" }),
  ).toHaveClass(/border-warning/);
  await expect(unknownPage.getByText("audit gap")).toBeVisible();
  await unknownContext.close();
});

test("terminal approvals disable both decisions and errors do not enumerate private resources", async ({
  browser,
  page,
}) => {
  await mockAccessibilityApis(page, { approvalStatus: "approved" });
  await page.goto(`/dashboard/approvals/${ACTION_ID}`);
  await expect(page.getByText(/Decision controls are disabled/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Approve this provider action" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Deny this provider action" })).toBeDisabled();

  const renderedErrors: string[] = [];
  for (const status of [403, 404]) {
    for (const surface of ["approval", "case"] as const) {
      const context = await browser.newContext();
      const errorPage = await context.newPage();
      await seedSession(errorPage);
      await mockAccessibilityApis(errorPage, {
        approvalErrorStatus: surface === "approval" ? status : undefined,
        caseErrorStatus: surface === "case" ? status : undefined,
      });
      await errorPage.goto(
        surface === "approval"
          ? `/dashboard/approvals/${ACTION_ID}`
          : `/dashboard/actions/${ACTION_ID}`,
      );
      const alert = errorPage.getByRole("alert");
      await expect(alert.getByText("Not found or not authorized")).toBeVisible();
      await expect(alert).not.toContainText(`PRIVATE_${status}`);
      renderedErrors.push((await alert.innerText()).replaceAll(/\s+/g, " ").trim());
      await context.close();
    }
  }
  expect(renderedErrors).toEqual([
    "Not found or not authorized not found / not authorized",
    "Not found or not authorized not found / not authorized",
    "Not found or not authorized not found / not authorized",
    "Not found or not authorized not found / not authorized",
  ]);
});

test("non-auth provider failures preserve reachable API diagnostics", async ({ browser, page }) => {
  await mockAccessibilityApis(page, {
    caseErrorStatus: 500,
    caseErrorBody: { ok: false, error: "CASE_EXPORT_UNAVAILABLE" },
  });
  await page.goto(`/dashboard/actions/${ACTION_ID}`);
  await expect(page.getByRole("alert")).toContainText("CASE_EXPORT_UNAVAILABLE");

  const approvalContext = await browser.newContext();
  const approvalPage = await approvalContext.newPage();
  await seedSession(approvalPage);
  await mockAccessibilityApis(approvalPage, {
    approvalDecisionError: {
      status: 400,
      body: { ok: false, error: { code: "APPROVAL_FIELD_INVALID" } },
    },
  });
  await approvalPage.goto(`/dashboard/approvals/${ACTION_ID}`);
  await approvalPage
    .getByLabel("Reason (required for approve and deny)")
    .fill("Reviewed but server rejected one field");
  await approvalPage.getByRole("button", { name: "Approve this provider action" }).click();
  await expect(approvalPage.getByRole("status")).toContainText("Error: APPROVAL_FIELD_INVALID");
  await approvalContext.close();
});

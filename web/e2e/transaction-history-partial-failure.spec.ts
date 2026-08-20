import { expect, type Page, type Route, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sessionToken(tenantId: string): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      email: "partial-history@example.test",
      exp: now + 3600,
      iat: now,
      role: "owner",
      tenantId,
      tenantRole: "owner",
      userId: "partial-history-user",
    }),
    "test-signature",
  ].join(".");
}

function transaction(id: string, agentId: string) {
  return {
    id,
    agentId,
    status: "pending",
    request: {
      chainId: 8453,
      to: "0x1111111111111111111111111111111111111111",
      value: "1000000000000000",
    },
    policyResults: [],
    createdAt: "2026-08-20T12:00:00.000Z",
  };
}

async function mockTenantSwitcher(page: Page, tenantBToken: string): Promise<void> {
  await page.route(
    (url) => url.href.startsWith(API) && url.pathname === "/user/me/tenants",
    async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: [
            { tenantId: "tenant-a", tenantName: "Tenant A", role: "owner" },
            { tenantId: "tenant-b", tenantName: "Tenant B", role: "owner" },
          ],
        },
      });
    },
  );
  await page.route("**/api/auth/refresh", async (route) => {
    const body = route.request().postDataJSON() as { tenantId?: string };
    expect(body.tenantId).toBe("tenant-b");
    await route.fulfill({ json: { ok: true, token: tenantBToken, expiresIn: 3600 } });
  });
}

async function waitForStableRequestCount(page: Page, readCount: () => number): Promise<void> {
  let previous = readCount();
  let stableChecks = 0;
  while (stableChecks < 4) {
    await page.waitForTimeout(250);
    const current = readCount();
    if (current === previous) {
      stableChecks += 1;
    } else {
      previous = current;
      stableChecks = 0;
    }
  }
}

async function switchToTenant(page: Page, email: string, tenantName: string): Promise<void> {
  await expect
    .poll(async () => {
      const tenantMenuItem = page.getByRole("menuitem", { name: tenantName });
      if (await tenantMenuItem.isVisible().catch(() => false)) {
        await tenantMenuItem.evaluate((button) => (button as HTMLButtonElement).click());
        return true;
      }

      const accountButton = page.getByRole("button", { name: email });
      if (await accountButton.isVisible().catch(() => false)) {
        await accountButton.evaluate((button) => (button as HTMLButtonElement).click());
      }
      return false;
    })
    .toBe(true);
}

test("dashboard surfaces partial transaction history without discarding available rows", async ({
  page,
  request,
}) => {
  await page.route(
    (url) => url.href.startsWith(API) && url.pathname === "/agents",
    async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: [
            { id: "agent-available", name: "Available Agent" },
            { id: "agent-unavailable", name: "Unavailable Agent" },
          ],
        },
      });
    },
  );
  await page.route(
    (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-available/history",
    async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: [
            {
              ...transaction("tx-visible", "agent-available"),
            },
          ],
        },
      });
    },
  );
  await page.route(
    (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-unavailable/history",
    async (route) => {
      await route.fulfill({ status: 503, json: { ok: false, error: "history unavailable" } });
    },
  );

  await loginWithMagicLink(page, request, `partial-history-${Date.now()}@example.test`);
  await page.goto(`${WEB}/dashboard`);
  const overviewWarning = page
    .getByRole("alert")
    .filter({ hasText: "Transaction history is incomplete" });
  await expect(overviewWarning).toContainText("1 agent history failed to load");
  await expect(page.getByText("Known Pending Approvals")).toBeVisible();
  await expect(page.getByRole("link", { name: "Available Agent" })).toBeVisible();

  await page.goto(`${WEB}/dashboard/transactions`);
  const transactionsWarning = page
    .getByRole("alert")
    .filter({ hasText: "Transaction history is incomplete" });
  await expect(transactionsWarning).toContainText(
    "The list and counts include only the available histories",
  );
  await expect(page.getByRole("link", { name: "Available Agent" })).toBeVisible();
  await expect(page.getByRole("button", { name: "All1" })).toBeVisible();
});

test("overview pending counts include agents beyond the former twenty-agent sample", async ({
  page,
  request,
}) => {
  const agents = Array.from({ length: 21 }, (_, index) => ({
    id: `agent-${index + 1}`,
    name: `Agent ${index + 1}`,
  }));

  await page.route(
    (url) => url.href.startsWith(API) && url.pathname === "/agents",
    (route) => route.fulfill({ json: { ok: true, data: agents } }),
  );
  await page.route(
    (url) => url.href.startsWith(API) && /^\/vault\/agent-\d+\/history$/.test(url.pathname),
    async (route) => {
      const agentId = new URL(route.request().url()).pathname.split("/")[2];
      await route.fulfill({
        json: {
          ok: true,
          data: agentId === "agent-21" ? [transaction("tx-agent-21", agentId)] : [],
        },
      });
    },
  );

  await loginWithMagicLink(page, request, `complete-history-${Date.now()}@example.test`);
  await page.goto(`${WEB}/dashboard`);
  const pendingStat = page.getByText("Pending Approvals").locator("..");
  await expect(pendingStat).toContainText("1");
  await expect(page.getByRole("link", { name: "Agent 21" })).toBeVisible();
});

for (const surface of [
  { name: "overview", path: "/dashboard" },
  { name: "transactions", path: "/dashboard/transactions" },
] as const) {
  test(`${surface.name} ignores a delayed tenant-A completion after switching to tenant B`, async ({
    page,
    request,
  }) => {
    const email = `tenant-fence-${surface.name}-${Date.now()}@example.test`;
    const tenantBToken = sessionToken("tenant-b");
    const delayedTenantA = { current: null as Route | null };

    await mockTenantSwitcher(page, tenantBToken);
    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/agents",
      async (route) => {
        const authorization = route.request().headers().authorization ?? null;
        const tenant = authorization === `Bearer ${tenantBToken}` ? "b" : "a";
        await route.fulfill({
          json: {
            ok: true,
            data: [{ id: `agent-${tenant}`, name: `Tenant ${tenant.toUpperCase()} Agent` }],
          },
        });
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-a/history",
      (route) => {
        delayedTenantA.current = route;
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-b/history",
      (route) => route.fulfill({ json: { ok: true, data: [transaction("tx-b", "agent-b")] } }),
    );

    await loginWithMagicLink(page, request, email);
    await page.goto(`${WEB}${surface.path}`);
    await expect.poll(() => delayedTenantA.current !== null).toBe(true);
    await switchToTenant(page, email, "Tenant B");
    await expect(page.getByRole("link", { name: "Tenant B Agent" })).toBeVisible();

    await delayedTenantA.current?.fulfill({
      json: { ok: true, data: [transaction("tx-a", "agent-a")] },
    });
    await page.waitForTimeout(250);
    await expect(page.getByRole("link", { name: "Tenant B Agent" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Tenant A Agent" })).toHaveCount(0);
  });

  test(`${surface.name} keeps the newest result when retries overlap`, async ({
    page,
    request,
  }) => {
    const delayedRetry = { current: null as Route | null };
    let phase: "initial" | "overlap" = "initial";
    let totalListRequests = 0;
    let listRequests = 0;
    let availableHistoryRequests = 0;
    let unavailableHistoryRequests = 0;

    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/agents",
      async (route) => {
        totalListRequests += 1;
        if (phase === "overlap") listRequests += 1;
        const availableName =
          phase === "initial"
            ? "Initial Agent"
            : listRequests === 1
              ? "Stale Agent"
              : "Newest Agent";
        await route.fulfill({
          json: {
            ok: true,
            data: [
              { id: "agent-available", name: availableName },
              { id: "agent-unavailable", name: "Unavailable Agent" },
            ],
          },
        });
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-available/history",
      async (route) => {
        if (phase === "initial") {
          await route.fulfill({
            json: { ok: true, data: [transaction("tx-initial", "agent-available")] },
          });
          return;
        }
        availableHistoryRequests += 1;
        if (availableHistoryRequests === 1) {
          delayedRetry.current = route;
          return;
        }
        await route.fulfill({
          json: {
            ok: true,
            data: [transaction("tx-newest", "agent-available")],
          },
        });
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && url.pathname === "/vault/agent-unavailable/history",
      async (route) => {
        if (phase === "initial") {
          await route.fulfill({ status: 503, json: { ok: false, error: "history unavailable" } });
          return;
        }
        unavailableHistoryRequests += 1;
        // The first retry is still waiting on its available history, so the
        // first unavailable request belongs to the newer retry.
        if (unavailableHistoryRequests === 1) {
          await route.fulfill({ json: { ok: true, data: [] } });
          return;
        }
        await route.fulfill({ status: 503, json: { ok: false, error: "history unavailable" } });
      },
    );

    await loginWithMagicLink(
      page,
      request,
      `retry-fence-${surface.name}-${Date.now()}@example.test`,
    );
    await page.goto(`${WEB}${surface.path}`);
    const warning = page
      .getByRole("alert")
      .filter({ hasText: "Transaction history is incomplete" });
    await expect(warning).toBeVisible();
    // The optional wallet provider can remount these pages once its chunks
    // settle. Start the deliberate overlap only after automatic loads stop so
    // the two generations below are the only requests under test.
    await waitForStableRequestCount(page, () => totalListRequests);
    await expect(warning).toBeVisible();
    phase = "overlap";
    const retry = page.getByRole("button", { name: "Retry histories" });
    await retry.evaluate((button) => {
      (button as HTMLButtonElement).click();
      (button as HTMLButtonElement).click();
    });
    await expect.poll(() => delayedRetry.current !== null).toBe(true);
    await expect(page.getByRole("link", { name: "Newest Agent" })).toBeVisible();
    await expect(warning).toHaveCount(0);

    await delayedRetry.current?.fulfill({
      json: { ok: true, data: [transaction("tx-stale", "agent-available")] },
    });
    await page.waitForTimeout(250);
    await expect(page.getByRole("link", { name: "Newest Agent" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Stale Agent" })).toHaveCount(0);
    await expect(warning).toHaveCount(0);
  });
}

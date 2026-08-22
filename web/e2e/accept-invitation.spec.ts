import { expect, type Page, type Route, test } from "@playwright/test";

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function sessionToken(tenantId: string, userId: string): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      email: `${userId}@example.test`,
      exp: now + 3600,
      iat: now,
      role: "owner",
      tenantId,
      tenantRole: "owner",
      userId,
    }),
    "test-signature",
  ].join(".");
}

async function seedSession(page: Page, token: string): Promise<void> {
  await page.addInitScript((value) => {
    if (!window.sessionStorage.getItem("steward_session_token")) {
      window.sessionStorage.setItem("steward_session_token", value);
    }
    // Production cleanup must remove this legacy JS-readable credential.
    window.sessionStorage.setItem("steward_refresh_token", "legacy-refresh-must-be-removed");
  }, token);
}

async function waitForHydration(page: Page): Promise<void> {
  await expect
    .poll(() => page.evaluate(() => window.sessionStorage.getItem("steward_refresh_token")))
    .toBeNull();
}

test("only explicit acceptance posts once with current encoded inputs and credential", async ({
  page,
}) => {
  const token = sessionToken("session-tenant", "invited-user");
  await seedSession(page, token);
  const requests: Array<{ url: string; authorization: string | undefined; body: unknown }> = [];
  const pendingRequest: { current: Route | null } = { current: null };
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    requests.push({
      url: route.request().url(),
      authorization: route.request().headers().authorization,
      body: route.request().postDataJSON(),
    });
    pendingRequest.current = route;
  });

  await page.goto(
    `/accept-invitation?tenantId=${encodeURIComponent("tenant / hostile")}&token=${encodeURIComponent("claim&token=1")}`,
  );
  await expect(page.getByRole("button", { name: "Accept invitation" })).toBeVisible();
  await waitForHydration(page);
  expect(requests).toHaveLength(0);

  await page.getByRole("button", { name: "Accept invitation" }).evaluate((button) => {
    // Dispatch both clicks in one task, before React can commit the first
    // state update, to exercise the ref-backed duplicate fence.
    (button as HTMLButtonElement).click();
    (button as HTMLButtonElement).click();
  });
  await expect.poll(() => requests.length).toBe(1);
  await expect(page.getByText("Accepting invitation...")).toBeVisible();
  await expect(page.getByRole("button", { name: "Accept invitation" })).toHaveCount(0);
  await pendingRequest.current?.fulfill({
    json: {
      ok: true,
      data: { tenantId: "tenant / hostile", role: "member", invitationId: "invitation-1" },
    },
  });
  await expect(page.getByText("You've joined tenant / hostile as member.")).toBeVisible();
  expect(requests).toEqual([
    {
      url: expect.stringContaining("/tenants/tenant%20%2F%20hostile/invitations/accept"),
      authorization: `Bearer ${token}`,
      body: { token: "claim&token=1" },
    },
  ]);
  await expect
    .poll(() => page.evaluate(() => window.sessionStorage.getItem("steward_refresh_token")))
    .toBeNull();
});

test("decline, navigation, missing parameters, and load never accept", async ({ page }) => {
  await seedSession(page, sessionToken("session-tenant", "invited-user"));
  let requests = 0;
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    requests += 1;
    await route.fulfill({ json: { ok: true, data: {} } });
  });

  await page.goto("/accept-invitation?tenantId=tenant-a&token=token-a");
  await waitForHydration(page);
  expect(requests).toBe(0);
  await page.getByRole("link", { name: "Decline" }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  expect(requests).toBe(0);
  await page.goBack();
  expect(requests).toBe(0);
  await page.goto("/accept-invitation?tenantId=tenant-a");
  await expect(page.getByText("This invitation link is missing required fields.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Accept invitation" })).toHaveCount(0);
  expect(requests).toBe(0);
});

test("route navigation wins over a delayed prior acceptance", async ({ page }) => {
  const authToken = sessionToken("session-tenant", "invited-user");
  await seedSession(page, authToken);
  const delayedFirst: { current: Route | null } = { current: null };
  const observed: Array<{ tenant: string; authorization: string | undefined }> = [];
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const tenant = pathname.includes("tenant-a") ? "tenant-a" : "tenant-b";
    observed.push({ tenant, authorization: route.request().headers().authorization });
    if (tenant === "tenant-a") {
      delayedFirst.current = route;
      return;
    }
    await route.fulfill({
      json: { ok: true, data: { tenantId: tenant, role: "member", invitationId: tenant } },
    });
  });

  await page.goto("/accept-invitation?tenantId=tenant-a&token=claim-a");
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect.poll(() => observed.length).toBe(1);

  await page.evaluate(() => {
    window.history.pushState({}, "", "/accept-invitation?tenantId=tenant-b&token=claim-b");
  });
  await expect(page.getByText(/invited to join tenant-b/)).toBeVisible();
  await delayedFirst.current?.fulfill({
    json: {
      ok: true,
      data: { tenantId: "tenant-a", role: "member", invitationId: "tenant-a" },
    },
  });
  await page.waitForTimeout(100);
  await expect(page.getByText(/invited to join tenant-b/)).toBeVisible();
  await expect(page.getByText(/joined tenant-a/)).toHaveCount(0);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-b as member.")).toBeVisible();
  expect(observed).toEqual([
    { tenant: "tenant-a", authorization: `Bearer ${authToken}` },
    { tenant: "tenant-b", authorization: `Bearer ${authToken}` },
  ]);
});

test("a new document uses the rotated concrete session credential", async ({ page }) => {
  const firstToken = sessionToken("tenant-a", "user-a");
  const secondToken = sessionToken("tenant-b", "user-b");
  await seedSession(page, firstToken);
  const observed: Array<string | undefined> = [];
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    observed.push(route.request().headers().authorization);
    const pathname = new URL(route.request().url()).pathname;
    const tenant = pathname.includes("tenant-a") ? "tenant-a" : "tenant-b";
    await route.fulfill({
      json: { ok: true, data: { tenantId: tenant, role: "member", invitationId: tenant } },
    });
  });

  await page.goto("/accept-invitation?tenantId=tenant-a&token=claim-a");
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-a as member.")).toBeVisible();
  await page.evaluate((token) => {
    window.sessionStorage.setItem("steward_session_token", token);
  }, secondToken);
  await page.goto("/accept-invitation?tenantId=tenant-b&token=claim-b");
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-b as member.")).toBeVisible();
  expect(observed).toEqual([`Bearer ${firstToken}`, `Bearer ${secondToken}`]);
});

test("failure text is sanitized and does not expose server details", async ({ page }) => {
  await seedSession(page, sessionToken("tenant-a", "user-a"));
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    await route.fulfill({
      status: 403,
      json: { ok: false, error: "database tenant row 42 secret-provider-detail" },
    });
  });
  await page.goto("/accept-invitation?tenantId=tenant-a&token=claim-a");
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(
    page.getByText("The invitation could not be accepted. Please verify the link and try again."),
  ).toBeVisible();
  await expect(page.getByText(/secret-provider-detail/)).toHaveCount(0);
});

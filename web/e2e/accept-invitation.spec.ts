import { expect, type Page, type Route, test } from "@playwright/test";

const TEST_JWT_SECRET = "steward-invitation-trust-suite-secret-2026";

// The Playwright worker is an isolated test process. Give the production JWT
// authority a strong, non-secret test key before minting browser fixtures.
process.env.STEWARD_JWT_SECRET = TEST_JWT_SECRET;

type VerifiedSession = {
  aud?: string | string[];
  iss?: string;
  jti?: string;
  tenantId?: string;
  userId?: string;
};

async function verifyProductionSession(
  token: string,
  expected?: { tenantId: string; userId: string },
): Promise<VerifiedSession> {
  const { verifyToken } = await import("../../packages/auth/src/jwt");
  const payload = await verifyToken(token);
  expect(payload.iss).toBe("steward");
  expect(payload.aud).toBe("steward-api");
  expect(payload.jti).toEqual(expect.any(String));
  if (expected) {
    expect(payload).toMatchObject(expected);
  }
  return payload;
}

async function sessionToken(tenantId: string, userId: string): Promise<string> {
  const { signAccessToken } = await import("../../packages/auth/src/jwt");
  const token = await signAccessToken(
    {
      address: "",
      email: `${userId}@example.test`,
      role: "owner",
      tenantId,
      tenantRole: "owner",
      userId,
    },
    "1h",
  );
  await verifyProductionSession(token, { tenantId, userId });
  return token;
}

async function signedAuthorization(route: Route): Promise<string> {
  const authorization = route.request().headers().authorization ?? "";
  expect(authorization).toMatch(/^Bearer /);
  await verifyProductionSession(authorization.slice("Bearer ".length));
  return authorization;
}

const CLAIM_A = "a".repeat(64);
const CLAIM_B = "b".repeat(64);

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
  const token = await sessionToken("session-tenant", "invited-user");
  await seedSession(page, token);
  const requests: Array<{ url: string; authorization: string | undefined; body: unknown }> = [];
  const pendingRequest: { current: Route | null } = { current: null };
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    requests.push({
      url: route.request().url(),
      authorization: await signedAuthorization(route),
      body: route.request().postDataJSON(),
    });
    pendingRequest.current = route;
  });

  await page.goto(
    `/accept-invitation?tenantId=${encodeURIComponent("tenant:current")}&token=${CLAIM_A}`,
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
      tenantId: "tenant:current",
      role: "member",
      invitationId: "invitation-1",
    },
  });
  await expect(page.getByText("You've joined tenant:current as member.")).toBeVisible();
  expect(requests).toEqual([
    {
      url: expect.stringContaining("/tenants/tenant%3Acurrent/invitations/accept"),
      authorization: `Bearer ${token}`,
      body: { token: CLAIM_A },
    },
  ]);
  await expect
    .poll(() => page.evaluate(() => window.sessionStorage.getItem("steward_refresh_token")))
    .toBeNull();
});

test("decline, navigation, missing parameters, and load never accept", async ({ page }) => {
  await seedSession(page, await sessionToken("session-tenant", "invited-user"));
  let requests = 0;
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    requests += 1;
    await route.fulfill({ json: { ok: true, data: {} } });
  });

  await page.goto(`/accept-invitation?tenantId=tenant-a&token=${CLAIM_A}`);
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

  await page.goto("/accept-invitation?tenantId=tenant%20with%20spaces&token=not-a-token");
  await expect(page.getByText("This invitation link contains invalid fields.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Accept invitation" })).toHaveCount(0);
  expect(requests).toBe(0);
});

test("session rotation and route navigation win over a delayed prior acceptance", async ({
  page,
}) => {
  const firstAuthToken = await sessionToken("tenant-a", "user-a");
  const secondAuthToken = await sessionToken("tenant-b", "user-b");
  await seedSession(page, firstAuthToken);
  const delayedFirst: { current: Route | null } = { current: null };
  const observed: Array<{ tenant: string; authorization: string | undefined }> = [];
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const tenant = pathname.includes("tenant-a") ? "tenant-a" : "tenant-b";
    observed.push({ tenant, authorization: await signedAuthorization(route) });
    if (tenant === "tenant-a") {
      delayedFirst.current = route;
      return;
    }
    await route.fulfill({
      json: { ok: true, tenantId: tenant, role: "member", invitationId: tenant },
    });
  });

  await page.goto(`/accept-invitation?tenantId=tenant-a&token=${CLAIM_A}`);
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect.poll(() => observed.length).toBe(1);

  await page.evaluate(
    ({ claim, session }) => {
      window.sessionStorage.setItem("steward_session_token", session);
      window.history.pushState({}, "", `/accept-invitation?tenantId=tenant-b&token=${claim}`);
    },
    { claim: CLAIM_B, session: secondAuthToken },
  );
  await expect(page.getByText(/invited to join tenant-b/)).toBeVisible();
  await delayedFirst.current?.fulfill({
    json: {
      ok: true,
      tenantId: "tenant-a",
      role: "member",
      invitationId: "tenant-a",
    },
  });
  await page.waitForTimeout(100);
  await expect(page.getByText(/invited to join tenant-b/)).toBeVisible();
  await expect(page.getByText(/joined tenant-a/)).toHaveCount(0);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-b as member.")).toBeVisible();
  expect(observed).toEqual([
    { tenant: "tenant-a", authorization: `Bearer ${firstAuthToken}` },
    { tenant: "tenant-b", authorization: `Bearer ${secondAuthToken}` },
  ]);
});

test("the retained document uses the rotated concrete session credential", async ({ page }) => {
  const firstToken = await sessionToken("tenant-a", "user-a");
  const secondToken = await sessionToken("tenant-b", "user-b");
  await seedSession(page, firstToken);
  const observed: Array<string | undefined> = [];
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    observed.push(await signedAuthorization(route));
    const pathname = new URL(route.request().url()).pathname;
    const tenant = pathname.includes("tenant-a") ? "tenant-a" : "tenant-b";
    await route.fulfill({
      json: { ok: true, tenantId: tenant, role: "member", invitationId: tenant },
    });
  });

  await page.goto(`/accept-invitation?tenantId=tenant-a&token=${CLAIM_A}`);
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-a as member.")).toBeVisible();
  await page.evaluate((token) => {
    window.sessionStorage.setItem("steward_session_token", token);
  }, secondToken);
  await page.evaluate((token) => {
    window.history.pushState({}, "", `/accept-invitation?tenantId=tenant-b&token=${token}`);
  }, CLAIM_B);
  await expect(page.getByText(/invited to join tenant-b/)).toBeVisible();
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(page.getByText("You've joined tenant-b as member.")).toBeVisible();
  expect(observed).toEqual([`Bearer ${firstToken}`, `Bearer ${secondToken}`]);
});

test("failure text is sanitized and does not expose server details", async ({ page }) => {
  await seedSession(page, await sessionToken("tenant-a", "user-a"));
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    await signedAuthorization(route);
    await route.fulfill({
      status: 403,
      json: { ok: false, error: "database tenant row 42 secret-provider-detail" },
    });
  });
  await page.goto(`/accept-invitation?tenantId=tenant-a&token=${CLAIM_A}`);
  await waitForHydration(page);
  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect(
    page.getByText("The invitation could not be accepted. Please verify the link and try again."),
  ).toBeVisible();
  await expect(page.getByText(/secret-provider-detail/)).toHaveCount(0);
});

test("network, parse, and malformed-success failures all use the generic message", async ({
  page,
}) => {
  await seedSession(page, await sessionToken("tenant-a", "user-a"));
  await page.route("**/user/me/tenants/**/invitations/accept", async (route) => {
    await signedAuthorization(route);
    const token = (route.request().postDataJSON() as { token: string }).token;
    if (token === CLAIM_A) {
      await route.abort("connectionrefused");
      return;
    }
    if (token === CLAIM_B) {
      await route.fulfill({
        status: 502,
        contentType: "text/plain",
        body: "proxy diagnostic secret-upstream-host",
      });
      return;
    }
    await route.fulfill({
      json: {
        ok: true,
        tenantId: "different-tenant",
        role: "owner",
        invitationId: "",
        internal: "secret-malformed-success",
      },
    });
  });

  for (const [tenantId, token] of [
    ["tenant-a", CLAIM_A],
    ["tenant-b", CLAIM_B],
    ["tenant-c", "c".repeat(64)],
  ] as const) {
    await page.goto(`/accept-invitation?tenantId=${tenantId}&token=${token}`);
    await waitForHydration(page);
    await page.getByRole("button", { name: "Accept invitation" }).click();
    await expect(
      page.getByText("The invitation could not be accepted. Please verify the link and try again."),
    ).toBeVisible();
    await expect(page.getByText(/secret-upstream-host|secret-malformed-success/)).toHaveCount(0);
  }
});

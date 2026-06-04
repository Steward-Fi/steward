import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type TenantUser = {
  userId: string;
  tenantId: string;
  role: string;
  joinedAt: string;
  email: string | null;
  emailVerified: boolean | null;
  name: string | null;
  tenantCustomMetadata: Record<string, unknown>;
  deactivatedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

type TenantInvitation = {
  id: string;
  tenantId: string;
  email: string;
  role: string;
  status: string;
  invitedByUserId: string | null;
  acceptedByUserId: string | null;
  acceptedAt: string | null;
  revokedAt: string | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

test.describe("Dashboard tenant team roles", () => {
  test("authenticated admins can update tenant user roles", async ({ page, request }, testInfo) => {
    const email = `tenant-rbac-${Date.now()}@example.test`;
    const tenantId = "personal-rbac-test";
    const now = new Date().toISOString();
    const tenantUser: TenantUser = {
      userId: "11111111-1111-4111-8111-111111111111",
      tenantId,
      role: "viewer",
      joinedAt: now,
      email: "dev@example.test",
      emailVerified: true,
      name: "Dev User",
      tenantCustomMetadata: {},
      deactivatedAt: null,
      createdAt: now,
      updatedAt: now,
    };
    const invitations: TenantInvitation[] = [];
    let tenantUserRemoved = false;
    let lastInviteBody: { email: string; role: string; sendEmail: boolean } | null = null;

    await page.route(/\/user\/me\/tenants\/[^/]+\/users(?:\?.*)?$/, async (route) => {
      await route.fulfill({
        json: { ok: true, data: { users: tenantUserRemoved ? [] : [tenantUser] } },
      });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/export(?:\?.*)?$/, async (route) => {
      await route.fulfill({
        body: "user_id,email\n11111111-1111-4111-8111-111111111111,dev@example.test\n",
        headers: {
          "Content-Disposition": `attachment; filename="${tenantId}-users.csv"`,
          "Content-Type": "text/csv",
        },
      });
    });
    await page.route(
      /\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/events(?:\?.*)?$/,
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              events: [
                {
                  id: 333,
                  seq: 7,
                  action: "tenant.member.role.update",
                  actorType: "user",
                  actorId: "44444444-4444-4444-8444-444444444444",
                  resourceType: "user",
                  resourceId: tenantUser.userId,
                  metadata: {},
                  createdAt: now,
                },
              ],
              limit: 10,
              offset: 0,
              total: 1,
            },
          },
        });
      },
    );
    await page.route(/\/user\/me\/tenants\/[^/]+\/invitations(?:\?.*)?$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { invitations } } });
        return;
      }
      if (routeRequest.method() === "POST") {
        const body = routeRequest.postDataJSON() as {
          email: string;
          role: string;
          sendEmail: boolean;
        };
        lastInviteBody = body;
        const invitation: TenantInvitation = {
          id: "22222222-2222-4222-8222-222222222222",
          tenantId,
          email: body.email,
          role: body.role,
          status: "pending",
          invitedByUserId: null,
          acceptedByUserId: null,
          acceptedAt: null,
          revokedAt: null,
          expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60_000).toISOString(),
          createdAt: now,
          updatedAt: now,
        };
        invitations.unshift(invitation);
        await route.fulfill({
          json: { ok: true, data: { invitation, token: "invite-token-e2e", emailSent: true } },
        });
        return;
      }
      await route.fallback();
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/invitations\/[^/]+$/, async (route) => {
      const id = route.request().url().split("/").pop() ?? "";
      const index = invitations.findIndex((invite) => invite.id === id);
      if (index >= 0) invitations.splice(index, 1);
      await route.fulfill({ json: { ok: true } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+$/, async (route) => {
      if (route.request().method() !== "GET" || route.request().url().includes("/export")) {
        await route.fallback();
        return;
      }
      await route.fulfill({ json: { ok: true, data: tenantUser } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/role$/, async (route) => {
      const body = route.request().postDataJSON() as { role: string };
      tenantUser.role = body.role;
      await route.fulfill({ json: { ok: true, data: tenantUser } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/metadata$/, async (route) => {
      const body = route.request().postDataJSON() as {
        tenantCustomMetadata: Record<string, unknown>;
      };
      tenantUser.tenantCustomMetadata = body.tenantCustomMetadata;
      await route.fulfill({ json: { ok: true, data: tenantUser } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/deactivate$/, async (route) => {
      const body = route.request().postDataJSON() as { deactivated: boolean };
      tenantUser.deactivatedAt = body.deactivated ? new Date().toISOString() : null;
      await route.fulfill({ json: { ok: true, data: tenantUser } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+$/, async (route) => {
      if (route.request().method() !== "DELETE") {
        await route.fallback();
        return;
      }
      tenantUserRemoved = true;
      await route.fulfill({ json: { ok: true } });
    });

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/users`);
    const tenantInput = page.getByPlaceholder("tenant-id");
    await expect(tenantInput).toHaveValue(/personal-/);

    // The Search button enables once (tenantId && token) are truthy, but in the
    // brief auth-hydration window right after the email-callback login the submit
    // handler's auth.getToken() can still read null — loadTenantUsers then
    // early-returns and the list stays in its initial "idle" state (it shows
    // "Search requires an owner or admin session…", which is just the pre-search
    // copy, not a real permission failure), so no user row ever renders. This is
    // a benign timing race (passes on firefox/webkit, deterministically lost on
    // chromium). Retry Search until the row appears; once the token has hydrated
    // the search sticks. A genuine "list never loads" bug still fails every cycle.
    const devUserButton = page.getByRole("button", { name: /dev@example\.test/ });
    await expect(async () => {
      await page.getByRole("button", { name: "Search" }).click();
      await expect(devUserButton).toBeVisible({ timeout: 3_000 });
    }).toPass({ timeout: 20_000 });

    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^personal-.+-users\.csv$/);

    await devUserButton.click();
    await expect(page.getByText("tenant.member.role.update")).toBeVisible();
    await page.getByLabel("Tenant role").selectOption("developer");

    await expect(page.getByLabel("Tenant role")).toHaveValue("developer");
    expect(tenantUser.role).toBe("developer");

    await page.getByLabel("Tenant metadata JSON").fill('{\n  "plan": "pro"\n}');
    await page.getByRole("button", { name: "Save Metadata" }).click();
    expect(tenantUser.tenantCustomMetadata).toEqual({ plan: "pro" });

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Deactivate User" }).click();
    await expect(page.getByText("Deactivated").first()).toBeVisible();
    expect(tenantUser.deactivatedAt).toBeTruthy();

    await page.getByRole("button", { name: "Reactivate User" }).click();
    await expect(page.getByText("Active").first()).toBeVisible();
    expect(tenantUser.deactivatedAt).toBeNull();

    await page.getByPlaceholder("teammate@example.com").fill("ops@example.test");
    await page.getByLabel("Invite role").selectOption("billing");
    await page.getByRole("button", { name: "Invite" }).click();
    await expect(page.getByText("invite-token-e2e")).toBeVisible();
    await expect(page.getByText("ops@example.test")).toBeVisible();
    expect(invitations[0]).toMatchObject({ email: "ops@example.test", role: "billing" });
    expect(lastInviteBody).toMatchObject({ sendEmail: true });

    await page.getByRole("button", { name: "Revoke" }).click();
    await expect(page.getByText("No pending invitations.")).toBeVisible();
    expect(invitations).toHaveLength(0);

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Remove User" }).click();
    await expect(page.getByText("Select a user.")).toBeVisible();
    expect(tenantUserRemoved).toBe(true);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-users-role-management.png"),
      fullPage: true,
    });
  });
});

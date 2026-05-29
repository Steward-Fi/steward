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
      createdAt: now,
      updatedAt: now,
    };

    await page.route(/\/user\/me\/tenants\/[^/]+\/users(?:\?.*)?$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: { users: [tenantUser] } } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+$/, async (route) => {
      await route.fulfill({ json: { ok: true, data: tenantUser } });
    });
    await page.route(/\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/role$/, async (route) => {
      const body = route.request().postDataJSON() as { role: string };
      tenantUser.role = body.role;
      await route.fulfill({ json: { ok: true, data: tenantUser } });
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
    await page.getByPlaceholder("tenant-id").fill(tenantId);
    await page.getByRole("button", { name: "Search" }).click();
    await page.getByRole("button", { name: /dev@example\.test/ }).click();
    await page.getByLabel("Tenant role").selectOption("developer");

    await expect(page.getByLabel("Tenant role")).toHaveValue("developer");
    expect(tenantUser.role).toBe("developer");

    await page.screenshot({
      path: testInfo.outputPath("dashboard-users-role-management.png"),
      fullPage: true,
    });
  });
});

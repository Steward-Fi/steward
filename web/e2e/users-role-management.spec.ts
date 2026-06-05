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
  walletExternalIds?: Array<{
    id?: string;
    tenantId?: string;
    walletExternalId?: string;
    externalId?: string;
  }>;
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

type WalletPolicyViolationReport = {
  tenantId: string;
  policyEnabled: boolean;
  total: number;
  limit: number;
  offset: number;
  violations: Array<{
    userId: string;
    email: string | null;
    name: string | null;
    role: string;
    walletCount: number;
    wallets: Array<{
      accountId: string;
      provider: "wallet:ethereum" | "wallet:solana";
      providerAccountId: string;
    }>;
  }>;
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
    const walletPolicyReport: WalletPolicyViolationReport = {
      tenantId,
      policyEnabled: true,
      total: 1,
      limit: 50,
      offset: 0,
      violations: [
        {
          userId: tenantUser.userId,
          email: tenantUser.email,
          name: tenantUser.name,
          role: tenantUser.role,
          walletCount: 2,
          wallets: [
            {
              accountId: "wallet-account-evm",
              provider: "wallet:ethereum",
              providerAccountId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            {
              accountId: "wallet-account-solana",
              provider: "wallet:solana",
              providerAccountId: "So11111111111111111111111111111111111111112",
            },
          ],
        },
      ],
    };
    let tenantUserRemoved = false;
    let lastInviteBody: { email: string; role: string; sendEmail: boolean } | null = null;
    let lastUsersSearchUrl = "";
    let lastBulkRemediationBody: { wallets: Array<{ userId: string; accountId: string }> } | null =
      null;
    const remediatedWalletAccountIds = new Set<string>();
    let walletPolicyReportLoads = 0;

    await page.route(/\/user\/me\/tenants\/[^/]+\/users(?:\?.*)?$/, async (route) => {
      lastUsersSearchUrl = route.request().url();
      await route.fulfill({
        json: { ok: true, data: { users: tenantUserRemoved ? [] : [tenantUser] } },
      });
    });
    await page.route(
      /\/user\/me\/tenants\/[^/]+\/users\/wallet-policy\/violations(?:\?.*)?$/,
      async (route) => {
        walletPolicyReportLoads += 1;
        if (remediatedWalletAccountIds.size > 0) {
          walletPolicyReport.violations = walletPolicyReport.violations
            .map((violation) => ({
              ...violation,
              wallets: violation.wallets.filter(
                (wallet) => !remediatedWalletAccountIds.has(wallet.accountId),
              ),
            }))
            .filter((violation) => violation.wallets.length > 1);
          walletPolicyReport.total = walletPolicyReport.violations.length;
        }
        await route.fulfill({ json: { ok: true, data: walletPolicyReport } });
      },
    );
    await page.route(
      /\/user\/me\/tenants\/[^/]+\/users\/[^/]+\/wallet-policy\/wallets\/[^/]+$/,
      async (route) => {
        expect(route.request().method()).toBe("DELETE");
        const accountId = decodeURIComponent(route.request().url().split("/").pop() ?? "");
        remediatedWalletAccountIds.add(accountId);
        await route.fulfill({
          json: {
            ok: true,
            data: {
              deleted: true,
              accountId,
              provider: "wallet:solana",
              providerAccountId: "So11111111111111111111111111111111111111112",
              issuedBefore: Date.now(),
            },
          },
        });
      },
    );
    await page.route(
      /\/user\/me\/tenants\/[^/]+\/users\/wallet-policy\/remediations$/,
      async (route) => {
        expect(route.request().method()).toBe("POST");
        lastBulkRemediationBody = route.request().postDataJSON() as {
          wallets: Array<{ userId: string; accountId: string }>;
        };
        for (const wallet of lastBulkRemediationBody.wallets) {
          remediatedWalletAccountIds.add(wallet.accountId);
        }
        await route.fulfill({
          json: {
            ok: true,
            data: {
              tenantId,
              succeeded: lastBulkRemediationBody.wallets.length,
              failed: 0,
              results: lastBulkRemediationBody.wallets.map((wallet) => ({
                ok: true,
                targetUserId: wallet.userId,
                accountId: wallet.accountId,
                provider:
                  wallet.accountId === "wallet-account-solana"
                    ? "wallet:solana"
                    : "wallet:ethereum",
                providerAccountId:
                  wallet.accountId === "wallet-account-solana"
                    ? "So11111111111111111111111111111111111111112"
                    : "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                issuedBefore: Date.now(),
                deleted: true,
              })),
            },
          },
        });
      },
    );
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
    await expect(page.getByRole("link", { name: "Users" })).toBeVisible({ timeout: 30_000 });

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
    await expect(page.getByRole("heading", { name: "Third-Party Wallet Policy" })).toBeVisible();
    await expect(page.getByText("Violating Users")).toBeVisible();
    await expect(page.getByText("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).toBeVisible();
    await expect(page.getByText("So11111111111111111111111111111111111111112")).toBeVisible();
    expect(walletPolicyReportLoads).toBeGreaterThan(0);
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Remove Wallet" }).nth(1).click();
    await expect(page.getByText("Removed Solana wallet")).toBeVisible();
    await expect(page.getByText("No users currently violate the one-wallet policy.")).toBeVisible();
    expect(remediatedWalletAccountIds.has("wallet-account-solana")).toBe(true);
    await page.getByRole("button", { name: "Refresh Report" }).click();
    expect(walletPolicyReportLoads).toBeGreaterThan(1);
    walletPolicyReport.violations = [
      {
        userId: tenantUser.userId,
        email: tenantUser.email,
        name: tenantUser.name,
        role: tenantUser.role,
        walletCount: 2,
        wallets: [
          {
            accountId: "wallet-account-evm",
            provider: "wallet:ethereum",
            providerAccountId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          },
          {
            accountId: "wallet-account-solana",
            provider: "wallet:solana",
            providerAccountId: "So11111111111111111111111111111111111111112",
          },
        ],
      },
    ];
    walletPolicyReport.total = 1;
    remediatedWalletAccountIds.clear();
    await page.getByRole("button", { name: "Refresh Report" }).click();
    await page.getByLabel("Select wallet-account-evm").check();
    await page.getByLabel("Select wallet-account-solana").check();
    await expect(page.getByText("2 selected")).toBeVisible();
    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Remove Selected" }).click();
    await expect(page.getByText("Bulk remediation completed: 2 removed, 0 failed.")).toBeVisible();
    expect(lastBulkRemediationBody).not.toBeNull();
    const bulkBody = lastBulkRemediationBody as unknown as {
      wallets: Array<{ userId: string; accountId: string }>;
    };
    expect(bulkBody.wallets).toEqual([
      { userId: tenantUser.userId, accountId: "wallet-account-evm" },
      { userId: tenantUser.userId, accountId: "wallet-account-solana" },
    ]);
    await expect(page.getByText("No users currently violate the one-wallet policy.")).toBeVisible();
    walletPolicyReport.violations = [
      {
        userId: tenantUser.userId,
        email: tenantUser.email,
        name: tenantUser.name,
        role: tenantUser.role,
        walletCount: 2,
        wallets: [
          {
            accountId: "wallet-account-evm",
            provider: "wallet:ethereum",
            providerAccountId: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          },
          {
            accountId: "wallet-account-solana",
            provider: "wallet:solana",
            providerAccountId: "So11111111111111111111111111111111111111112",
          },
        ],
      },
    ];
    walletPolicyReport.total = 1;
    remediatedWalletAccountIds.clear();
    await page.getByRole("button", { name: "Refresh Report" }).click();
    await page.getByRole("button", { name: "Review User" }).click();
    await expect(page.getByText("tenant.member.role.update")).toBeVisible();

    await page.getByLabel("Search field").selectOption("walletExternalId");
    await page.getByPlaceholder("wallet external id").fill("wallet-ext-dashboard-1");
    tenantUser.walletExternalIds = [
      {
        id: "wallet-ext-row-1",
        tenantId,
        walletExternalId: "wallet-ext-dashboard-1",
      },
      {
        tenantId,
        externalId: "wallet-ext-legacy-shape",
      },
    ];
    await page.getByRole("button", { name: "Search" }).click();
    await expect(page.getByText("wallet-ext-dashboard-1").first()).toBeVisible();
    expect(new URL(lastUsersSearchUrl).searchParams.get("walletExternalId")).toBe(
      "wallet-ext-dashboard-1",
    );

    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toMatch(/^personal-.+-users\.csv$/);

    await devUserButton.click();
    await expect(page.getByText("tenant.member.role.update")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Wallet External IDs" })).toBeVisible();
    await expect(page.getByText("wallet-ext-legacy-shape")).toBeVisible();
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

import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type AccountWallet = {
  id: string;
  walletId: string;
  membershipId: string;
  name: string;
  ownerUserId?: string | null;
  walletType?: string | null;
  custody?: {
    type: "server" | "user_embedded" | string;
    ownerUserId?: string | null;
  };
  signing?: {
    signerCount: number;
    activeSignerCount: number;
    quorumCount: number;
    activeQuorumCount: number;
  };
  chainType: "ethereum" | "solana";
  chainFamily: "evm" | "solana";
  address: string;
  purpose?: string | null;
  venue?: string | null;
  createdAt: string;
};

type Account = {
  id: string;
  tenantId: string;
  displayName: string | null;
  metadata: Record<string, unknown>;
  ownerUserIds?: string[];
  owner_user_ids?: string[];
  additionalSignerIds?: string[];
  additional_signer_ids?: string[];
  signerPolicyIds?: string[];
  signer_policy_ids?: string[];
  walletIds: string[];
  wallets: AccountWallet[];
  createdAt: string;
  updatedAt: string;
};

type Aggregation = {
  id: string;
  accountId: string;
  tenantId: string;
  displayName: string | null;
  walletIds: string[];
  chainFamilies: Array<"evm" | "solana">;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

type AuditEvent = {
  id: string;
  seq: number;
  actor_type: string;
  actor_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata: Record<string, unknown>;
  request_id: string | null;
  created_at: string;
};

const now = new Date().toISOString();

function isApiRequest(url: string): boolean {
  return url.startsWith(API);
}

function accountFixture(overrides: Partial<Account> = {}): Account {
  const id = overrides.id ?? "acct_ops";
  const walletIds = overrides.walletIds ?? ["agent-wallet-1"];
  return {
    id,
    tenantId: "personal-asset-accounts",
    displayName: "Ops Account",
    metadata: { env: "test" },
    ownerUserIds: ["user_ops_owner"],
    owner_user_ids: ["user_ops_owner"],
    additionalSignerIds: ["signer_ops_delegate"],
    additional_signer_ids: ["signer_ops_delegate"],
    signerPolicyIds: ["policy_ops_review"],
    signer_policy_ids: ["policy_ops_review"],
    walletIds,
    wallets: walletIds.map((walletId, index) => ({
      id: walletId,
      walletId,
      membershipId: `${id}-member-${index}`,
      name: `${walletId} wallet`,
      ownerUserId: index === 0 ? "user_ops_owner" : null,
      walletType: index === 0 ? "user_embedded" : "agent",
      custody: {
        type: index === 0 ? "user_embedded" : "server",
        ownerUserId: index === 0 ? "user_ops_owner" : null,
      },
      signing: {
        signerCount: 3,
        activeSignerCount: 2,
        quorumCount: 1,
        activeQuorumCount: 1,
      },
      chainType: index % 2 === 0 ? "ethereum" : "solana",
      chainFamily: index % 2 === 0 ? "evm" : "solana",
      address:
        index % 2 === 0
          ? "0x1111111111111111111111111111111111111111"
          : "So11111111111111111111111111111111111111112",
      purpose: index === 0 ? "payments" : "settlement",
      venue: index === 0 ? "base" : "solana-mainnet",
      createdAt: now,
    })),
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

test.describe("Dashboard asset accounts", () => {
  test("authenticated users can manage asset account resources", async ({
    page,
    request,
  }, testInfo) => {
    const email = `asset-accounts-${Date.now()}@example.test`;
    const accounts = [accountFixture()];
    const aggregations: Aggregation[] = [
      {
        id: "acct_agg_existing",
        accountId: "acct_ops",
        tenantId: "personal-asset-accounts",
        displayName: "Existing Snapshot",
        walletIds: ["agent-wallet-1"],
        chainFamilies: ["evm"],
        metadata: {},
        createdAt: now,
        updatedAt: now,
      },
    ];
    const accountHistory: Record<string, AuditEvent[]> = {
      acct_ops: [
        {
          id: "audit-wallet-action",
          seq: 42,
          actor_type: "system",
          actor_id: null,
          action: "wallet.action.signed",
          resource_type: "account",
          resource_id: "acct_ops",
          metadata: {
            walletActionId: "action-transfer-1",
            agentId: "agent-wallet-1",
            status: "signed",
            adapter: {
              kind: "swap",
              provider: "mock-swap",
              lifecycleStatus: "built",
            },
          },
          request_id: "request-wallet-action",
          created_at: now,
        },
        {
          id: "audit-account-create",
          seq: 41,
          actor_type: "user",
          actor_id: "user_ops_owner",
          action: "account.create",
          resource_type: "account",
          resource_id: "acct_ops",
          metadata: { displayName: "Ops Account" },
          request_id: "request-account-create",
          created_at: now,
        },
      ],
      acct_treasury: [],
    };
    let createBody: Record<string, unknown> | null = null;
    let updateBody: Record<string, unknown> | null = null;
    let aggregationBody: Record<string, unknown> | null = null;
    let deletedAccountId: string | null = null;
    const accountHistoryRequests: string[] = [];

    await loginWithMagicLink(page, request, email);

    await page.route(/\/accounts(?:\?.*)?$/, async (route) => {
      const request = route.request();
      if (!isApiRequest(request.url())) {
        await route.fallback();
        return;
      }
      if (request.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { accounts } } });
        return;
      }
      if (request.method() === "POST") {
        createBody = request.postDataJSON() as Record<string, unknown>;
        const created = accountFixture({
          id: String(createBody.id),
          displayName: String(createBody.display_name),
          metadata: createBody.metadata as Record<string, unknown>,
          ownerUserIds: createBody.owner_user_ids as string[],
          owner_user_ids: createBody.owner_user_ids as string[],
          additionalSignerIds: createBody.additional_signer_ids as string[],
          additional_signer_ids: createBody.additional_signer_ids as string[],
          signerPolicyIds: createBody.signer_policy_ids as string[],
          signer_policy_ids: createBody.signer_policy_ids as string[],
          walletIds: createBody.wallet_ids as string[],
        });
        accounts.unshift(created);
        await route.fulfill({ status: 201, json: { ok: true, data: created } });
        return;
      }
      await route.fallback();
    });

    await page.route(/\/accounts\/[^/]+\/aggregations(?:\?.*)?$/, async (route) => {
      const request = route.request();
      if (!isApiRequest(request.url())) {
        await route.fallback();
        return;
      }
      if (request.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { aggregations } } });
        return;
      }
      if (request.method() === "POST") {
        aggregationBody = request.postDataJSON() as Record<string, unknown>;
        const created: Aggregation = {
          id: "acct_agg_new",
          accountId: "acct_ops",
          tenantId: "personal-asset-accounts",
          displayName: String(aggregationBody.display_name),
          walletIds: ["agent-wallet-1", "agent-wallet-2"],
          chainFamilies: ["evm", "solana"],
          metadata: {},
          createdAt: now,
          updatedAt: now,
        };
        aggregations.unshift(created);
        await route.fulfill({ status: 201, json: { ok: true, data: created } });
        return;
      }
      await route.fallback();
    });

    await page.route(/\/accounts\/[^/]+\/aggregations\/[^/]+$/, async (route) => {
      if (!isApiRequest(route.request().url())) {
        await route.fallback();
        return;
      }
      if (route.request().method() !== "DELETE") {
        await route.fallback();
        return;
      }
      const id = route.request().url().split("/").pop() ?? "";
      const index = aggregations.findIndex((aggregation) => aggregation.id === id);
      if (index >= 0) aggregations.splice(index, 1);
      await route.fulfill({ json: { ok: true, data: { id, deleted: true } } });
    });

    await page.route(/\/accounts\/[^/]+$/, async (route) => {
      const request = route.request();
      if (!isApiRequest(request.url())) {
        await route.fallback();
        return;
      }
      const id = request.url().split("/").pop() ?? "";
      const account = accounts.find((item) => item.id === id);
      if (request.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: account } });
        return;
      }
      if (request.method() === "PATCH" && account) {
        updateBody = request.postDataJSON() as Record<string, unknown>;
        account.displayName = String(updateBody.display_name);
        account.metadata = updateBody.metadata as Record<string, unknown>;
        account.ownerUserIds = updateBody.owner_user_ids as string[];
        account.owner_user_ids = updateBody.owner_user_ids as string[];
        account.additionalSignerIds = updateBody.additional_signer_ids as string[];
        account.additional_signer_ids = updateBody.additional_signer_ids as string[];
        account.signerPolicyIds = updateBody.signer_policy_ids as string[];
        account.signer_policy_ids = updateBody.signer_policy_ids as string[];
        account.walletIds = updateBody.wallet_ids as string[];
        await route.fulfill({ json: { ok: true, data: accountFixture(account) } });
        return;
      }
      if (request.method() === "DELETE") {
        deletedAccountId = id;
        const index = accounts.findIndex((item) => item.id === id);
        if (index >= 0) accounts.splice(index, 1);
        await route.fulfill({ json: { ok: true, data: { id, deleted: true } } });
        return;
      }
      await route.fallback();
    });

    await page.route(/\/audit\/events(?:\?.*)?$/, async (route) => {
      const request = route.request();
      if (!isApiRequest(request.url())) {
        await route.fallback();
        return;
      }
      const url = new URL(request.url());
      const resourceType = url.searchParams.get("resourceType");
      const resourceId = url.searchParams.get("resourceId") ?? "";
      accountHistoryRequests.push(url.search);
      expect(resourceType).toBe("account");
      await route.fulfill({
        json: {
          ok: true,
          data: {
            data: accountHistory[resourceId] ?? [],
            pagination: {
              page: 1,
              limit: 10,
              total: accountHistory[resourceId]?.length ?? 0,
              totalPages: accountHistory[resourceId]?.length ? 1 : 0,
            },
          },
        },
      });
    });

    await page.goto(`${WEB}/dashboard/accounts`);
    await expect(page.getByRole("heading", { name: "Asset Accounts" })).toBeVisible();
    await expect(page.getByText("Ops Account").first()).toBeVisible();
    await expect(page.getByText("Existing Snapshot")).toBeVisible();
    await expect(page.getByText("User embedded")).toBeVisible();
    await expect(page.getByText("2/3 signers, 1/1 quorums")).toBeVisible();
    await expect(page.getByText("purpose payments")).toBeVisible();
    await expect(page.getByText("venue base")).toBeVisible();
    await expect(page.getByText("owner user_ops_owner")).toBeVisible();
    await expect(page.getByText("membership acct_ops-member-0")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Authorization Assignments" })).toBeVisible();
    const authorizationSection = page.locator("section").filter({
      has: page.getByRole("heading", { name: "Authorization Assignments" }),
    });
    await expect(authorizationSection.getByText("signer_ops_delegate")).toBeVisible();
    await expect(authorizationSection.getByText("policy_ops_review")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Account History" })).toBeVisible();
    await expect(page.getByText("Showing 2 of 2 events")).toBeVisible();
    await expect(page.getByText("wallet.action.signed")).toBeVisible();
    await expect(
      page.getByText("status signed - action action-transfer-1 - wallet agent-wallet-1"),
    ).toBeVisible();
    await expect(page.getByText("swap / mock-swap / built")).toBeVisible();
    await expect(page.getByText("account.create")).toBeVisible();
    expect(accountHistoryRequests.some((query) => query.includes("resourceId=acct_ops"))).toBe(
      true,
    );

    await page.getByRole("button", { name: "New Account" }).click();
    await page.getByLabel("Create Asset Account account id").fill("acct_treasury");
    await page.getByLabel("Create Asset Account display name").fill("Treasury");
    await page.getByLabel("Create Asset Account owner user ids").fill("user_treasury_owner");
    await page
      .getByLabel("Create Asset Account additional signer ids")
      .fill("signer_treasury_delegate");
    await page.getByLabel("Create Asset Account signer policy ids").fill("policy_treasury_review");
    await page.getByLabel("Create Asset Account wallet ids").fill("treasury-wallet-1");
    await page
      .getByLabel("Create Asset Account metadata JSON")
      .fill('{\n  "purpose": "treasury"\n}');
    await page.getByRole("button", { name: "Create", exact: true }).click();

    await expect(page.getByText("Treasury").first()).toBeVisible();
    expect(createBody).toMatchObject({
      id: "acct_treasury",
      display_name: "Treasury",
      metadata: { purpose: "treasury" },
      owner_user_ids: ["user_treasury_owner"],
      additional_signer_ids: ["signer_treasury_delegate"],
      signer_policy_ids: ["policy_treasury_review"],
      wallet_ids: ["treasury-wallet-1"],
    });

    await page.getByRole("button", { name: "Ops Account" }).click();
    await page.getByLabel("Edit Account display name").fill("Ops Updated");
    await page.getByLabel("Edit Account owner user ids").fill("user_ops_owner\nuser_ops_backup");
    await page
      .getByLabel("Edit Account additional signer ids")
      .fill("signer_ops_delegate\nsigner_ops_breakglass");
    await page
      .getByLabel("Edit Account signer policy ids")
      .fill("policy_ops_review\npolicy_ops_mfa");
    await page.getByLabel("Edit Account wallet ids").fill("agent-wallet-1\nagent-wallet-2");
    await page.getByRole("button", { name: "Save Changes" }).click();
    await expect(page.getByText("Ops Updated").first()).toBeVisible();
    await expect(authorizationSection.getByText("user_ops_backup")).toBeVisible();
    await expect(authorizationSection.getByText("signer_ops_breakglass")).toBeVisible();
    await expect(authorizationSection.getByText("policy_ops_mfa")).toBeVisible();
    expect(updateBody).toMatchObject({
      display_name: "Ops Updated",
      owner_user_ids: ["user_ops_owner", "user_ops_backup"],
      additional_signer_ids: ["signer_ops_delegate", "signer_ops_breakglass"],
      signer_policy_ids: ["policy_ops_review", "policy_ops_mfa"],
      wallet_ids: ["agent-wallet-1", "agent-wallet-2"],
    });

    await page.getByPlaceholder("Aggregation name").fill("Month End");
    await page.getByRole("button", { name: "Create Snapshot" }).click();
    await expect(page.getByText("Month End")).toBeVisible();
    expect(aggregationBody).toMatchObject({ display_name: "Month End" });

    await page.getByRole("button", { name: "Remove" }).first().click();
    await expect(page.getByText("Month End")).toHaveCount(0);

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: "Delete" }).click();
    expect(deletedAccountId).toBe("acct_ops");

    await page.screenshot({
      path: testInfo.outputPath("dashboard-asset-accounts.png"),
      fullPage: true,
    });
  });
});

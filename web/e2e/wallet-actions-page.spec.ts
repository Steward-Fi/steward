import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

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

test.describe("Dashboard wallet actions", () => {
  test("renders action statuses and adapter lifecycle metadata", async ({
    page,
    request,
  }, testInfo) => {
    const email = `wallet-actions-${Date.now()}@example.test`;
    const walletActionEvents: AuditEvent[] = [
      {
        id: "audit-transfer-confirmed",
        seq: 56,
        actor_type: "agent",
        actor_id: "agent-wallet-4",
        action: "wallet_action.transfer.confirmed",
        resource_type: "wallet_action",
        resource_id: "action-transfer-4",
        metadata: {
          chainId: 8453,
          to: "0x4444444444444444444444444444444444444444",
          value: "3000000000000000",
          token: "native",
          status: "confirmed",
          txHash: "0xconfirmed",
        },
        request_id: "request-transfer-confirmed",
        created_at: now,
      },
      {
        id: "audit-transfer-success",
        seq: 54,
        actor_type: "agent",
        actor_id: "agent-wallet-1",
        action: "wallet_action.transfer.succeeded",
        resource_type: "wallet_action",
        resource_id: "action-transfer-1",
        metadata: {
          chainId: 8453,
          to: "0x2222222222222222222222222222222222222222",
          value: "1000000000000000",
          token: "native",
          broadcast: true,
          txHash: "0xabc",
        },
        request_id: "request-transfer-success",
        created_at: now,
      },
      {
        id: "audit-transfer-queued",
        seq: 53,
        actor_type: "agent",
        actor_id: "agent-wallet-2",
        action: "wallet_action.transfer.queued_for_approval",
        resource_type: "wallet_action",
        resource_id: "action-transfer-2",
        metadata: {
          chainId: 1,
          to: "0x3333333333333333333333333333333333333333",
          value: "2000000000000000",
          token: "native",
        },
        request_id: "request-transfer-queued",
        created_at: now,
      },
      {
        id: "audit-transfer-failed",
        seq: 52,
        actor_type: "agent",
        actor_id: "agent-wallet-3",
        action: "wallet_action.transfer.failed",
        resource_type: "wallet_action",
        resource_id: "action-transfer-3",
        metadata: { error: "simulated failure" },
        request_id: "request-transfer-failed",
        created_at: now,
      },
    ];
    const adapterEvents: AuditEvent[] = [
      {
        id: "audit-adapter-replaced",
        seq: 57,
        actor_type: "system",
        actor_id: null,
        action: "wallet.action.replaced",
        resource_type: "account",
        resource_id: "acct_ops",
        metadata: {
          walletActionId: "action-swap-replaced",
          agentId: "agent-wallet-4",
          replacementTxHash: "0xreplacement",
          adapter: {
            kind: "swap",
            provider: "mock-swap",
            lifecycleStatus: "replaced",
            sessionId: "adapter-session-2",
          },
        },
        request_id: "request-adapter-replaced",
        created_at: now,
      },
      {
        id: "audit-adapter-signed",
        seq: 55,
        actor_type: "system",
        actor_id: null,
        action: "wallet.action.signed",
        resource_type: "account",
        resource_id: "acct_ops",
        metadata: {
          walletActionId: "action-swap-1",
          agentId: "agent-wallet-1",
          status: "signed",
          chainId: 8453,
          adapter: {
            kind: "swap",
            provider: "mock-swap",
            lifecycleStatus: "built",
            sessionId: "adapter-session-1",
          },
        },
        request_id: "request-adapter-signed",
        created_at: now,
      },
    ];
    const auditQueries: string[] = [];
    const adapterOnlyReloadQueries: string[] = [];
    let recordAdapterOnlyReload = false;

    await loginWithMagicLink(page, request, email);

    await page.route(/\/audit\/events(?:\?.*)?$/, async (route) => {
      const req = route.request();
      if (!isApiRequest(req.url())) {
        await route.fallback();
        return;
      }
      const url = new URL(req.url());
      auditQueries.push(url.search);
      if (recordAdapterOnlyReload) {
        adapterOnlyReloadQueries.push(url.search);
      }
      const resourceType = url.searchParams.get("resourceType");
      const actionPrefix = url.searchParams.get("actionPrefix");
      const data =
        resourceType === "wallet_action" && actionPrefix === "wallet_action."
          ? walletActionEvents
          : resourceType === "account" && actionPrefix === "wallet.action."
            ? adapterEvents
            : [];
      await route.fulfill({
        json: {
          ok: true,
          data: {
            data,
            pagination: {
              page: 1,
              limit: 50,
              total: data.length,
              totalPages: data.length ? 1 : 0,
            },
          },
        },
      });
    });

    await page.goto(`${WEB}/dashboard/actions`);
    await expect(page.getByRole("heading", { name: "Wallet Actions" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Actions", exact: true })).toBeVisible();

    await expect(page.getByText("Showing 6 of 6 loaded events")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.confirmed")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.succeeded")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.queued_for_approval")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.failed")).toBeVisible();
    await expect(page.getByText("wallet.action.replaced")).toBeVisible();
    await expect(page.getByText("wallet.action.signed")).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet_action.transfer.confirmed" })
        .getByText("Confirmed", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet_action.transfer.succeeded" })
        .getByText("Succeeded", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet_action.transfer.queued_for_approval" })
        .getByText("Queued", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet_action.transfer.failed" })
        .getByText("Failed", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet.action.signed" })
        .getByText("Signed", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .locator("article")
        .filter({ hasText: "wallet.action.replaced" })
        .getByText("Replaced", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText("0xconfirmed")).toBeVisible();
    await expect(page.getByText("0xreplacement")).toBeVisible();
    await expect(page.getByText("swap / mock-swap / built")).toBeVisible();
    await expect(page.getByText("swap / mock-swap / replaced")).toBeVisible();
    await expect(page.getByText("session adapter-session-1")).toBeVisible();
    await expect(page.getByText("session adapter-session-2")).toBeVisible();
    await expect(page.getByText("action-swap-1")).toBeVisible();
    await expect(page.getByText("agent-wallet-1").first()).toBeVisible();

    await page.getByRole("button", { name: "Confirmed 1" }).click();
    await expect(page.getByText("Showing 1 of 6 loaded events")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.confirmed")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.failed")).toHaveCount(0);
    await page.getByRole("button", { name: "All", exact: true }).click();
    await page.getByLabel("Search wallet actions").fill("0xreplacement");
    await expect(page.getByText("Showing 1 of 6 loaded events")).toBeVisible();
    await expect(page.getByText("wallet.action.replaced")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.confirmed")).toHaveCount(0);
    await page.getByLabel("Search wallet actions").fill("");

    expect(
      auditQueries.some((query) => {
        const params = new URLSearchParams(query);
        return (
          params.get("resourceType") === "wallet_action" &&
          params.get("actionPrefix") === "wallet_action."
        );
      }),
    ).toBeTruthy();
    expect(
      auditQueries.some((query) => {
        const params = new URLSearchParams(query);
        return (
          params.get("resourceType") === "account" &&
          params.get("actionPrefix") === "wallet.action."
        );
      }),
    ).toBeTruthy();

    recordAdapterOnlyReload = true;
    await page.getByLabel("Adapter metadata only").check();
    await expect
      .poll(() => adapterOnlyReloadQueries.length, {
        message: "adapter-only reload should issue exactly one audit query",
      })
      .toBe(1);

    const adapterOnlyParams = new URLSearchParams(adapterOnlyReloadQueries[0]);
    expect(adapterOnlyParams.get("resourceType")).toBe("account");
    expect(adapterOnlyParams.get("actionPrefix")).toBe("wallet.action.");
    expect(adapterOnlyParams.get("limit")).toBe("50");
    expect(
      adapterOnlyReloadQueries.some((query) => {
        const params = new URLSearchParams(query);
        return (
          params.get("resourceType") === "wallet_action" ||
          params.get("actionPrefix") === "wallet_action."
        );
      }),
    ).toBe(false);

    await expect(page.getByText("Showing 2 of 2 loaded events")).toBeVisible();
    await expect(page.getByText("wallet.action.signed")).toBeVisible();
    await expect(page.getByText("wallet.action.replaced")).toBeVisible();
    await expect(page.getByText("wallet_action.transfer.succeeded")).toHaveCount(0);
    await expect(page.getByText("wallet_action.transfer.confirmed")).toHaveCount(0);
    await expect(page.getByText("wallet_action.transfer.queued_for_approval")).toHaveCount(0);
    await expect(page.getByText("wallet_action.transfer.failed")).toHaveCount(0);
    await expect(page.getByText("swap / mock-swap / built")).toBeVisible();
    await expect(page.getByText("swap / mock-swap / replaced")).toBeVisible();
    await expect(page.getByText("session adapter-session-1")).toBeVisible();
    await expect(page.getByText("session adapter-session-2")).toBeVisible();
    await expect(page.getByText("action-swap-1")).toBeVisible();
    await expect(page.getByText("agent-wallet-1").first()).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-wallet-actions.png"),
      fullPage: true,
    });
  });
});

import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

const DENY_STATUSES = new Set(["rejected", "denied", "deny", "violation", "policy_violation"]);
const ERROR_STATUSES = new Set(["error", "failed", "failure"]);

type AuditLogEntry = {
  id: string;
  timestamp: string;
  agentId: string;
  action: string;
  status: string;
  details?: Record<string, unknown>;
  value?: string;
};

function isApiRequest(url: string): boolean {
  return url.startsWith(API);
}

function rawStatusMatchesFilter(rawStatus: string, filterStatus: string | null): boolean {
  if (!filterStatus) return true;
  const normalized = rawStatus.toLowerCase();
  if (filterStatus === "deny") return DENY_STATUSES.has(normalized);
  if (filterStatus === "error") return ERROR_STATUSES.has(normalized);
  return normalized === filterStatus;
}

test.describe("Dashboard audit log", () => {
  test("authenticated admins can filter and inspect security audit events", async ({
    page,
    request,
  }, testInfo) => {
    const email = `audit-log-${Date.now()}@example.test`;
    const auditQueries: string[] = [];
    const auditEntries: AuditLogEntry[] = [
      {
        id: "audit-deny-vault-signing",
        timestamp: "2026-06-04T14:15:00.000Z",
        agentId: "agent-risk-review",
        action: "sign_tx",
        status: "denied",
        value: "0.0003",
        details: {
          policy: "daily-spend-limit",
          reason: "recipient not on allowlist",
          txId: "tx-policy-review-1",
        },
      },
      {
        id: "audit-allow-proxy",
        timestamp: "2026-06-04T14:10:00.000Z",
        agentId: "agent-support",
        action: "proxy",
        status: "approved",
        value: "0.00001",
        details: { route: "/v1/chat/completions", provider: "openai" },
      },
      {
        id: "audit-error-secret",
        timestamp: "2026-06-04T14:05:00.000Z",
        agentId: "agent-risk-review",
        action: "secret_inject",
        status: "error",
        value: "0",
        details: { secretId: "sec_prod", failure: "missing route binding" },
      },
    ];

    await loginWithMagicLink(page, request, email);

    await page.route(
      (url) => isApiRequest(url.href) && url.pathname === "/agents",
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: [
              {
                id: "agent-risk-review",
                tenantId: "personal-test",
                name: "Risk Review Agent",
                walletAddress: "0x1111111111111111111111111111111111111111",
                createdAt: "2026-06-04T13:00:00.000Z",
              },
              {
                id: "agent-support",
                tenantId: "personal-test",
                name: "Support Agent",
                walletAddress: "0x2222222222222222222222222222222222222222",
                createdAt: "2026-06-04T13:05:00.000Z",
              },
            ],
          },
        });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href) && url.pathname === "/audit/summary",
      async (route) => {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              totalTransactions: 3,
              totalApprovals: 1,
              totalRejections: 1,
              totalProxyRequests: 1,
              policyViolations: 1,
              topAgents: [
                { agentId: "agent-risk-review", name: "Risk Review Agent", txCount: 2 },
                { agentId: "agent-support", name: "Support Agent", txCount: 1 },
              ],
              dailyActivity: [{ date: "2026-06-04", txCount: 3 }],
            },
          },
        });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href) && url.pathname === "/audit/log",
      async (route) => {
        const url = new URL(route.request().url());
        auditQueries.push(url.search);

        const agentId = url.searchParams.get("agentId");
        const action = url.searchParams.get("action");
        const status = url.searchParams.get("status");
        const filtered = auditEntries.filter(
          (entry) =>
            (!agentId || entry.agentId === agentId) &&
            (!action || entry.action === action) &&
            rawStatusMatchesFilter(entry.status, status),
        );

        await route.fulfill({
          json: {
            ok: true,
            data: {
              data: filtered,
              pagination: {
                page: Number(url.searchParams.get("page") ?? "1"),
                limit: Number(url.searchParams.get("limit") ?? "50"),
                total: filtered.length,
                totalPages: filtered.length ? 1 : 0,
              },
            },
          },
        });
      },
    );

    await page.goto(`${WEB}/dashboard/audit`);

    await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible();
    await expect(page.getByText("Total Actions")).toBeVisible();
    await expect(page.getByText("Denied", { exact: true })).toBeVisible();
    await expect(page.getByText("Active Agents")).toBeVisible();
    await expect(page.getByText("Risk Review Agent").first()).toBeVisible();
    await expect(page.getByText("agent-risk-review").first()).toBeVisible();
    await expect(page.getByText("sign_tx")).toBeVisible();
    await expect(page.getByText("proxy")).toBeVisible();

    await page.getByLabel("Agent").selectOption("agent-risk-review");
    await page.getByLabel("Action Type").selectOption("sign_tx");
    await page.getByLabel("Result").selectOption("deny");
    await page.getByRole("button", { name: /Apply/ }).click();

    await expect
      .poll(() => {
        const params = new URLSearchParams(auditQueries[auditQueries.length - 1] ?? "");
        return {
          action: params.get("action"),
          agentId: params.get("agentId"),
          limit: params.get("limit"),
          status: params.get("status"),
        };
      })
      .toEqual({
        action: "sign_tx",
        agentId: "agent-risk-review",
        limit: "50",
        status: "deny",
      });
    await expect(page.getByText("sign_tx")).toBeVisible();
    await expect(page.getByRole("button", { name: /proxy/ })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /secret_inject/ })).toHaveCount(0);

    const filteredParams = new URLSearchParams(auditQueries[auditQueries.length - 1] ?? "");
    expect(filteredParams.get("agentId")).toBe("agent-risk-review");
    expect(filteredParams.get("action")).toBe("sign_tx");
    expect(filteredParams.get("status")).toBe("deny");
    expect(filteredParams.get("limit")).toBe("50");

    await page.getByRole("button", { name: /sign_tx/ }).click();
    await expect(page.getByText("Details")).toBeVisible();
    await expect(page.getByText("recipient not on allowlist")).toBeVisible();
    await expect(page.getByText("daily-spend-limit")).toBeVisible();
    await expect(page.getByText("ID: audit-deny-vault-signing")).toBeVisible();
    await expect(page.getByText("Agent totals:")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-audit-log-filtered.png"),
      fullPage: true,
    });
  });
});

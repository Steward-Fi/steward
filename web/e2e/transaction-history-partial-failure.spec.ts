import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test("dashboard surfaces partial transaction history without discarding available rows", async ({
  page,
  request,
}) => {
  await loginWithMagicLink(page, request, `partial-history-${Date.now()}@example.test`);

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
              id: "tx-visible",
              agentId: "agent-available",
              status: "pending",
              request: {
                chainId: 8453,
                to: "0x1111111111111111111111111111111111111111",
                value: "1000000000000000",
              },
              policyResults: [],
              createdAt: "2026-08-20T12:00:00.000Z",
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

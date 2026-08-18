import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test("an invitation is accepted only after explicit confirmation", async ({ page, request }) => {
  await loginWithMagicLink(page, request, `invitation-${Date.now()}@example.test`);

  let acceptRequests = 0;
  await page.route("**/user/me/tenants/invited-tenant/invitations/accept", async (route) => {
    acceptRequests += 1;
    await route.fulfill({
      json: {
        ok: true,
        data: {
          tenantId: "invited-tenant",
          role: "member",
          invitationId: "invitation-1",
        },
      },
    });
  });

  await page.goto(`${WEB}/accept-invitation?tenantId=invited-tenant&token=invitation-token`);
  await expect(page.getByRole("button", { name: "Accept invitation" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Decline" })).toBeVisible();
  expect(acceptRequests).toBe(0);

  await page.getByRole("button", { name: "Accept invitation" }).click();
  await expect.poll(() => acceptRequests).toBe(1);
  await expect(page.getByText("You've joined invited-tenant as member.")).toBeVisible();
});

import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type AccessAllowlistEntry = {
  id: string;
  tenantId: string;
  type: "email" | "email_domain" | "wallet" | "phone";
  value: string;
  acceptedAt: string | null;
};

test.describe("Dashboard access allowlist controls", () => {
  test("authenticated users can manage app access allowlist entries", async ({
    page,
    request,
  }, testInfo) => {
    const email = `allowlist-${Date.now()}@example.test`;
    const tenantId = "e2e-tenant";
    let entries: AccessAllowlistEntry[] = [
      {
        id: "email_domain:example.test",
        tenantId,
        type: "email_domain",
        value: "example.test",
        acceptedAt: null,
      },
    ];

    await page.route(/\/tenants\/[^/]+\/access-allowlist$/, async (route) => {
      const request = route.request();
      if (request.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { entries } } });
        return;
      }
      if (request.method() === "POST") {
        const body = request.postDataJSON() as {
          entries?: Array<{ type: AccessAllowlistEntry["type"]; value: string }>;
          type?: AccessAllowlistEntry["type"];
          value?: string;
        };
        const additions = body.entries ?? [{ type: body.type!, value: body.value! }];
        entries = entries.concat(
          additions.map((entry) => ({
            id: `${entry.type}:${entry.value}`,
            tenantId,
            type: entry.type,
            value: entry.value,
            acceptedAt: null,
          })),
        );
        await route.fulfill({ json: { ok: true, data: { entries } } });
        return;
      }
      if (request.method() === "DELETE") {
        const body = request.postDataJSON() as { id: string };
        entries = entries.filter((entry) => entry.id !== body.id);
        await route.fulfill({ json: { ok: true, data: { entries } } });
        return;
      }
      await route.fallback();
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

    await page.goto(`${WEB}/dashboard/settings`);
    await expect(page.getByRole("heading", { name: "App Access Allowlist" })).toBeVisible();

    const allowlist = page.locator("form").filter({
      has: page.getByRole("heading", { name: "App Access Allowlist" }),
    });
    await expect(allowlist.getByText("example.test")).toBeVisible();

    await allowlist.getByRole("combobox", { name: /^Type$/ }).selectOption("email");
    const valueInput = allowlist.getByRole("textbox", { name: /^Value$/ });
    await valueInput.fill("alice@example.test");
    await expect(valueInput).toHaveValue("alice@example.test");
    await allowlist.getByRole("button", { name: "Add Entry" }).click();
    await expect(allowlist.getByText("alice@example.test")).toBeVisible();

    await allowlist
      .getByRole("textbox", { name: /^Bulk Entries/ })
      .fill("email_domain: customer.test\nwallet: 0x0000000000000000000000000000000000000001");
    await allowlist.getByRole("button", { name: "Add Entry" }).click();
    await expect(allowlist.getByText("customer.test")).toBeVisible();
    await expect(allowlist.getByText("0x0000000000000000000000000000000000000001")).toBeVisible();

    await allowlist
      .getByRole("row", { name: /alice@example\.test/ })
      .getByRole("button", { name: "Remove" })
      .click();
    await expect(allowlist.getByText("alice@example.test")).toBeHidden();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-access-allowlist.png"),
      fullPage: true,
    });
  });
});

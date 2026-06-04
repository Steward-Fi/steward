import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type RequestSigningKey = {
  id: string;
  tenantId: string;
  name: string;
  secretPrefix: string;
  status: "active" | "retiring" | "revoked";
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
};

test.describe("Dashboard request signing keys", () => {
  test("authenticated admins can rotate, reveal, and revoke signing keys", async ({
    page,
    request,
  }, testInfo) => {
    const email = `request-signing-${Date.now()}@example.test`;
    let keys: RequestSigningKey[] = [
      {
        id: "sig_existing",
        tenantId: "personal-test",
        name: "Existing signing key",
        secretPrefix: "stw_sig_existing",
        status: "active",
        createdAt: "2026-05-28T12:00:00.000Z",
        updatedAt: "2026-05-28T12:00:00.000Z",
        expiresAt: null,
        revokedAt: null,
      },
    ];

    await page.route(/\/tenants\/[^/]+\/config$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            allowedOrigins: ["https://app.example.com"],
            allowedRedirectUrls: ["https://app.example.com/auth/callback"],
            appClients: [],
          },
        },
      });
    });
    await page.route(/\/tenants\/[^/]+\/security-checklist$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            tenantId: "personal-test",
            generatedAt: "2026-05-29T00:00:00.000Z",
            summary: { pass: 7, warning: 0, fail: 0 },
            items: [],
          },
        },
      });
    });
    await page.route(/\/tenants\/[^/]+\/request-signing-keys(?:\/[^/]+)?$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { keys } } });
        return;
      }
      if (routeRequest.method() === "POST") {
        const body = routeRequest.postDataJSON() as { name?: string };
        keys = keys.map((key) =>
          key.status === "active"
            ? {
                ...key,
                status: "retiring",
                expiresAt: "2026-06-04T12:00:00.000Z",
                updatedAt: "2026-05-29T12:00:00.000Z",
              }
            : key,
        );
        const created: RequestSigningKey = {
          id: "sig_rotated",
          tenantId: "personal-test",
          name: body.name ?? "Production signing key",
          secretPrefix: "stw_sig_rotated",
          status: "active",
          createdAt: "2026-05-29T12:00:00.000Z",
          updatedAt: "2026-05-29T12:00:00.000Z",
          expiresAt: null,
          revokedAt: null,
        };
        keys = [created, ...keys];
        await route.fulfill({
          json: {
            ok: true,
            data: {
              key: created,
              signingSecret: "stw_sig_rotated_once_only",
            },
          },
        });
        return;
      }
      if (routeRequest.method() === "DELETE") {
        const keyId = new URL(routeRequest.url()).pathname.split("/").at(-1);
        keys = keys.map((key) =>
          key.id === keyId
            ? {
                ...key,
                status: "revoked",
                revokedAt: "2026-05-29T12:05:00.000Z",
                updatedAt: "2026-05-29T12:05:00.000Z",
              }
            : key,
        );
        const revoked = keys.find((key) => key.id === keyId);
        await route.fulfill({ json: { ok: true, data: { key: revoked } } });
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
    const section = page.locator("section").filter({
      has: page.getByRole("heading", { name: "Request Signing Keys" }),
    });
    await expect(section).toBeVisible();
    await expect(section.getByText("Existing signing key")).toBeVisible();

    await section.getByLabel("Key Name").fill("Production API signing");
    await section.getByRole("button", { name: "Rotate Key" }).click();
    await expect(section.getByText("Secret: stw_sig_rotated_once_only")).toBeVisible();
    await expect(section.getByText('requestSigningKeyId: "sig_rotated"')).toBeVisible();
    await expect(section.getByText("Production API signing")).toBeVisible();

    await section.getByRole("button", { name: "Revoke" }).last().click();
    await expect(section.getByText("revoked")).toBeVisible();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-request-signing-keys.png"),
      fullPage: true,
    });
  });
});

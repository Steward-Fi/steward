import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type AppClient = {
  id: string;
  name: string;
  environment: "development" | "preview" | "staging" | "production";
  enabled: boolean;
  allowedOrigins: string[];
  allowedRedirectUrls: string[];
};

test.describe("Dashboard app client settings", () => {
  test("authenticated users can add and edit app clients", async ({ page, request }, testInfo) => {
    const email = `app-clients-${Date.now()}@example.test`;
    let savedAppClients: AppClient[] = [
      {
        id: "web-prod",
        name: "Production Web",
        environment: "production",
        enabled: true,
        allowedOrigins: ["https://app.example.com"],
        allowedRedirectUrls: ["https://app.example.com/auth/callback"],
      },
    ];

    await page.route(/\/tenants\/[^/]+\/config$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              allowedOrigins: ["https://app.example.com"],
              allowedRedirectUrls: ["https://app.example.com/auth/callback"],
              appClients: savedAppClients,
            },
          },
        });
        return;
      }
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as { appClients?: AppClient[] };
        if (body.appClients) savedAppClients = body.appClients;
        await route.fulfill({
          json: {
            ok: true,
            data: {
              allowedOrigins: ["https://app.example.com"],
              allowedRedirectUrls: ["https://app.example.com/auth/callback"],
              appClients: savedAppClients,
            },
          },
        });
        return;
      }
      await route.fallback();
    });
    await page.route(/\/tenants\/[^/]+\/app-clients\/[^/]+\/secrets$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            appId: "personal-test/web-prod",
            appSecret: "stw_app_created_once",
            secret: {
              id: "secret-1",
              tenantId: "personal-test",
              clientId: "web-prod",
              appId: "personal-test/web-prod",
              secretPrefix: "stw_app_cre...once",
              status: "active",
              createdAt: "2026-05-28T12:00:00.000Z",
              updatedAt: "2026-05-28T12:00:00.000Z",
              expiresAt: null,
              revokedAt: null,
            },
          },
        },
      });
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
    const appClientsForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "App Clients" }),
    });
    await expect(appClientsForm).toBeVisible();

    const firstClient = appClientsForm.getByTestId("app-client-row").first();
    await expect(firstClient.getByLabel("Client ID")).toHaveValue("web-prod");
    await expect(firstClient.getByLabel("Name")).toHaveValue("Production Web");
    await expect(firstClient.getByLabel("Environment")).toHaveValue("production");

    await firstClient.getByLabel("Name").fill("Production Web Updated");
    await firstClient.getByLabel("Environment").selectOption("preview");
    await firstClient.getByLabel("Enabled").uncheck();
    await firstClient.getByLabel("Allowed Origins").fill("https://preview.example.com");
    await firstClient.getByLabel("Redirect URLs").fill("https://preview.example.com/auth/callback");
    await firstClient.getByRole("button", { name: "Rotate Secret" }).click();
    await expect(firstClient.getByText("stw_app_created_once")).toBeVisible();

    await appClientsForm.getByRole("button", { name: "Add Client" }).click();
    const secondClient = appClientsForm.getByTestId("app-client-row").nth(1);
    await secondClient.getByLabel("Client ID").fill("mobile-dev");
    await secondClient.getByLabel("Name").fill("Mobile Development");
    await secondClient.getByLabel("Environment").selectOption("development");
    await secondClient.getByLabel("Allowed Origins").fill("http://localhost:3000");
    await secondClient.getByLabel("Redirect URLs").fill("http://localhost:3000/auth/callback");

    await appClientsForm.getByRole("button", { name: "Save Clients" }).click();
    await expect(appClientsForm.getByText("Saved")).toBeVisible();

    expect(savedAppClients).toEqual([
      {
        id: "web-prod",
        name: "Production Web Updated",
        environment: "preview",
        enabled: false,
        allowedOrigins: ["https://preview.example.com"],
        allowedRedirectUrls: ["https://preview.example.com/auth/callback"],
      },
      {
        id: "mobile-dev",
        name: "Mobile Development",
        environment: "development",
        enabled: true,
        allowedOrigins: ["http://localhost:3000"],
        allowedRedirectUrls: ["http://localhost:3000/auth/callback"],
      },
    ]);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-app-clients.png"),
      fullPage: true,
    });
  });
});

import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type AppClient = {
  id: string;
  name: string;
  environment: "development" | "preview" | "staging" | "production";
  enabled: boolean;
  allowedOrigins: string[];
  allowedRedirectUrls: string[];
  loginMethods?: {
    passkey?: boolean;
    email?: boolean;
    sms?: boolean;
    whatsapp?: boolean;
    totp?: boolean;
    siwe?: boolean;
    siws?: boolean;
    telegram?: boolean;
    farcaster?: boolean;
    oauth?: {
      google?: boolean;
      discord?: boolean;
      github?: boolean;
      twitter?: boolean;
    };
  };
  embeddedWallets?: {
    createOnLogin?: "off" | "users-without-wallets" | "all-users";
  };
  globalWalletEnabled?: boolean;
  globalWalletAllowedScopes?: string[];
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
        loginMethods: {
          passkey: true,
          email: true,
          sms: false,
          whatsapp: false,
          totp: true,
          siwe: true,
          siws: true,
          telegram: true,
          farcaster: true,
          oauth: {
            google: true,
            discord: true,
            github: true,
            twitter: false,
          },
        },
        embeddedWallets: { createOnLogin: "users-without-wallets" },
        globalWalletEnabled: false,
        globalWalletAllowedScopes: ["eth_accounts", "personal_sign"],
      },
      {
        id: "web-inherit",
        name: "Inherited Web",
        environment: "preview",
        enabled: true,
        allowedOrigins: ["https://inherit.example.com"],
        allowedRedirectUrls: ["https://inherit.example.com/auth/callback"],
        globalWalletEnabled: false,
        globalWalletAllowedScopes: ["eth_accounts"],
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

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/settings`);
    const appClientsForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "App Clients" }),
    });
    await expect(appClientsForm).toBeVisible();

    const firstClient = appClientsForm.getByTestId("app-client-row").first();
    await expect(firstClient.getByLabel("Client ID")).toHaveValue("web-prod");
    await expect(firstClient.getByLabel("Name")).toHaveValue("Production Web");
    await expect(firstClient.getByLabel("Environment")).toHaveValue("production");

    const inheritedClient = appClientsForm.getByTestId("app-client-row").nth(1);
    await expect(inheritedClient.getByLabel("Client ID")).toHaveValue("web-inherit");
    await expect(inheritedClient.getByLabel("Create on Login")).toHaveValue("inherit");
    await inheritedClient.getByLabel("Name").fill("Inherited Web Updated");

    await firstClient.getByLabel("Environment").selectOption("preview");
    await firstClient.getByLabel("Enabled").uncheck();
    await firstClient.getByLabel("Allowed Origins").fill("https://preview.example.com");
    await firstClient.getByLabel("Redirect URLs").fill("https://preview.example.com/auth/callback");
    await firstClient.getByRole("checkbox", { name: "SMS" }).check();
    await firstClient.getByRole("checkbox", { name: "SIWE" }).uncheck();
    await firstClient.getByRole("checkbox", { name: "Twitter/X" }).check();
    await firstClient.getByRole("checkbox", { name: "Global Wallet" }).check();
    await firstClient.getByLabel("Global Wallet Scopes").fill("eth_accounts");
    await firstClient.getByLabel("Create on Login").selectOption("off");
    await firstClient.getByRole("button", { name: "Rotate Secret" }).click();
    await expect(firstClient.getByTestId("app-client-secret-value")).toContainText(
      "stw_app_created_once",
    );
    await expect(firstClient.getByText("Use the same secret as")).toBeVisible();
    await firstClient.getByLabel("Name").fill("Production Web Updated");
    await expect(firstClient.getByLabel("Name")).toHaveValue("Production Web Updated");

    await appClientsForm.getByRole("button", { name: "Add Client" }).click();
    const secondClient = appClientsForm.getByTestId("app-client-row").nth(2);
    await expect(secondClient.getByLabel("Create on Login")).toHaveValue("inherit");
    await secondClient.getByLabel("Client ID").fill("mobile-dev");
    await secondClient.getByLabel("Name").fill("Mobile Development");
    await secondClient.getByLabel("Environment").selectOption("development");
    await secondClient.getByLabel("Allowed Origins").fill("http://localhost:3000");
    await secondClient.getByLabel("Redirect URLs").fill("http://localhost:3000/auth/callback");
    await secondClient.getByLabel("Global Wallet Scopes").fill("eth_accounts\npersonal_sign");
    await expect(secondClient.getByLabel("Create on Login")).toHaveValue("inherit");
    await secondClient.getByLabel("Create on Login").selectOption("all-users");

    await appClientsForm.getByRole("button", { name: "Add Client" }).click();
    const thirdClient = appClientsForm.getByTestId("app-client-row").nth(3);
    await thirdClient.getByLabel("Client ID").fill("server-prod");
    await thirdClient.getByLabel("Name").fill("Server Production");
    await thirdClient.getByLabel("Environment").selectOption("production");
    await thirdClient.getByLabel("Allowed Origins").fill("https://server.example.com");
    await thirdClient.getByLabel("Redirect URLs").fill("https://server.example.com/auth/callback");
    await expect(thirdClient.getByLabel("Create on Login")).toHaveValue("inherit");

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
        loginMethods: {
          passkey: true,
          email: true,
          sms: true,
          whatsapp: false,
          totp: true,
          siwe: false,
          siws: true,
          telegram: true,
          farcaster: true,
          oauth: {
            google: true,
            discord: true,
            github: true,
            twitter: true,
          },
        },
        embeddedWallets: { createOnLogin: "off" },
        globalWalletEnabled: true,
        globalWalletAllowedScopes: ["eth_accounts"],
      },
      {
        id: "web-inherit",
        name: "Inherited Web Updated",
        environment: "preview",
        enabled: true,
        allowedOrigins: ["https://inherit.example.com"],
        allowedRedirectUrls: ["https://inherit.example.com/auth/callback"],
        loginMethods: {
          passkey: true,
          email: true,
          sms: true,
          whatsapp: true,
          totp: true,
          siwe: true,
          siws: true,
          telegram: true,
          farcaster: true,
          oauth: {
            google: true,
            discord: true,
            github: true,
            twitter: true,
          },
        },
        globalWalletEnabled: false,
        globalWalletAllowedScopes: ["eth_accounts"],
      },
      {
        id: "mobile-dev",
        name: "Mobile Development",
        environment: "development",
        enabled: true,
        allowedOrigins: ["http://localhost:3000"],
        allowedRedirectUrls: ["http://localhost:3000/auth/callback"],
        loginMethods: {
          passkey: true,
          email: true,
          sms: true,
          whatsapp: true,
          totp: true,
          siwe: true,
          siws: true,
          telegram: true,
          farcaster: true,
          oauth: {
            google: true,
            discord: true,
            github: true,
            twitter: true,
          },
        },
        embeddedWallets: { createOnLogin: "all-users" },
        globalWalletEnabled: false,
        globalWalletAllowedScopes: ["eth_accounts", "personal_sign"],
      },
      {
        id: "server-prod",
        name: "Server Production",
        environment: "production",
        enabled: true,
        allowedOrigins: ["https://server.example.com"],
        allowedRedirectUrls: ["https://server.example.com/auth/callback"],
        loginMethods: {
          passkey: true,
          email: true,
          sms: true,
          whatsapp: true,
          totp: true,
          siwe: true,
          siws: true,
          telegram: true,
          farcaster: true,
          oauth: {
            google: true,
            discord: true,
            github: true,
            twitter: true,
          },
        },
        globalWalletEnabled: false,
        globalWalletAllowedScopes: ["eth_accounts", "personal_sign"],
      },
    ]);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-app-clients.png"),
      fullPage: true,
    });
  });
});

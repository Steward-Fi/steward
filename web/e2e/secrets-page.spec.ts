import { expect, type Page, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type SecretRecord = {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  version: number;
  routeCount: number;
  createdAt: string;
  updatedAt: string;
};

type RouteRecord = {
  id: string;
  agentId: string | null;
  secretId: string;
  hostPattern: string;
  pathPattern?: string;
  injectAs: "header" | "query" | "body";
  headerName?: string;
  queryParam?: string;
  bodyPath?: string;
  createdAt: string;
};

function isApiRequest(url: string): boolean {
  const parsed = new URL(url);
  return url.startsWith(API) || parsed.port === "3299";
}

function base64UrlJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

function testSessionToken(email: string): string {
  const now = Math.floor(Date.now() / 1000);
  return [
    base64UrlJson({ alg: "none", typ: "JWT" }),
    base64UrlJson({
      address: "0x0000000000000000000000000000000000000001",
      email,
      exp: now + 3600,
      iat: now,
      role: "owner",
      tenantId: "personal-test",
      tenantRole: "owner",
      userId: "secrets-admin",
    }),
    "signature",
  ].join(".");
}

async function seedDashboardSession(page: Page, email: string): Promise<void> {
  const token = testSessionToken(email);
  await page.addInitScript((sessionToken) => {
    window.sessionStorage.setItem("steward_session_token", sessionToken);
    window.sessionStorage.setItem("steward_refresh_token", "secrets-refresh-token");
  }, token);
}

test.describe("Dashboard secrets", () => {
  test.setTimeout(180_000);

  test("authenticated admins can create, route, remove, and rotate injected secrets", async ({
    page,
  }, testInfo) => {
    const email = `secrets-${Date.now()}@example.test`;
    const createdAt = "2026-06-04T15:00:00.000Z";
    let secretCreateBody: Record<string, unknown> | null = null;
    let routeCreateBody: Record<string, unknown> | null = null;
    let rotateBody: Record<string, unknown> | null = null;
    let secrets: SecretRecord[] = [
      {
        id: "sec_openai",
        tenantId: "personal-test",
        name: "OpenAI Production",
        description: "Existing production LLM key",
        version: 2,
        routeCount: 1,
        createdAt,
        updatedAt: createdAt,
      },
    ];
    let routes: RouteRecord[] = [
      {
        id: "route_openai",
        agentId: "agent-support",
        secretId: "sec_openai",
        hostPattern: "api.openai.com",
        pathPattern: "/v1/*",
        injectAs: "header",
        headerName: "Authorization",
        createdAt,
      },
    ];

    await seedDashboardSession(page, email);

    await page.route(
      (url) => isApiRequest(url.href) && url.pathname === "/secrets",
      async (route) => {
        const method = route.request().method();
        if (method === "GET") {
          await route.fulfill({ json: { ok: true, data: secrets } });
          return;
        }
        if (method === "POST") {
          secretCreateBody = route.request().postDataJSON() as Record<string, unknown>;
          const created: SecretRecord = {
            id: "sec_stripe_billing",
            tenantId: "personal-test",
            name: String(secretCreateBody.name),
            description: String(secretCreateBody.description ?? ""),
            version: 1,
            routeCount: 0,
            createdAt,
            updatedAt: createdAt,
          };
          secrets = [created, ...secrets];
          await route.fulfill({ json: { ok: true, data: created } });
          return;
        }
        await route.fulfill({ status: 405, json: { ok: false, error: "method not allowed" } });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href) && url.pathname === "/secrets/routes",
      async (route) => {
        const method = route.request().method();
        const url = new URL(route.request().url());
        if (method === "GET") {
          const secretId = url.searchParams.get("secretId");
          await route.fulfill({
            json: {
              ok: true,
              data: secretId ? routes.filter((item) => item.secretId === secretId) : routes,
            },
          });
          return;
        }
        if (method === "POST") {
          routeCreateBody = route.request().postDataJSON() as Record<string, unknown>;
          const created: RouteRecord = {
            id: "route_stripe_header",
            agentId: String(routeCreateBody.agentId),
            secretId: String(routeCreateBody.secretId),
            hostPattern: String(routeCreateBody.hostPattern),
            pathPattern: String(routeCreateBody.pathPattern ?? ""),
            injectAs: routeCreateBody.injectAs as RouteRecord["injectAs"],
            headerName: String(routeCreateBody.headerName ?? ""),
            queryParam: String(routeCreateBody.queryParam ?? ""),
            bodyPath: String(routeCreateBody.bodyPath ?? ""),
            createdAt,
          };
          routes = [...routes, created];
          secrets = secrets.map((secret) =>
            secret.id === created.secretId
              ? { ...secret, routeCount: secret.routeCount + 1, updatedAt: createdAt }
              : secret,
          );
          await route.fulfill({ json: { ok: true, data: created } });
          return;
        }
        await route.fulfill({ status: 405, json: { ok: false, error: "method not allowed" } });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href) && /^\/secrets\/[^/]+\/rotate$/.test(url.pathname),
      async (route) => {
        rotateBody = route.request().postDataJSON() as Record<string, unknown>;
        const secretId = new URL(route.request().url()).pathname.split("/")[2] ?? "";
        const updated = secrets.find((secret) => secret.id === secretId);
        if (!updated) {
          await route.fulfill({ status: 404, json: { ok: false, error: "not found" } });
          return;
        }
        const rotated = { ...updated, version: updated.version + 1, updatedAt: createdAt };
        secrets = secrets.map((secret) => (secret.id === secretId ? rotated : secret));
        await route.fulfill({ json: { ok: true, data: rotated } });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href) && /^\/secrets\/routes\/[^/]+$/.test(url.pathname),
      async (route) => {
        const routeId = new URL(route.request().url()).pathname.split("/").pop() ?? "";
        const removed = routes.find((item) => item.id === routeId);
        routes = routes.filter((item) => item.id !== routeId);
        if (removed) {
          secrets = secrets.map((secret) =>
            secret.id === removed.secretId
              ? { ...secret, routeCount: Math.max(0, secret.routeCount - 1), updatedAt: createdAt }
              : secret,
          );
        }
        await route.fulfill({ json: { ok: true, data: { deleted: true } } });
      },
    );

    await page.route(
      (url) => isApiRequest(url.href),
      async (route) => {
        const url = new URL(route.request().url());
        if (url.pathname === "/health") {
          await route.fulfill({ json: { ok: true, status: "ok" } });
          return;
        }
        if (url.pathname === "/tenants/config") {
          await route.fulfill({ json: { ok: true, data: {} } });
          return;
        }
        if (url.pathname === "/auth/providers") {
          await route.fulfill({
            json: {
              ok: true,
              email: true,
              passkey: true,
              oauth: { google: false, discord: false, github: false, twitter: false },
            },
          });
          return;
        }
        if (url.pathname === "/user/me/tenants") {
          await route.fulfill({
            json: {
              ok: true,
              data: [
                {
                  tenantId: "personal-test",
                  tenantName: "Personal Test",
                  role: "owner",
                },
              ],
            },
          });
          return;
        }
        if (url.pathname === "/user/me") {
          await route.fulfill({
            json: {
              ok: true,
              data: {
                user: { id: "secrets-admin", email },
                activeTenantId: "personal-test",
              },
            },
          });
          return;
        }
        await route.fallback();
      },
    );

    await expect(async () => {
      const response = await page.goto(`${WEB}/dashboard/secrets`, {
        waitUntil: "domcontentloaded",
      });
      expect(response?.status()).not.toBe(404);
      await expect(page.getByRole("heading", { name: "Secrets" })).toBeVisible();
    }).toPass({ timeout: 120_000 });
    await expect(page.getByText("OpenAI Production")).toBeVisible();
    await expect(page.getByText("Existing production LLM key")).toBeVisible();
    await expect(page.getByText("sk-live")).toHaveCount(0);

    await page.getByRole("button", { name: "New Secret" }).click();
    await page.getByLabel("Name").fill("Stripe Billing Key");
    await page.getByLabel("Description").fill("Stripe payment API key");
    await page.getByLabel("Secret Value").fill("sk-live-secret-value");
    await page.getByRole("button", { name: "Create", exact: true }).click();

    await expect(page.getByText("Secret created")).toBeVisible();
    await expect(page.getByText("Stripe Billing Key")).toBeVisible();
    expect(secretCreateBody).toMatchObject({
      description: "Stripe payment API key",
      name: "Stripe Billing Key",
      value: "sk-live-secret-value",
    });
    await expect(page.getByText("sk-live-secret-value")).toHaveCount(0);

    const stripeSecretButton = page.getByRole("button", { name: "Open secret Stripe Billing Key" });
    await expect(stripeSecretButton).toBeVisible();
    await stripeSecretButton.click();
    await expect(page.getByRole("heading", { name: "Stripe Billing Key" })).toBeVisible();
    await expect(page.getByText("Value encrypted at rest")).toBeVisible();
    await expect(page.getByText("No routes configured")).toBeVisible();

    await page.getByRole("button", { name: "+ Add Route" }).click();
    await page.getByLabel("Agent ID").fill("agent-billing");
    await page.getByLabel("Host Pattern").fill("api.stripe.com");
    await page.getByLabel("Path Pattern").fill("/v1/*");
    await page.getByLabel("Inject As").selectOption("header");
    await page.getByLabel("Header Name").fill("Authorization");
    await page.getByRole("button", { name: "Add Route", exact: true }).click();

    await expect(page.getByText("Route added")).toBeVisible();
    await expect(page.getByText("api.stripe.com")).toBeVisible();
    await expect(page.getByText("/v1/*")).toBeVisible();
    await expect(page.getByText("Authorization")).toBeVisible();
    expect(routeCreateBody).toMatchObject({
      agentId: "agent-billing",
      headerName: "Authorization",
      hostPattern: "api.stripe.com",
      injectAs: "header",
      pathPattern: "/v1/*",
      secretId: "sec_stripe_billing",
    });

    await page.getByRole("button", { name: "Remove" }).click();
    await expect(page.getByText("Route removed")).toBeVisible();
    await expect(page.getByText("No routes configured")).toBeVisible();

    await page.getByRole("button", { name: "Rotate Secret" }).click();
    await page.getByLabel("New Secret Value").fill("sk-live-rotated-secret-value");
    await page.getByRole("button", { name: "Confirm Rotation" }).click();

    await expect(page.getByText("Secret rotated to version 2")).toBeVisible();
    await expect(stripeSecretButton.getByText("v2")).toBeVisible();
    expect(rotateBody).toEqual({ value: "sk-live-rotated-secret-value" });
    await expect(page.getByText("sk-live-rotated-secret-value")).toHaveCount(0);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-secrets-rotated.png"),
      fullPage: true,
    });
  });
});

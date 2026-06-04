import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type OidcProvider = {
  id: string;
  enabled: boolean;
  issuer: string;
  audience: string[];
  jwksUri: string;
  clientId?: string;
  clientSecretEnv?: string;
  authorizationUrl?: string;
  tokenUrl?: string;
  scopes?: string[];
  allowedAlgs?: Array<"RS256" | "ES256">;
  allowJitProvisioning?: boolean;
};

test.describe("Dashboard OIDC provider settings", () => {
  test("authenticated users can configure enterprise OIDC auth-code fields", async ({
    page,
    request,
  }, testInfo) => {
    const email = `oidc-settings-${Date.now()}@example.test`;
    let providers: OidcProvider[] = [
      {
        id: "acme-sso",
        enabled: true,
        issuer: "https://idp.example.com",
        audience: ["steward-api"],
        jwksUri: "https://idp.example.com/.well-known/jwks.json",
        allowedAlgs: ["RS256"],
        allowJitProvisioning: true,
      },
    ];

    await page.route(/\/tenants\/[^/]+\/oidc-providers$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { providers } } });
        return;
      }
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as { providers?: OidcProvider[] };
        providers = body.providers ?? [];
        await route.fulfill({ json: { ok: true, data: { providers } } });
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
    const oidcForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "OIDC / JWT Login" }),
    });
    await expect(oidcForm).toBeVisible();

    await oidcForm.getByLabel("Client ID").fill("enterprise-client");
    await oidcForm.getByLabel("Client Secret Env Var").fill("ACME_SSO_CLIENT_SECRET");
    await oidcForm
      .getByLabel("Authorization URL")
      .fill("https://idp.example.com/oauth2/v1/authorize");
    await oidcForm.getByLabel("Token URL").fill("https://idp.example.com/oauth2/v1/token");
    await oidcForm.getByLabel("Scopes").fill("openid\nemail\nprofile");
    // The "Saved" confirmation is a 2s auto-hiding toast (a motion.span gated on
    // a state flag that resets via setTimeout). A single click+assert can lose
    // the window if the toast's whole lifetime elapses before the first poll
    // (observed flaky/deterministic on chromium). Retry the save+assert as a
    // unit — the PUT is mocked and idempotent, so re-clicking is safe, and a
    // genuine "never saves" bug still fails every cycle (toPass can't mask it).
    const saveProvidersButton = oidcForm.getByRole("button", { name: "Save Providers" });
    const savedToast = oidcForm.getByText("Saved");
    await expect(async () => {
      await saveProvidersButton.click();
      await expect(savedToast).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 15_000 });

    expect(providers[0]).toMatchObject({
      id: "acme-sso",
      clientId: "enterprise-client",
      clientSecretEnv: "ACME_SSO_CLIENT_SECRET",
      authorizationUrl: "https://idp.example.com/oauth2/v1/authorize",
      tokenUrl: "https://idp.example.com/oauth2/v1/token",
      scopes: ["openid", "email", "profile"],
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-oidc-providers.png"),
      fullPage: true,
    });
  });
});

import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

const CERT = `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgIUU3Rld2FyZC1TQU1MLUlkUC1maXh0dXJlLWNlcnQwDQYJ
KoZIhvcNAQELBQAwSDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN0ZXdhcmQgVGVz
dDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0dXJlMB4XDTI2MDEwMTAw
MDAwMFoXDTM2MDEwMTAwMDAwMFowSDELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN0
ZXdhcmQgVGVzdDElMCMGA1UEAwwcU3Rld2FyZCBTQU1MIElkUCBGaXh0dXJlMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AQIDAQAB
-----END CERTIFICATE-----`;

type SamlSsoConfig = {
  tenantId: string;
  enabled: boolean;
  status: "pending" | "active" | "error";
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertPems: string[];
  spEntityId: string;
  acsUrl: string;
  emailAttribute: string;
  groupsAttribute?: string;
  allowJitProvisioning: boolean;
  jitDefaultRole: "viewer";
  createdAt: string;
  updatedAt: string;
};

test.describe("Dashboard SAML SSO settings", () => {
  test("authenticated users can configure SAML IdP settings", async ({
    page,
    request,
  }, testInfo) => {
    const email = `saml-settings-${Date.now()}@example.test`;
    const tenantId = "e2e-tenant";
    const now = "2026-05-28T12:00:00.000Z";
    const serviceProvider = {
      spEntityId: "https://api.example.com/auth/saml/e2e-tenant/metadata",
      acsUrl: "https://api.example.com/auth/saml/e2e-tenant/acs",
      metadataUrl: "https://api.example.com/auth/saml/e2e-tenant/metadata",
    };
    let config: SamlSsoConfig | null = null;

    await page.route(/\/tenants\/[^/]+\/saml-sso$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { config, serviceProvider } } });
        return;
      }
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as {
          enabled?: boolean;
          idpEntityId: string;
          idpSsoUrl: string;
          idpCertPems: string[];
          emailAttribute?: string;
          groupsAttribute?: string;
          allowJitProvisioning?: boolean;
        };
        config = {
          tenantId,
          enabled: body.enabled === true,
          status: body.enabled === true ? "active" : "pending",
          idpEntityId: body.idpEntityId,
          idpSsoUrl: body.idpSsoUrl,
          idpCertPems: body.idpCertPems,
          spEntityId: serviceProvider.spEntityId,
          acsUrl: serviceProvider.acsUrl,
          emailAttribute: body.emailAttribute ?? "email",
          groupsAttribute: body.groupsAttribute,
          allowJitProvisioning: body.allowJitProvisioning === true,
          jitDefaultRole: "viewer",
          createdAt: now,
          updatedAt: now,
        };
        await route.fulfill({ json: { ok: true, data: { config } } });
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
    const samlForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "SAML SSO" }),
    });
    await expect(samlForm).toBeVisible();
    await expect(samlForm.getByText(serviceProvider.acsUrl)).toBeVisible();

    await samlForm.getByLabel("Enable SAML SSO").check();
    await samlForm.getByLabel("IdP Entity ID").fill("https://idp.example.com/saml");
    await samlForm.getByLabel("IdP SSO URL").fill("https://idp.example.com/sso");
    await samlForm.getByLabel("Email Attribute").fill("email");
    await samlForm.getByLabel("Groups Attribute").fill("groups");
    await samlForm.getByLabel("IdP Certificate PEMs").fill(CERT);
    await samlForm.getByLabel("Auto-create SSO users as Viewer").check();
    await samlForm.getByRole("button", { name: "Save SAML" }).click();
    await expect(samlForm.getByText("Saved")).toBeVisible();

    expect(config).toMatchObject({
      enabled: true,
      idpEntityId: "https://idp.example.com/saml",
      idpSsoUrl: "https://idp.example.com/sso",
      idpCertPems: [CERT],
      emailAttribute: "email",
      groupsAttribute: "groups",
      allowJitProvisioning: true,
      jitDefaultRole: "viewer",
    });

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-saml-sso.png"),
      fullPage: true,
    });
  });
});

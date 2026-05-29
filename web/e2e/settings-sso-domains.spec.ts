import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type TenantSsoDomain = {
  id: string;
  tenantId: string;
  domain: string;
  verificationToken: string;
  status: "pending" | "verified";
  ssoRequired: boolean;
  verifiedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

test.describe("Dashboard SSO domain settings", () => {
  test("authenticated users can create, verify, and delete SSO domains", async ({
    page,
    request,
  }, testInfo) => {
    const email = `sso-domains-${Date.now()}@example.test`;
    const tenantId = "e2e-tenant";
    const now = "2026-05-28T12:00:00.000Z";
    let domains: TenantSsoDomain[] = [
      {
        id: "sso-existing",
        tenantId,
        domain: "existing.example",
        verificationToken: "steward-sso-existing",
        status: "pending",
        ssoRequired: true,
        verifiedAt: null,
        createdAt: now,
        updatedAt: now,
      },
    ];

    await page.route(/\/tenants\/[^/]+\/sso-domains(?:\/[^/]+(?:\/verify)?)?$/, async (route) => {
      const routeRequest = route.request();
      const url = new URL(routeRequest.url());
      const parts = url.pathname.split("/").filter(Boolean);
      const domainParam = parts[3] ? decodeURIComponent(parts[3]) : null;

      if (routeRequest.method() === "GET") {
        await route.fulfill({ json: { ok: true, data: { domains } } });
        return;
      }
      if (routeRequest.method() === "POST" && !url.pathname.endsWith("/verify")) {
        const body = routeRequest.postDataJSON() as { domain: string; ssoRequired?: boolean };
        const nextDomain: TenantSsoDomain = {
          id: `sso-${body.domain}`,
          tenantId,
          domain: body.domain,
          verificationToken: "steward-sso-created",
          status: "pending",
          ssoRequired: body.ssoRequired === true,
          verifiedAt: null,
          createdAt: now,
          updatedAt: now,
        };
        domains = [nextDomain, ...domains.filter((item) => item.domain !== body.domain)];
        await route.fulfill({ status: 201, json: { ok: true, data: { domain: nextDomain } } });
        return;
      }
      if (routeRequest.method() === "POST" && domainParam && url.pathname.endsWith("/verify")) {
        const nextDomain = domains.find((item) => item.domain === domainParam);
        if (!nextDomain) {
          await route.fulfill({ status: 404, json: { ok: false, error: "SSO domain not found" } });
          return;
        }
        nextDomain.status = "verified";
        nextDomain.verifiedAt = now;
        nextDomain.updatedAt = now;
        await route.fulfill({ json: { ok: true, data: { domain: nextDomain } } });
        return;
      }
      if (routeRequest.method() === "DELETE" && domainParam) {
        domains = domains.filter((item) => item.domain !== domainParam);
        await route.fulfill({ json: { ok: true, data: { deleted: true } } });
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
    const ssoDomainsForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "SSO Domains" }),
    });
    await expect(ssoDomainsForm).toBeVisible();
    await expect(
      ssoDomainsForm.getByRole("cell", { name: "existing.example", exact: true }),
    ).toBeVisible();
    await expect(ssoDomainsForm.getByText("_steward-sso.existing.example")).toBeVisible();

    await ssoDomainsForm.getByLabel("Domain").fill("corp.example");
    await ssoDomainsForm.getByLabel("Require SSO").check();
    await ssoDomainsForm.getByRole("button", { name: "Add Domain" }).click();
    await expect(
      ssoDomainsForm.getByRole("cell", { name: "corp.example", exact: true }),
    ).toBeVisible();
    await expect(ssoDomainsForm.getByText("steward-sso-created")).toBeVisible();

    await ssoDomainsForm
      .getByRole("row", { name: /corp\.example/ })
      .getByRole("button", { name: "Verify" })
      .click();
    await expect(ssoDomainsForm.getByRole("row", { name: /corp\.example/ })).toContainText(
      "Verified",
    );

    await ssoDomainsForm
      .getByRole("row", { name: /corp\.example/ })
      .getByRole("button", { name: "Delete" })
      .click();
    await expect(
      ssoDomainsForm.getByRole("cell", { name: "corp.example", exact: true }),
    ).toBeHidden();

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-sso-domains.png"),
      fullPage: true,
    });
  });
});

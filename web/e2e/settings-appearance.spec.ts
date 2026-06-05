import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type TenantTheme = {
  primaryColor: string;
  accentColor: string;
  backgroundColor: string;
  surfaceColor: string;
  textColor: string;
  mutedColor: string;
  successColor: string;
  errorColor: string;
  warningColor: string;
  borderRadius: number;
  fontFamily: string;
  colorScheme: "light" | "dark" | "system";
  logoUrl: string;
  faviconUrl: string;
};

test.describe("Dashboard appearance settings", () => {
  test("authenticated users can update and preview tenant theme tokens", async ({
    page,
    request,
  }, testInfo) => {
    const email = `appearance-${Date.now()}@example.test`;
    let theme: TenantTheme = {
      primaryColor: "#D4A054",
      accentColor: "#A78BFA",
      backgroundColor: "#0F0F0F",
      surfaceColor: "#1A1A2E",
      textColor: "#FAFAFA",
      mutedColor: "#6B7280",
      successColor: "#10B981",
      errorColor: "#EF4444",
      warningColor: "#F59E0B",
      borderRadius: 8,
      fontFamily: "Inter, system-ui, sans-serif",
      colorScheme: "dark",
      logoUrl: "",
      faviconUrl: "",
    };

    await page.route(/\/tenants\/[^/]+\/config$/, async (route) => {
      const routeRequest = route.request();
      if (routeRequest.method() === "GET") {
        await route.fulfill({
          json: {
            ok: true,
            data: {
              allowedOrigins: [],
              allowedRedirectUrls: [],
              appClients: [],
              theme,
            },
          },
        });
        return;
      }
      if (routeRequest.method() === "PUT") {
        const body = routeRequest.postDataJSON() as { theme?: TenantTheme };
        if (body.theme) theme = body.theme;
        await route.fulfill({
          json: {
            ok: true,
            data: {
              allowedOrigins: [],
              allowedRedirectUrls: [],
              appClients: [],
              theme,
            },
          },
        });
        return;
      }
      await route.fallback();
    });
    await page.route(/\/tenants\/[^/]+\/idempotency-metrics$/, async (route) => {
      await route.fulfill({
        json: {
          ok: true,
          data: {
            tenantId: "personal-test",
            generatedAt: new Date().toISOString(),
            windowStartedAt: new Date().toISOString(),
            lastSeenAt: new Date().toISOString(),
            ttlMs: 86_400_000,
            counters: {
              observed: 3,
              reserved: 1,
              completed: 1,
              replayed: 1,
              conflicts: 1,
              inFlightConflicts: 0,
              suppressedAuthResponses: 0,
              invalidKeys: 0,
              storeErrors: 0,
              skippedUnsafeContext: 0,
              releasedOnError: 0,
            },
          },
        },
      });
    });
    await page.route(/\/tenants\/[^/]+\/idempotency-metrics\/export$/, async (route) => {
      expect(route.request().method()).toBe("GET");
      await route.fulfill({
        body:
          "tenant_id,generated_at,window_started_at,last_seen_at,ttl_ms,observed,reserved,completed,replayed,conflicts,in_flight_conflicts,suppressed_auth_responses,invalid_keys,store_errors,skipped_unsafe_context,released_on_error\n" +
          '"personal-test","2026-06-04T00:00:00.000Z","2026-06-04T00:00:00.000Z","2026-06-04T00:00:01.000Z","86400000","3","1","1","1","1","0","0","0","0","0","0"\n',
        headers: {
          "Content-Disposition": 'attachment; filename="personal-test-idempotency-metrics.csv"',
          "Content-Type": "text/csv; charset=utf-8",
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
    await expect(page.getByRole("link", { name: "Settings" })).toBeVisible({ timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/settings`);
    const appearanceForm = page.locator("form").filter({
      has: page.getByRole("heading", { name: "Appearance" }),
    });
    await expect(appearanceForm).toBeVisible();

    await appearanceForm.getByLabel("Primary color", { exact: true }).fill("#3366FF");
    await appearanceForm.getByLabel("Accent color", { exact: true }).fill("#22C55E");
    await appearanceForm.getByLabel("Background color", { exact: true }).fill("#101828");
    await appearanceForm.getByLabel("Surface color", { exact: true }).fill("#172033");
    await appearanceForm.getByLabel("Text color", { exact: true }).fill("#FFFFFF");
    await appearanceForm.getByLabel("Muted color", { exact: true }).fill("#94A3B8");
    await appearanceForm.getByLabel("Border Radius").fill("10");
    await appearanceForm.getByLabel("Font Family").fill("Inter, system-ui, sans-serif");
    await appearanceForm.getByLabel("Color Scheme").selectOption("system");
    await appearanceForm.getByLabel("Logo URL").fill("https://assets.example.com/logo.png");
    await appearanceForm.getByLabel("Favicon URL").fill("https://assets.example.com/favicon.ico");

    const preview = appearanceForm.getByTestId("appearance-preview");
    await expect(preview).toHaveCSS("background-color", "rgb(16, 24, 40)");
    await expect(preview.locator("img")).toHaveAttribute(
      "src",
      "https://assets.example.com/logo.png",
    );

    await appearanceForm.getByRole("button", { name: "Save Appearance" }).click();
    await expect(appearanceForm.getByText("Saved")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Idempotency Metrics" })).toBeVisible();
    await expect(page.getByText("Replayed", { exact: true })).toBeVisible();
    const idempotencyDownload = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV" }).click();
    const download = await idempotencyDownload;
    expect(download.suggestedFilename()).toMatch(/idempotency-metrics\.csv$/);

    expect(theme.primaryColor).toBe("#3366FF");
    expect(theme.backgroundColor).toBe("#101828");
    expect(theme.borderRadius).toBe(10);
    expect(theme.colorScheme).toBe("system");
    expect(theme.logoUrl).toBe("https://assets.example.com/logo.png");
    expect(theme.faviconUrl).toBe("https://assets.example.com/favicon.ico");

    await page.screenshot({
      path: testInfo.outputPath("dashboard-settings-appearance.png"),
      fullPage: true,
    });
  });
});

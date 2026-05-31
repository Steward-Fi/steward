import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

test.describe("Email magic-link — mock inbox round-trip", () => {
  test("send → read code from MockEmailProvider inbox → redeem", async ({ request }) => {
    const email = `e2e-${Date.now()}@example.test`;

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);
    const sent = (await sendRes.json()) as { ok: boolean; expiresAt: string };
    expect(sent.ok).toBe(true);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string; magicLink: string };
    expect(inbox.token).toMatch(/^[a-f0-9]{64}$/);
    expect(inbox.magicLink).toContain("token=");

    const verifyRes = await request.post(`${API}/auth/email/verify`, {
      data: { token: inbox.token, email },
    });
    expect(verifyRes.status()).toBe(200);
    const verify = (await verifyRes.json()) as { ok: boolean; token: string };
    expect(verify.ok).toBe(true);
    expect(verify.token.split(".").length).toBe(3);
  });

  test("magic-link tokens are single-use", async ({ request }) => {
    const email = `e2e-once-${Date.now()}@example.test`;
    await request.post(`${API}/auth/email/send`, { data: { email } });
    const { token } = (await (
      await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`)
    ).json()) as { token: string };

    const first = await request.post(`${API}/auth/email/verify`, { data: { token, email } });
    expect(first.status()).toBe(200);
    const second = await request.post(`${API}/auth/email/verify`, { data: { token, email } });
    expect(second.status()).toBeGreaterThanOrEqual(400);
  });

  test("browser flow: click 'email me a link' on the login page sends a message", async ({
    page,
  }) => {
    await page.goto(`${WEB}/login`);

    const emailInput = page.getByLabel("email");
    await emailInput.waitFor();
    const email = `browser-${Date.now()}@example.test`;
    await emailInput.fill(email);
    await page.getByRole("button", { name: /email me a link/i }).click();

    await page.getByText(/link sent to/i).waitFor();

    // Inbox should now hold the magic link addressed to this user.
    const inbox = await page.request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inbox.status()).toBe(200);
    const body = (await inbox.json()) as { token: string };
    expect(body.token).toMatch(/^[a-f0-9]{64}$/);
  });

  test("browser callback redeems, stores only in sessionStorage, scrubs URL, and redirects", async ({
    page,
  }) => {
    const email = `callback-${Date.now()}@example.test`;
    await page.request.post(`${API}/auth/email/send`, { data: { email } });
    const { token } = (await (
      await page.request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`)
    ).json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard$/, { timeout: 30_000 });

    const storageState = await page.evaluate(() => ({
      href: window.location.href,
      sessionToken: window.sessionStorage.getItem("steward_session_token"),
      refreshToken: window.sessionStorage.getItem("steward_refresh_token"),
      localToken: window.localStorage.getItem("steward_session_token"),
      localRefreshToken: window.localStorage.getItem("steward_refresh_token"),
    }));

    expect(storageState.href).not.toContain("token=");
    expect(storageState.href).not.toContain("email=");
    expect(storageState.sessionToken?.split(".")).toHaveLength(3);
    expect(storageState.refreshToken).toBeTruthy();
    expect(storageState.localToken).toBeNull();
    expect(storageState.localRefreshToken).toBeNull();
  });

  test("stale localStorage auth tokens are ignored by the dashboard guard", async ({ page }) => {
    await page.goto(`${WEB}/login`);
    await page.evaluate(() => {
      window.localStorage.setItem("steward_session_token", "stale.local.token");
      window.localStorage.setItem("steward_refresh_token", "stale-local-refresh");
      window.sessionStorage.removeItem("steward_session_token");
      window.sessionStorage.removeItem("steward_refresh_token");
    });

    await page.goto(`${WEB}/dashboard`);
    await page.waitForURL(/\/login$/, { timeout: 30_000 });

    const storageState = await page.evaluate(() => ({
      localToken: window.localStorage.getItem("steward_session_token"),
      sessionToken: window.sessionStorage.getItem("steward_session_token"),
    }));
    expect(storageState.localToken).toBe("stale.local.token");
    expect(storageState.sessionToken).toBeNull();
  });

  test("invalid callback URL shows an error and does not create storage tokens", async ({
    page,
  }) => {
    await page.goto(`${WEB}/auth/callback/email?token=not-a-real-token`);

    await expect(page.getByText(/missing token or email/i)).toBeVisible();
    const storageState = await page.evaluate(() => ({
      sessionToken: window.sessionStorage.getItem("steward_session_token"),
      refreshToken: window.sessionStorage.getItem("steward_refresh_token"),
      localToken: window.localStorage.getItem("steward_session_token"),
      localRefreshToken: window.localStorage.getItem("steward_refresh_token"),
    }));
    expect(storageState.sessionToken).toBeNull();
    expect(storageState.refreshToken).toBeNull();
    expect(storageState.localToken).toBeNull();
    expect(storageState.localRefreshToken).toBeNull();
  });
});

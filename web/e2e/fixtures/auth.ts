import { type APIRequestContext, expect, type Page } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

export async function loginWithMagicLink(
  page: Page,
  request: APIRequestContext,
  email: string,
): Promise<void> {
  const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
  expect(sendRes.status()).toBe(200);

  const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
  expect(inboxRes.status()).toBe(200);
  const inbox = (await inboxRes.json()) as { token: string };

  await page
    .goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    )
    .catch((error) => {
      if (!String(error).includes("ERR_ABORTED")) throw error;
    });

  await expect.poll(() => page.url(), { timeout: 30_000 }).toMatch(/\/dashboard/);
  await expect
    .poll(
      () =>
        page.evaluate(() => ({
          sessionToken: window.sessionStorage.getItem("steward_session_token"),
          refreshToken: window.sessionStorage.getItem("steward_refresh_token"),
        })),
      { timeout: 30_000 },
    )
    .toMatchObject({
      sessionToken: expect.stringMatching(/^[^.]+\.[^.]+\.[^.]+$/),
      refreshToken: expect.any(String),
    });
}

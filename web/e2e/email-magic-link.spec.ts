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
});

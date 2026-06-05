import { expect, type Page, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";

async function mountConnectOrCreateFixture(
  page: Page,
  {
    authenticated = true,
    hostedAuth = false,
  }: { authenticated?: boolean; hostedAuth?: boolean } = {},
) {
  await page.setContent(`
    <!doctype html>
    <html>
      <body>
        <div data-testid="stwd-connect-or-create-wallet">
          <section aria-label="External wallets">
            <button type="button">Ethereum</button>
            <button type="button">Solana</button>
          </section>
          <button
            type="button"
            data-testid="stwd-connect-or-create-embedded"
            data-stwd-auth-state="${authenticated ? "authenticated" : "signed-out"}"
            ${authenticated || hostedAuth ? "" : "disabled"}
          >
            ${authenticated ? "create embedded wallet" : hostedAuth ? "open hosted login" : "sign in to create wallet"}
          </button>
          <div data-testid="stwd-connect-or-create-embedded-status"></div>
          <div data-testid="stwd-wallet-error" hidden></div>
          <dialog data-testid="stwd-hosted-auth-modal">sign in before creating an embedded wallet</dialog>
        </div>
        <script>
          const button = document.querySelector('[data-testid="stwd-connect-or-create-embedded"]');
          const status = document.querySelector('[data-testid="stwd-connect-or-create-embedded-status"]');
          const error = document.querySelector('[data-testid="stwd-wallet-error"]');
          const hostedAuthEnabled = ${JSON.stringify(hostedAuth)};
          const authenticated = ${JSON.stringify(authenticated)};
          const hostedModal = document.querySelector('[data-testid="stwd-hosted-auth-modal"]');
          let walletReady = false;
          button.addEventListener('click', async () => {
            if (button.disabled || walletReady) return;
            if (!authenticated && hostedAuthEnabled) {
              hostedModal.showModal();
              return;
            }
            button.disabled = true;
            error.hidden = true;
            status.textContent = "";
            try {
              const response = await fetch('${API}/user/me/wallet', {
                method: 'POST',
                headers: {
                  'Accept': 'application/json',
                  'Authorization': 'Bearer browser-session-token',
                  'Content-Type': 'application/json'
                },
                body: JSON.stringify({})
              });
              const payload = await response.json();
              if (!response.ok || payload.ok === false) {
                throw new Error(payload.error || 'failed to create wallet');
              }
              walletReady = true;
              button.textContent = "wallet ready";
              button.disabled = true;
              status.dataset.stwdWalletState = payload.data.claimed ? "connected" : "created";
              status.innerHTML = '<span>wallet created</span><code>' + payload.data.walletAddress + '</code>';
            } catch (err) {
              error.textContent = err instanceof Error ? err.message : String(err);
              error.hidden = false;
            } finally {
              if (walletReady) return;
              button.disabled = false;
            }
          });
        </script>
      </body>
    </html>
  `);
}

test.describe("Connect-or-create wallet browser contract", () => {
  test("signed-out users cannot trigger embedded wallet creation", async ({ page }) => {
    await mountConnectOrCreateFixture(page, { authenticated: false });

    await expect(page.getByTestId("stwd-connect-or-create-wallet")).toBeVisible();
    await expect(page.getByRole("button", { name: "sign in to create wallet" })).toBeDisabled();
  });

  test("signed-out hosted modal callback opens auth without wallet provisioning", async ({
    page,
  }) => {
    const walletRequests: string[] = [];
    await page.route(`${API}/user/me/wallet`, async (route) => {
      walletRequests.push(route.request().url());
      await route.abort();
    });
    await mountConnectOrCreateFixture(page, { authenticated: false, hostedAuth: true });

    await page.getByTestId("stwd-connect-or-create-embedded").click();

    await expect(page.getByTestId("stwd-hosted-auth-modal")).toBeVisible();
    await expect(page.getByTestId("stwd-connect-or-create-embedded-status")).toHaveText("");
    expect(walletRequests).toEqual([]);
  });

  test("authenticated fallback provisions only through the user-session wallet endpoint", async ({
    page,
  }) => {
    const walletRequests: string[] = [];
    const platformRequests: string[] = [];
    await page.route("**/*", async (route) => {
      const request = route.request();
      if (request.method() === "OPTIONS") {
        await route.fulfill({
          status: 204,
          headers: {
            "Access-Control-Allow-Headers": "accept, authorization, content-type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Origin": "*",
          },
        });
        return;
      }
      if (request.method() === "POST" && request.url() === `${API}/user/me/wallet`) {
        walletRequests.push(request.url());
        await route.fulfill({
          headers: { "Access-Control-Allow-Origin": "*" },
          json: {
            ok: true,
            data: {
              agentId: "agent_user_browser",
              walletAddress: "0xabc0000000000000000000000000000000000def",
            },
          },
        });
        return;
      }
      if (request.url().includes("connect-or-create")) {
        platformRequests.push(request.url());
      }
      await route.continue();
    });
    await mountConnectOrCreateFixture(page);

    await page.getByTestId("stwd-connect-or-create-embedded").click();

    await expect(page.getByTestId("stwd-connect-or-create-embedded-status")).toContainText(
      "wallet created",
    );
    await expect(page.getByTestId("stwd-connect-or-create-embedded-status")).toContainText(
      "0xabc0000000000000000000000000000000000def",
    );
    await expect(page.getByTestId("stwd-connect-or-create-embedded")).toBeDisabled();
    await expect(page.getByTestId("stwd-connect-or-create-embedded")).toHaveText("wallet ready");
    expect(walletRequests).toEqual([`${API}/user/me/wallet`]);
    expect(platformRequests).toEqual([]);
  });

  test("embedded wallet provisioning failures stay inline", async ({ page }) => {
    await page.route(`${API}/user/me/wallet`, async (route) => {
      if (route.request().method() === "OPTIONS") {
        await route.fulfill({
          status: 204,
          headers: {
            "Access-Control-Allow-Headers": "accept, authorization, content-type",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Origin": "*",
          },
        });
        return;
      }
      await route.fulfill({
        status: 409,
        headers: { "Access-Control-Allow-Origin": "*" },
        json: { ok: false, error: "wallet already exists" },
      });
    });
    await mountConnectOrCreateFixture(page);

    await page.getByTestId("stwd-connect-or-create-embedded").click();

    await expect(page.getByTestId("stwd-wallet-error")).toHaveText("wallet already exists");
    await expect(page.getByTestId("stwd-connect-or-create-embedded")).toBeEnabled();
  });
});

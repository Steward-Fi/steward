import { expect, test } from "@playwright/test";

const API = process.env.E2E_API_URL ?? "http://localhost:3299";
const WEB = process.env.E2E_WEB_URL ?? "http://localhost:3499";

type ConditionSet = {
  id: string;
  tenantId: string;
  name: string;
  description: string | null;
  ownerId: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

type ConditionSetItem = {
  id: string;
  conditionSetId: string;
  tenantId: string;
  value: string;
  label: string | null;
  metadata: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
};

test.describe("Dashboard condition sets", () => {
  test("authenticated admins can create and edit condition-set items", async ({
    page,
    request,
  }, testInfo) => {
    const email = `condition-sets-${Date.now()}@example.test`;
    let sets: ConditionSet[] = [
      {
        id: "cs_existing",
        tenantId: "personal-test",
        name: "Approved recipients",
        description: "Existing transfer allowlist",
        ownerId: "dashboard",
        metadata: {},
        createdAt: "2026-05-29T12:00:00.000Z",
        updatedAt: "2026-05-29T12:00:00.000Z",
      },
    ];
    let itemsBySet: Record<string, ConditionSetItem[]> = {
      cs_existing: [
        {
          id: "csi_existing_1",
          conditionSetId: "cs_existing",
          tenantId: "personal-test",
          value: "0x1111111111111111111111111111111111111111",
          label: null,
          metadata: {},
          createdAt: "2026-05-29T12:00:00.000Z",
          updatedAt: "2026-05-29T12:00:00.000Z",
        },
      ],
    };

    await page.route(
      (url) => url.href.startsWith(API) && /\/policies(?:\/[^/]+)?$/.test(url.pathname),
      async (route) => {
        await route.fulfill({ json: { ok: true, data: [] } });
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && /\/agents$/.test(url.pathname),
      async (route) => {
        await route.fulfill({ json: { ok: true, data: [] } });
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && /\/condition-sets$/.test(url.pathname),
      async (route) => {
        const routeRequest = route.request();
        if (routeRequest.method() === "GET") {
          await route.fulfill({
            json: { ok: true, data: { conditionSets: sets, limit: 100, offset: 0 } },
          });
          return;
        }
        if (routeRequest.method() === "POST") {
          const body = routeRequest.postDataJSON() as { name: string; description?: string };
          const created: ConditionSet = {
            id: "cs_created",
            tenantId: "personal-test",
            name: body.name,
            description: body.description ?? null,
            ownerId: "dashboard",
            metadata: {},
            createdAt: "2026-05-29T12:05:00.000Z",
            updatedAt: "2026-05-29T12:05:00.000Z",
          };
          sets = [created, ...sets];
          itemsBySet = { ...itemsBySet, [created.id]: [] };
          await route.fulfill({ json: { ok: true, data: created } });
          return;
        }
        await route.fallback();
      },
    );
    await page.route(
      (url) => url.href.startsWith(API) && /\/condition-sets\/[^/]+\/items$/.test(url.pathname),
      async (route) => {
        const routeRequest = route.request();
        const setId = new URL(routeRequest.url()).pathname.split("/").at(-2) ?? "";
        if (routeRequest.method() === "GET") {
          await route.fulfill({ json: { ok: true, data: itemsBySet[setId] ?? [] } });
          return;
        }
        if (routeRequest.method() === "PUT") {
          const body = routeRequest.postDataJSON() as { items?: Array<{ value: string }> };
          const nextItems = (body.items ?? []).map((item, index) => ({
            id: `csi_${setId}_${index}`,
            conditionSetId: setId,
            tenantId: "personal-test",
            value: item.value,
            label: null,
            metadata: {},
            createdAt: "2026-05-29T12:06:00.000Z",
            updatedAt: "2026-05-29T12:06:00.000Z",
          }));
          itemsBySet = { ...itemsBySet, [setId]: nextItems };
          await route.fulfill({ json: { ok: true, data: nextItems } });
          return;
        }
        await route.fallback();
      },
    );

    const sendRes = await request.post(`${API}/auth/email/send`, { data: { email } });
    expect(sendRes.status()).toBe(200);

    const inboxRes = await request.get(`${API}/auth/test/inbox/${encodeURIComponent(email)}`);
    expect(inboxRes.status()).toBe(200);
    const inbox = (await inboxRes.json()) as { token: string };

    await page.goto(
      `${WEB}/auth/callback/email?token=${encodeURIComponent(inbox.token)}&email=${encodeURIComponent(email)}`,
    );
    await page.waitForURL(/\/dashboard/, { timeout: 30_000 });

    await page.goto(`${WEB}/dashboard/policies`);
    const section = page.locator("section").filter({
      has: page.getByRole("heading", { name: "Condition Sets" }),
    });
    await expect(section).toBeVisible();
    await expect(section.getByText("Approved recipients")).toBeVisible();
    await expect(section.getByText("0x1111111111111111111111111111111111111111")).toBeVisible();

    const nameInput = section.getByPlaceholder("Approved recipients");
    const descriptionInput = section.getByPlaceholder("Production transfer allowlist");
    await nameInput.fill("Blocked contracts");
    await expect(nameInput).toHaveValue("Blocked contracts");
    await descriptionInput.fill("Contracts blocked from production signing");
    await section
      .getByLabel("Items")
      .fill(
        "0x2222222222222222222222222222222222222222\n0x3333333333333333333333333333333333333333",
      );
    await section.getByRole("button", { name: "Create Set" }).click();
    await expect(page.getByText("Condition set created")).toBeVisible();

    expect(sets[0]).toMatchObject({ id: "cs_created", name: "Blocked contracts" });
    expect(itemsBySet.cs_created.map((item) => item.value)).toEqual([
      "0x2222222222222222222222222222222222222222",
      "0x3333333333333333333333333333333333333333",
    ]);

    await section.getByLabel("Items").fill("0x4444444444444444444444444444444444444444");
    await section.getByRole("button", { name: "Save Items" }).click();
    await expect(page.getByText("Condition set items saved")).toBeVisible();
    expect(itemsBySet.cs_created.map((item) => item.value)).toEqual([
      "0x4444444444444444444444444444444444444444",
    ]);

    await page.screenshot({
      path: testInfo.outputPath("dashboard-policies-condition-sets.png"),
      fullPage: true,
    });
  });
});

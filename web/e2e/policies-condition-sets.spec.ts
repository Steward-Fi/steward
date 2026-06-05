import { expect, test } from "@playwright/test";
import { loginWithMagicLink } from "./fixtures/auth";

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

function makeItem(
  conditionSetId: string,
  id: string,
  value: string,
  label: string | null = null,
): ConditionSetItem {
  return {
    id,
    conditionSetId,
    tenantId: "personal-test",
    value,
    label,
    metadata: {},
    createdAt: "2026-05-29T12:00:00.000Z",
    updatedAt: "2026-05-29T12:00:00.000Z",
  };
}

test.describe("Dashboard condition sets", () => {
  test("authenticated admins can manage paginated condition-set items", async ({
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
        makeItem("cs_existing", "csi_existing_1", "0x1111111111111111111111111111111111111111"),
        makeItem("cs_existing", "csi_existing_2", "0x2222222222222222222222222222222222222222"),
        makeItem("cs_existing", "csi_existing_3", "0x3333333333333333333333333333333333333333"),
        makeItem("cs_existing", "csi_existing_4", "0x4444444444444444444444444444444444444444"),
        makeItem("cs_existing", "csi_existing_5", "0x5555555555555555555555555555555555555555"),
        makeItem("cs_existing", "csi_existing_6", "0x6666666666666666666666666666666666666666"),
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
          const url = new URL(routeRequest.url());
          const limit = Number(url.searchParams.get("limit") ?? "200");
          const offset = Number(url.searchParams.get("offset") ?? "0");
          await route.fulfill({
            json: {
              ok: true,
              data: {
                items: (itemsBySet[setId] ?? []).slice(offset, offset + limit),
                limit,
                offset,
              },
            },
          });
          return;
        }
        if (routeRequest.method() === "POST") {
          const body = routeRequest.postDataJSON() as { value: string; label?: string };
          const existing = (itemsBySet[setId] ?? []).find((item) => item.value === body.value);
          const nextItem =
            existing ??
            makeItem(setId, `csi_${setId}_${Date.now()}`, body.value, body.label ?? null);
          nextItem.label = body.label ?? null;
          itemsBySet = {
            ...itemsBySet,
            [setId]: [
              nextItem,
              ...(itemsBySet[setId] ?? []).filter((item) => item.id !== nextItem.id),
            ],
          };
          await route.fulfill({ json: { ok: true, data: nextItem } });
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
    await page.route(
      (url) =>
        url.href.startsWith(API) && /\/condition-sets\/[^/]+\/items\/[^/]+$/.test(url.pathname),
      async (route) => {
        const routeRequest = route.request();
        const parts = new URL(routeRequest.url()).pathname.split("/");
        const setId = parts.at(-3) ?? "";
        const itemId = parts.at(-1) ?? "";
        const item = (itemsBySet[setId] ?? []).find((candidate) => candidate.id === itemId);
        if (!item) {
          await route.fulfill({ status: 404, json: { ok: false, error: "Not found" } });
          return;
        }
        if (routeRequest.method() === "GET") {
          await route.fulfill({ json: { ok: true, data: item } });
          return;
        }
        if (routeRequest.method() === "PATCH") {
          const body = routeRequest.postDataJSON() as { value?: string; label?: string | null };
          const updated: ConditionSetItem = {
            ...item,
            value: body.value ?? item.value,
            label: body.label ?? null,
            updatedAt: "2026-05-29T12:10:00.000Z",
          };
          itemsBySet = {
            ...itemsBySet,
            [setId]: (itemsBySet[setId] ?? []).map((candidate) =>
              candidate.id === itemId ? updated : candidate,
            ),
          };
          await route.fulfill({ json: { ok: true, data: updated } });
          return;
        }
        if (routeRequest.method() === "DELETE") {
          itemsBySet = {
            ...itemsBySet,
            [setId]: (itemsBySet[setId] ?? []).filter((candidate) => candidate.id !== itemId),
          };
          await route.fulfill({ json: { ok: true } });
          return;
        }
        await route.fallback();
      },
    );

    await loginWithMagicLink(page, request, email);

    await page.goto(`${WEB}/dashboard/policies`);
    const section = page.locator("section").filter({
      has: page.getByRole("heading", { name: "Condition Sets" }),
    });
    await expect(section).toBeVisible();
    await expect(section.getByText("Approved recipients")).toBeVisible();
    await expect(section.getByTestId("condition-set-item-csi_existing_1")).toContainText(
      "0x1111111111111111111111111111111111111111",
    );
    await expect(section.getByTestId("condition-set-item-csi_existing_6")).toHaveCount(0);
    await section.getByRole("button", { name: "Next" }).click();
    await expect(section.getByText("Offset 5")).toBeVisible();
    await expect(section.getByTestId("condition-set-item-csi_existing_6")).toContainText(
      "0x6666666666666666666666666666666666666666",
    );
    await section.getByRole("button", { name: "Previous" }).click();
    await expect(section.getByText("Offset 0")).toBeVisible();

    const nameInput = section.getByPlaceholder("Approved recipients");
    const descriptionInput = section.getByPlaceholder("Production transfer allowlist");
    await nameInput.fill("Blocked contracts");
    await expect(nameInput).toHaveValue("Blocked contracts");
    await descriptionInput.fill("Contracts blocked from production signing");
    await section
      .getByLabel("Bulk replace values")
      .fill(
        "0x7777777777777777777777777777777777777777\n0x8888888888888888888888888888888888888888",
      );
    await section.getByRole("button", { name: "Create Set" }).click();
    await expect(page.getByText("Condition set created")).toBeVisible();

    expect(sets[0]).toMatchObject({ id: "cs_created", name: "Blocked contracts" });
    expect(itemsBySet.cs_created.map((item) => item.value)).toEqual([
      "0x7777777777777777777777777777777777777777",
      "0x8888888888888888888888888888888888888888",
    ]);

    await section
      .getByRole("textbox", { name: "Value", exact: true })
      .fill("0x9999999999999999999999999999999999999999");
    await section.getByRole("textbox", { name: "Label", exact: true }).fill("Treasury");
    await section.getByRole("button", { name: "Add Item" }).click();
    await expect(page.getByText("Condition set item added")).toBeVisible();
    const added = itemsBySet.cs_created[0];
    expect(added).toMatchObject({
      value: "0x9999999999999999999999999999999999999999",
      label: "Treasury",
    });

    const addedRow = section.getByTestId(`condition-set-item-${added.id}`);
    await addedRow.getByRole("button", { name: "Refresh" }).click();
    await expect(page.getByText("Condition set item refreshed")).toBeVisible();
    await addedRow.getByRole("button", { name: "Edit" }).click();
    await addedRow.getByLabel("Value").fill("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    await addedRow.getByLabel("Label").fill("Operations");
    await addedRow.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Condition set item updated")).toBeVisible();
    expect(itemsBySet.cs_created[0]).toMatchObject({
      value: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      label: "Operations",
    });

    await addedRow.getByRole("button", { name: "Delete" }).click();
    await expect(page.getByText("Condition set item deleted")).toBeVisible();
    expect(itemsBySet.cs_created.map((item) => item.value)).not.toContain(
      "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );

    await section
      .getByLabel("Bulk replace values")
      .fill("0x4444444444444444444444444444444444444444");
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

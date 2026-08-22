import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { auditEvents, getDb, tenants, users, userTenants } from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import type { AppVariables } from "../services/context";

const PLATFORM_KEY = "legacy-webhook-platform-key-with-enough-entropy";
const TENANT_ID = "legacy-webhook-existing";
const CREATE_TENANT_ID = "legacy-webhook-create";
const LEGACY_URL = "https://attacker.example.test/unsigned";
const EXPECTED_ERROR =
  "webhookUrl is retired because it cannot provision a receiver-verifiable signing secret; create a webhook with POST /webhooks instead (the secret is returned once)";

let app: Hono<{ Variables: AppVariables }>;
let tenantConfigs: typeof import("../services/context")["tenantConfigs"];
let sessionToken: string;
const USER_ID = "11111111-1111-4111-8111-111111111111";

beforeAll(async () => {
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
  process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
    [PLATFORM_KEY]: ["platform:write", "platform:tenant:create"],
  });

  const context = await import("../services/context");
  const { tenantRoutes } = await import("../routes/tenants");
  tenantConfigs = context.tenantConfigs;
  await getDb()
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Historical webhook tenant",
      apiKeyHash: `hash-${TENANT_ID}`,
    });
  await getDb()
    .insert(users)
    .values({ id: USER_ID, email: `${USER_ID}@example.test` });
  await getDb().insert(userTenants).values({ userId: USER_ID, tenantId: TENANT_ID, role: "owner" });
  const { createSessionToken } = await import("../routes/auth");
  sessionToken = await createSessionToken("0x0000000000000000000000000000000000000000", TENANT_ID, {
    userId: USER_ID,
    email: `${USER_ID}@example.test`,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  tenantConfigs.set(TENANT_ID, {
    id: TENANT_ID,
    name: "Historical webhook tenant",
    webhookUrl: LEGACY_URL,
  });

  app = new Hono<{ Variables: AppVariables }>();
  app.route("/tenants", tenantRoutes);
});

afterAll(async () => {
  tenantConfigs?.delete(TENANT_ID);
  await getDb().delete(userTenants).where(eq(userTenants.tenantId, TENANT_ID));
  await getDb().delete(users).where(eq(users.id, USER_ID));
  await getDb().delete(tenants).where(eq(tenants.id, TENANT_ID));
  delete process.env.STEWARD_PLATFORM_KEYS;
  delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
});

async function legacyAuditRows() {
  return getDb()
    .select({ action: auditEvents.action })
    .from(auditEvents)
    .where(
      and(
        inArray(auditEvents.tenantId, [TENANT_ID, CREATE_TENANT_ID]),
        inArray(auditEvents.action, [
          "tenant.create.authorized",
          "tenant.create",
          "tenant.update.authorized",
          "tenant.update",
        ]),
      ),
    );
}

describe("legacy tenant webhook deprecation", () => {
  it("rejects both mounted legacy write shapes identically before mutation or audit", async () => {
    const before = await legacyAuditRows();
    const create = await app.request("/tenants", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-platform-key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: CREATE_TENANT_ID,
        name: "Legacy webhook create",
        apiKeyHash: "raw-api-key",
        webhookUrl: LEGACY_URL,
      }),
    });
    const update = await app.request(`/tenants/${TENANT_ID}/webhook`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "content-type": "application/json",
        "x-steward-tenant": TENANT_ID,
      },
      body: JSON.stringify({ webhookUrl: LEGACY_URL }),
    });

    for (const response of [create, update]) {
      expect(response.status).toBe(410);
      await expect(response.json()).resolves.toEqual({ ok: false, error: EXPECTED_ERROR });
    }
    expect(update.headers.get("cache-control")).toContain("no-store");
    expect(tenantConfigs.get(TENANT_ID)?.webhookUrl).toBe(LEGACY_URL);
    expect(await legacyAuditRows()).toEqual(before);
  });

  it("keeps historical values inert and absent from mounted reads", async () => {
    const response = await app.request(`/tenants/${TENANT_ID}`, {
      headers: {
        authorization: `Bearer ${sessionToken}`,
        "x-steward-tenant": TENANT_ID,
      },
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: Record<string, unknown> };
    expect(body.data.webhookUrl).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain(LEGACY_URL);
    expect(response.headers.get("cache-control")).toContain("no-store");
  });
});

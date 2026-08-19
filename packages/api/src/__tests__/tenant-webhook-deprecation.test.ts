import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAccessToken } from "@stwd/auth";
import { closeDb, getDb, secrets, tenants, users, userTenants, webhookConfigs } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";

setDefaultTimeout(30_000);

const TENANT_ID = `legacy-webhook-${crypto.randomUUID()}`;
const REJECTED_TENANT_ID = `legacy-webhook-rejected-${crypto.randomUUID()}`;
const OWNER_ID = crypto.randomUUID();
const PLATFORM_KEY = `platform-${crypto.randomUUID()}`;
const LEGACY_URL = "https://historical.example.test/inert";
const originalPlatformKeys = process.env.STEWARD_PLATFORM_KEYS;
const originalPlatformScopes = process.env.STEWARD_PLATFORM_KEY_SCOPES;

let app: typeof import("../app")["app"];
let tenantConfigs: typeof import("../services/context")["tenantConfigs"];

async function ownerToken(): Promise<string> {
  return signAccessToken(
    {
      address: `0x${"1".repeat(40)}`,
      tenantId: TENANT_ID,
      userId: OWNER_ID,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    },
    "10m",
  );
}

describe("legacy tenant webhook deprecation", () => {
  beforeAll(async () => {
    process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [PLATFORM_KEY]: ["platform:write", "platform:tenant:create"],
    });
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    ({ app } = await import("../app"));
    ({ tenantConfigs } = await import("../services/context"));

    await db.insert(tenants).values({
      id: TENANT_ID,
      name: "Historical webhook tenant",
      apiKeyHash: "legacy-webhook-test-hash",
    });
    await db.insert(users).values({ id: OWNER_ID, email: `${OWNER_ID}@example.test` });
    await db.insert(userTenants).values({
      tenantId: TENANT_ID,
      userId: OWNER_ID,
      role: "owner",
    });
    tenantConfigs.set(TENANT_ID, {
      id: TENANT_ID,
      name: "Historical webhook tenant",
      webhookUrl: LEGACY_URL,
      defaultPolicies: [],
    });
  });

  afterAll(async () => {
    tenantConfigs?.delete(TENANT_ID);
    await closeDb();
    if (originalPlatformKeys === undefined) delete process.env.STEWARD_PLATFORM_KEYS;
    else process.env.STEWARD_PLATFORM_KEYS = originalPlatformKeys;
    if (originalPlatformScopes === undefined) delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
    else process.env.STEWARD_PLATFORM_KEY_SCOPES = originalPlatformScopes;
  });

  it("rejects legacy webhook values on tenant creation without provisioning delivery state", async () => {
    const response = await app.request("/tenants", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-steward-platform-key": PLATFORM_KEY,
      },
      body: JSON.stringify({
        id: REJECTED_TENANT_ID,
        name: "Rejected legacy webhook tenant",
        apiKeyHash: "unused-api-key",
        webhookUrl: "https://receiver.example.test/hook",
      }),
    });

    expect(response.status).toBe(410);
    expect(await response.json()).toEqual({
      ok: false,
      error:
        "webhookUrl is retired because it cannot provision a receiver-verifiable signing secret; create a webhook with POST /webhooks instead (the secret is returned once)",
    });
    expect(
      await getDb()
        .select({ id: tenants.id })
        .from(tenants)
        .where(eq(tenants.id, REJECTED_TENANT_ID)),
    ).toEqual([]);
    expect(
      await getDb()
        .select({ id: secrets.id })
        .from(secrets)
        .where(eq(secrets.tenantId, REJECTED_TENANT_ID)),
    ).toEqual([]);
    expect(
      await getDb()
        .select({ id: webhookConfigs.id })
        .from(webhookConfigs)
        .where(eq(webhookConfigs.tenantId, REJECTED_TENANT_ID)),
    ).toEqual([]);
  });

  it("rejects legacy updates and leaves the historical value inert", async () => {
    const token = await ownerToken();
    const rejected = await app.request(`/tenants/${TENANT_ID}/webhook`, {
      method: "PUT",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ webhookUrl: "https://receiver.example.test/replacement" }),
    });
    expect(rejected.status).toBe(410);
    expect((await rejected.json()) as { error: string }).toMatchObject({
      error: expect.stringContaining("POST /webhooks"),
    });
    expect(tenantConfigs.get(TENANT_ID)?.webhookUrl).toBe(LEGACY_URL);

    const read = await app.request(`/tenants/${TENANT_ID}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(read.status).toBe(200);
    expect(JSON.stringify(await read.json())).not.toContain(LEGACY_URL);
  });

  it("clears an inert historical URL when another tenant setting is updated", async () => {
    const response = await app.request(`/tenants/${TENANT_ID}/webhook`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${await ownerToken()}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ defaultPolicies: [] }),
    });

    expect(response.status).toBe(200);
    expect(JSON.stringify(await response.json())).not.toContain(LEGACY_URL);
    expect(tenantConfigs.get(TENANT_ID)?.webhookUrl).toBeUndefined();
  });
});

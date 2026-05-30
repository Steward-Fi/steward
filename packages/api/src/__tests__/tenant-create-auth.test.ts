import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { getDb, tenants } from "@stwd/db";
import { eq } from "drizzle-orm";

setDefaultTimeout(30000);

const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

const PLATFORM_KEY = "test-platform-tenant-create-key";
const TENANT_PREFIX = `test-tenant-create-${process.pid}`;
const UNAUTH_TENANT_ID = `${TENANT_PREFIX}-unauth`;
const AUTH_TENANT_ID = `${TENANT_PREFIX}-auth`;

let app: typeof import("../app")["app"];
let previousPlatformKeys: string | undefined;

function createBody(tenantId: string) {
  return {
    id: tenantId,
    name: `Tenant Create Auth ${tenantId}`,
    apiKeyHash: `tenant-create-key-${tenantId}`,
    webhookUrl: "https://example.com/webhook",
  };
}

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  previousPlatformKeys = process.env.STEWARD_PLATFORM_KEYS;
  process.env.STEWARD_PLATFORM_KEYS = PLATFORM_KEY;

  ({ app } = await import("../app"));
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;

  const db = getDb();
  await db
    .delete(tenants)
    .where(eq(tenants.id, UNAUTH_TENANT_ID))
    .catch(() => {});
  await db
    .delete(tenants)
    .where(eq(tenants.id, AUTH_TENANT_ID))
    .catch(() => {});

  if (previousPlatformKeys === undefined) {
    delete process.env.STEWARD_PLATFORM_KEYS;
  } else {
    process.env.STEWARD_PLATFORM_KEYS = previousPlatformKeys;
  }
});

describeWithDatabase("POST /tenants platform authentication", () => {
  it("rejects unauthenticated tenant creation", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(createBody(UNAUTH_TENANT_ID)),
    });

    expect(res.status).toBe(403);
    const body = (await res.json()) as { ok: boolean; error?: string };
    expect(body.ok).toBe(false);

    const rows = await getDb().select().from(tenants).where(eq(tenants.id, UNAUTH_TENANT_ID));
    expect(rows).toHaveLength(0);
  });

  it("creates a tenant with a valid platform key", async () => {
    const res = await app.request("/tenants", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Steward-Platform-Key": PLATFORM_KEY,
      },
      body: JSON.stringify(createBody(AUTH_TENANT_ID)),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data?: { id: string; name: string; apiKeyHash: string };
    };
    expect(body.ok).toBe(true);
    expect(body.data?.id).toBe(AUTH_TENANT_ID);
    expect(body.data?.name).toBe(`Tenant Create Auth ${AUTH_TENANT_ID}`);
    expect(body.data?.apiKeyHash).not.toBe(`tenant-create-key-${AUTH_TENANT_ID}`);

    const rows = await getDb().select().from(tenants).where(eq(tenants.id, AUTH_TENANT_ID));
    expect(rows).toHaveLength(1);
  });
});

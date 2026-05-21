import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAccessToken } from "@stwd/auth";
import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { and, eq } from "drizzle-orm";

setDefaultTimeout(30000);

const TENANT_ID = "tenant-role-auth";
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();
let app: typeof import("../app")["app"];

beforeAll(async () => {
  process.env.DATABASE_URL = "pglite://embedded";
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "tenant-role-auth-master-password";
  process.env.STEWARD_JWT_SECRET = "tenant-role-auth-jwt-secret-with-enough-bytes";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  ({ app } = await import("../app"));

  const dbHandle = getDb();
  await dbHandle.insert(tenants).values({
    id: TENANT_ID,
    name: "Tenant Role Auth",
    apiKeyHash: "hash",
  });
  await dbHandle.insert(users).values([
    { id: OWNER_USER_ID, email: "owner@example.test" },
    { id: MEMBER_USER_ID, email: "member@example.test" },
  ]);
  await dbHandle.insert(userTenants).values([
    { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
    { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
  ]);
});

afterAll(async () => {
  await closeDb().catch(() => {});
  delete process.env.DATABASE_URL;
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
});

async function createUserToken(userId: string) {
  return signAccessToken(
    {
      address: `0x${"1".repeat(40)}`,
      tenantId: TENANT_ID,
      userId,
    },
    "1h",
  );
}

describe("tenantAuth membership checks and requireTenantLevel role checks", () => {
  it("allows owner sessions to use tenant-level routes but rejects member sessions", async () => {
    const ownerToken = await createUserToken(OWNER_USER_ID);
    const memberToken = await createUserToken(MEMBER_USER_ID);

    const ownerRes = await app.request("/secrets", {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    expect(ownerRes.status).toBe(200);

    const memberRes = await app.request("/secrets", {
      headers: { Authorization: `Bearer ${memberToken}` },
    });
    expect(memberRes.status).toBe(403);
    const memberBody = (await memberRes.json()) as { ok: boolean; error: string };
    expect(memberBody.ok).toBe(false);
    expect(memberBody.error).toContain("tenant-level authentication");
  });

  it("re-validates tenant membership on every request", async () => {
    const memberToken = await createUserToken(MEMBER_USER_ID);

    const beforeRemoval = await app.request("/agents", {
      headers: { Authorization: `Bearer ${memberToken}` },
    });
    expect(beforeRemoval.status).toBe(200);

    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.userId, MEMBER_USER_ID), eq(userTenants.tenantId, TENANT_ID)));

    const afterRemoval = await app.request("/agents", {
      headers: { Authorization: `Bearer ${memberToken}` },
    });
    expect(afterRemoval.status).toBe(403);
    const body = (await afterRemoval.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Not a member");
  });
});

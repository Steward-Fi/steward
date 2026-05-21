import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { signAccessToken } from "@stwd/auth";
import { getDb, tenants, users, userTenants } from "@stwd/db";
import { and, eq } from "drizzle-orm";

setDefaultTimeout(30000);

/**
 * NOTE on test isolation:
 *   Uses the ambient `DATABASE_URL` set by the `Integration Tests (Postgres)`
 *   CI job. The original implementation called `setPGLiteOverride` in
 *   `beforeAll` and `closeDb()` in `afterAll`, which poisoned every
 *   subsequent test in `bun test packages/api` with `error: PGlite is
 *   closed`. We use a unique tenant id and clean up rows in afterAll
 *   instead of swapping the connection.
 */

const TENANT_ID = "test-tenant-role-auth";
const OWNER_USER_ID = crypto.randomUUID();
const MEMBER_USER_ID = crypto.randomUUID();
const hasDatabaseUrl = Boolean(process.env.DATABASE_URL);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;

let app: typeof import("../app")["app"];

beforeAll(async () => {
  if (!hasDatabaseUrl) return;

  ({ app } = await import("../app"));

  const dbHandle = getDb();
  await dbHandle
    .insert(tenants)
    .values({
      id: TENANT_ID,
      name: "Tenant Role Auth",
      apiKeyHash: "hash",
    })
    .onConflictDoNothing();
  await dbHandle
    .insert(users)
    .values([
      { id: OWNER_USER_ID, email: `owner-${OWNER_USER_ID}@example.test` },
      { id: MEMBER_USER_ID, email: `member-${MEMBER_USER_ID}@example.test` },
    ])
    .onConflictDoNothing();
  await dbHandle
    .insert(userTenants)
    .values([
      { userId: OWNER_USER_ID, tenantId: TENANT_ID, role: "owner" },
      { userId: MEMBER_USER_ID, tenantId: TENANT_ID, role: "member" },
    ])
    .onConflictDoNothing();
});

afterAll(async () => {
  if (!hasDatabaseUrl) return;
  const dbHandle = getDb();
  await dbHandle
    .delete(userTenants)
    .where(eq(userTenants.tenantId, TENANT_ID))
    .catch(() => {});
  await dbHandle
    .delete(users)
    .where(eq(users.id, OWNER_USER_ID))
    .catch(() => {});
  await dbHandle
    .delete(users)
    .where(eq(users.id, MEMBER_USER_ID))
    .catch(() => {});
  await dbHandle
    .delete(tenants)
    .where(eq(tenants.id, TENANT_ID))
    .catch(() => {});
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

describeWithDatabase("tenantAuth membership checks and requireTenantLevel role checks", () => {
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
    // Use the OWNER token, because `/agents` is tenant-level (per #56) and
    // the new requireTenantLevel gate enforces role=owner. The point of
    // this test is to verify that revoking the user's membership rejects
    // the very next request even though the JWT is otherwise still valid.
    const ownerToken = await createUserToken(OWNER_USER_ID);

    const beforeRemoval = await app.request("/agents", {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    expect(beforeRemoval.status).toBe(200);

    await getDb()
      .delete(userTenants)
      .where(and(eq(userTenants.userId, OWNER_USER_ID), eq(userTenants.tenantId, TENANT_ID)));

    const afterRemoval = await app.request("/agents", {
      headers: { Authorization: `Bearer ${ownerToken}` },
    });
    expect(afterRemoval.status).toBe(403);
    const body = (await afterRemoval.json()) as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Not a member");
  });
});

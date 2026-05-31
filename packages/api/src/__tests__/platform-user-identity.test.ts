import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { accounts, getDb, sql, tenants, users, userTenants } from "@stwd/db";
import { and, eq } from "drizzle-orm";

const SKIP = !process.env.DATABASE_URL;
const describeWithDatabase = SKIP ? describe.skip : describe;

const TEST_PORT = parseInt(process.env.PORT || "3200", 10);
const BASE_URL = `http://localhost:${TEST_PORT}`;
const PLATFORM_KEY =
  (process.env.STEWARD_PLATFORM_KEYS ?? "").split(",")[0].trim() || "dev-platform-key";

const TENANT_ID = `platform-identity-${Date.now()}`;
const OTHER_TENANT_ID = `${TENANT_ID}-other`;
const USER_EMAIL = `platform-identity-${Date.now()}@example.com`;
let userId = "";

function platformHeaders() {
  return {
    "Content-Type": "application/json",
    "X-Steward-Platform-Key": PLATFORM_KEY,
  };
}

beforeAll(async () => {
  if (SKIP) return;
  const db = getDb();

  await db.execute(sql`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS custom_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
  `);
  await db.execute(sql`
    ALTER TABLE user_tenants
    ADD COLUMN IF NOT EXISTS custom_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
  `);

  await db.insert(tenants).values({
    id: TENANT_ID,
    name: "Platform Identity Test",
    // apiKeyHash is unique-indexed; the two tenants need distinct hashes.
    apiKeyHash: `test-hash-${TENANT_ID}`,
  });
  await db.insert(tenants).values({
    id: OTHER_TENANT_ID,
    name: "Platform Identity Other Tenant",
    apiKeyHash: `test-hash-${OTHER_TENANT_ID}`,
  });
  const [user] = await db
    .insert(users)
    .values({
      email: USER_EMAIL,
      emailVerified: true,
      name: "Identity Test User",
      walletAddress: "0x9999999999999999999999999999999999999999",
      stewardWalletId: "personal-secret-wallet",
      customMetadata: { source: "seed" },
    })
    .returning({ id: users.id });
  userId = user.id;
  await db.insert(userTenants).values({
    userId,
    tenantId: TENANT_ID,
    role: "member",
    customMetadata: { externalId: "crm-1" },
  });
  await db.insert(userTenants).values({
    userId,
    tenantId: OTHER_TENANT_ID,
    role: "member",
    customMetadata: { externalId: "crm-other" },
  });
  await db.insert(accounts).values({
    userId,
    provider: "google",
    providerAccountId: "global-google-account",
  });
});

afterAll(async () => {
  if (SKIP) return;
  const db = getDb();
  // Guard: if beforeAll failed before assigning userId, skip the uuid-typed
  // deletes (an empty string is not a valid uuid and throws).
  if (userId) {
    await db.delete(accounts).where(eq(accounts.userId, userId));
  }
  await db.delete(userTenants).where(eq(userTenants.tenantId, TENANT_ID));
  await db.delete(userTenants).where(eq(userTenants.tenantId, OTHER_TENANT_ID));
  if (userId) {
    await db.delete(users).where(eq(users.id, userId));
  }
  await db.delete(tenants).where(eq(tenants.id, TENANT_ID));
  await db.delete(tenants).where(eq(tenants.id, OTHER_TENANT_ID));
});

describeWithDatabase("platform tenant-scoped user identity", () => {
  it("searches tenant users by email without leaking users from other tenants", async () => {
    const res = await fetch(
      `${BASE_URL}/platform/tenants/${TENANT_ID}/users?email=${encodeURIComponent(USER_EMAIL)}`,
      { headers: platformHeaders() },
    );

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        users: Array<{
          userId: string;
          email: string;
          tenantCustomMetadata: unknown;
          walletAddress?: string;
          stewardWalletId?: string;
          customMetadata?: Record<string, unknown>;
        }>;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.users).toHaveLength(1);
    expect(body.data.users[0]).toMatchObject({
      userId,
      email: USER_EMAIL,
      tenantCustomMetadata: { externalId: "crm-1" },
    });
    expect(body.data.users[0]?.walletAddress).toBeUndefined();
    expect(body.data.users[0]?.stewardWalletId).toBeUndefined();
    expect(body.data.users[0]?.customMetadata).toBeUndefined();
  });

  it("updates only tenant-scoped custom metadata", async () => {
    const res = await fetch(`${BASE_URL}/platform/tenants/${TENANT_ID}/users/${userId}/metadata`, {
      method: "PATCH",
      headers: platformHeaders(),
      body: JSON.stringify({
        customMetadata: { source: "migration", tier: "gold" },
        tenantCustomMetadata: { externalId: "crm-2" },
      }),
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        customMetadata?: Record<string, unknown>;
        tenantCustomMetadata: Record<string, unknown>;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.customMetadata).toBeUndefined();
    expect(body.data.tenantCustomMetadata).toEqual({ externalId: "crm-2" });

    const [globalUser] = await getDb()
      .select({ customMetadata: users.customMetadata })
      .from(users)
      .where(eq(users.id, userId));
    expect(globalUser?.customMetadata).toEqual({ source: "seed" });
  });

  it("does not expose or mutate global linked accounts through tenant-scoped routes", async () => {
    const getRes = await fetch(`${BASE_URL}/platform/tenants/${TENANT_ID}/users/${userId}`, {
      headers: platformHeaders(),
    });
    expect(getRes.status).toBe(200);
    const getBody = (await getRes.json()) as {
      data: { linkedAccounts?: Array<{ provider: string; providerAccountId: string }> };
    };
    expect(getBody.data.linkedAccounts).toBeUndefined();

    const linkRes = await fetch(
      `${BASE_URL}/platform/tenants/${TENANT_ID}/users/${userId}/accounts`,
      {
        method: "POST",
        headers: platformHeaders(),
        body: JSON.stringify({ provider: "google", providerAccountId: `acct-${Date.now()}` }),
      },
    );

    expect(linkRes.status).toBe(410);

    const unlinkRes = await fetch(
      `${BASE_URL}/platform/tenants/${TENANT_ID}/users/${userId}/accounts/google/global-google-account`,
      { method: "DELETE", headers: platformHeaders() },
    );
    expect(unlinkRes.status).toBe(410);

    const db = getDb();
    const accountsAfter = await db
      .select({ id: accounts.id })
      .from(accounts)
      .where(
        and(
          eq(accounts.userId, userId),
          eq(accounts.provider, "google"),
          eq(accounts.providerAccountId, "global-google-account"),
        ),
      );
    expect(accountsAfter).toHaveLength(1);
  });

  it("resolves Privy-style platform user lookup aliases through the global identity graph", async () => {
    const emailRes = await fetch(`${BASE_URL}/platform/users/email/address`, {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ email: USER_EMAIL, tenantId: TENANT_ID }),
    });
    expect(emailRes.status).toBe(200);
    const emailBody = (await emailRes.json()) as { data: { user: { userId: string } | null } };
    expect(emailBody.data.user?.userId).toBe(userId);

    const githubAccountId = `octocat-${Date.now()}`;
    await getDb().insert(accounts).values({
      userId,
      provider: "github",
      providerAccountId: githubAccountId,
    });
    const githubRes = await fetch(`${BASE_URL}/platform/users/github/username`, {
      method: "POST",
      headers: platformHeaders(),
      body: JSON.stringify({ username: githubAccountId, tenantId: TENANT_ID }),
    });
    expect(githubRes.status).toBe(200);
    const githubBody = (await githubRes.json()) as { data: { user: { userId: string } | null } };
    expect(githubBody.data.user?.userId).toBe(userId);
  });
});

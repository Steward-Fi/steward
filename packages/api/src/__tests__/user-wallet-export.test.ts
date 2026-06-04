import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";
import { getDb, tenants, users, userTenants } from "@stwd/db";
import { eq } from "drizzle-orm";

const previousDatabaseUrl = process.env.DATABASE_URL;
// This suite seeds real rows (tenants/users/userTenants) and exercises the
// hardened export routes against an actual database. It cannot run against a
// dummy localhost URL, so it skips when no real DATABASE_URL is configured
// (matching agent-route-scope.test.ts). CI's integration job always provides one.
const hasDatabaseUrl = Boolean(previousDatabaseUrl);
const describeWithDatabase = hasDatabaseUrl ? describe : describe.skip;
process.env.DATABASE_URL ||= "postgres://unused:unused@localhost:5432/unused";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ID = crypto.randomUUID();
const USER_ADDRESS = `0x${crypto.randomUUID().replace(/-/g, "").slice(0, 40).padEnd(40, "0")}`;
const PERSONAL_TENANT_ID = `personal-${USER_ID}`;

let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];

beforeAll(async () => {
  if (!hasDatabaseUrl) return;
  process.env.STEWARD_MASTER_PASSWORD = "user-wallet-export-master-password";
  process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
  process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";
  ({ createSessionToken } = await import("../routes/auth"));
  ({ userRoutes } = await import("../routes/user"));
  await getDb()
    .insert(tenants)
    .values({
      id: PERSONAL_TENANT_ID,
      name: "User Wallet Export Tenant",
      apiKeyHash: `hash-user-wallet-export-${USER_ID}`,
    })
    .onConflictDoNothing();
  await getDb()
    .insert(users)
    .values({ id: USER_ID, walletAddress: USER_ADDRESS, walletChain: "ethereum" })
    .onConflictDoNothing();
  await getDb()
    .insert(userTenants)
    .values({ userId: USER_ID, tenantId: PERSONAL_TENANT_ID, role: "owner" })
    .onConflictDoNothing();
});

beforeEach(() => {
  dispatchWebhookMock.mockClear();
});

afterAll(() => {
  if (previousDatabaseUrl === undefined) {
    delete process.env.DATABASE_URL;
  } else {
    process.env.DATABASE_URL = previousDatabaseUrl;
  }
  if (!hasDatabaseUrl) return;
  void getDb()
    .delete(userTenants)
    .where(eq(userTenants.userId, USER_ID))
    .catch(() => {});
  void getDb()
    .delete(users)
    .where(eq(users.id, USER_ID))
    .catch(() => {});
  void getDb()
    .delete(tenants)
    .where(eq(tenants.id, PERSONAL_TENANT_ID))
    .catch(() => {});
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
  delete process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT;
});

describeWithDatabase("user wallet private key export hardening", () => {
  it("requires a recent MFA step-up before wallet transaction signing reaches vault setup", async () => {
    const token = await createSessionToken(USER_ADDRESS, PERSONAL_TENANT_ID, { userId: USER_ID });

    const res = await userRoutes.request("/me/wallet/sign", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        to: "0x1234567890123456789012345678901234567890",
        value: "1",
        chainId: 8453,
      }),
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("Wallet transaction signing requires a recent MFA step-up");
  });

  it("requires a recent MFA step-up even when break-glass export flags are enabled", async () => {
    const token = await createSessionToken(USER_ADDRESS, PERSONAL_TENANT_ID, { userId: USER_ID });

    const res = await userRoutes.request("/me/wallet/export", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const body = (await res.json()) as { ok: boolean; error?: string };

    expect(res.status).toBe(403);
    expect(body.ok).toBe(false);
    expect(body.error).toContain("recent MFA step-up");
    expect(dispatchWebhookMock).not.toHaveBeenCalled();
  });
});

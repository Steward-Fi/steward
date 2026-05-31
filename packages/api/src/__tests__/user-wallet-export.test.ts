import { afterAll, beforeAll, beforeEach, describe, expect, it, mock } from "bun:test";

import { closeDb, getDb, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";

const dispatchWebhookMock = mock(() => {});

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: dispatchWebhookMock,
}));

const USER_ADDRESS = "0x0000000000000000000000000000000000000001";

let createSessionToken: Awaited<typeof import("../routes/auth")>["createSessionToken"];
let userRoutes: Awaited<typeof import("../routes/user")>["userRoutes"];
let userId = "";
let personalTenantId = "";

beforeAll(async () => {
  process.env.STEWARD_PGLITE_MEMORY = "true";
  process.env.STEWARD_MASTER_PASSWORD = "user-wallet-export-master-password";
  process.env.STEWARD_JWT_SECRET = "user-wallet-export-jwt-secret-with-enough-entropy";
  process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT = "true";
  process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT = "true";

  const { db, client } = await createPGLiteDb("memory://");
  setPGLiteOverride(db, async () => {
    await client.close();
  });

  const [userRow] = await getDb()
    .insert(users)
    .values({ email: "wallet-export@example.test", emailVerified: true })
    .returning({ id: users.id });
  userId = userRow.id;
  personalTenantId = `personal-${userId}`;

  // verifySessionToken requires a userTenants row matching the token tenantId.
  await getDb()
    .insert(tenants)
    .values({
      id: personalTenantId,
      name: "Wallet Export Personal",
      apiKeyHash: `${personalTenantId}-hash`,
    });
  await getDb().insert(userTenants).values({ userId, tenantId: personalTenantId, role: "owner" });

  ({ createSessionToken } = await import("../routes/auth"));
  ({ userRoutes } = await import("../routes/user"));
});

beforeEach(() => {
  dispatchWebhookMock.mockClear();
});

afterAll(async () => {
  await closeDb();
  delete process.env.STEWARD_PGLITE_MEMORY;
  delete process.env.STEWARD_MASTER_PASSWORD;
  delete process.env.STEWARD_JWT_SECRET;
  delete process.env.STEWARD_ALLOW_PRIVATE_KEY_EXPORT;
  delete process.env.STEWARD_ALLOW_USER_PRIVATE_KEY_EXPORT;
});

// A personal session WITHOUT a recent MFA step-up (no mfaVerifiedAt) — passes
// session auth + personal-tenant gating, then must be rejected by the MFA check.
async function personalSessionWithoutMfa(): Promise<string> {
  return createSessionToken(USER_ADDRESS, personalTenantId, {
    userId,
    tenantId: personalTenantId,
  });
}

describe("user wallet private key export hardening", () => {
  it("requires a recent MFA step-up before wallet transaction signing reaches vault setup", async () => {
    const token = await personalSessionWithoutMfa();

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
    const token = await personalSessionWithoutMfa();

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

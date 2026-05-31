import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, refreshTokens, tenants, users, userTenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, inArray } from "drizzle-orm";

const TENANT_ID = "retention-deactivated-users";

describe("deactivated user retention", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_MASTER_PASSWORD = "retention-deactivated-users-master";
    process.env.STEWARD_ALLOW_DEV_SECRETS = "true";
    process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DAYS = "90";
    process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED = "true";

    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Retention Deactivated Users",
      apiKeyHash: "retention-deactivated-users-hash",
    });
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_MASTER_PASSWORD;
    delete process.env.STEWARD_ALLOW_DEV_SECRETS;
    delete process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DAYS;
    delete process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED;
  });

  it("hard-deletes only old deactivated non-owner users when explicitly confirmed", async () => {
    const db = getDb();
    const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000);
    const freshDate = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
    const [oldMember] = await db
      .insert(users)
      .values({ email: "old-deactivated@example.test", deactivatedAt: oldDate })
      .returning({ id: users.id });
    const [freshMember] = await db
      .insert(users)
      .values({ email: "fresh-deactivated@example.test", deactivatedAt: freshDate })
      .returning({ id: users.id });
    const [oldOwner] = await db
      .insert(users)
      .values({ email: "old-owner-deactivated@example.test", deactivatedAt: oldDate })
      .returning({ id: users.id });
    await db.insert(userTenants).values([
      { userId: oldMember.id, tenantId: TENANT_ID, role: "member" },
      { userId: freshMember.id, tenantId: TENANT_ID, role: "member" },
      { userId: oldOwner.id, tenantId: TENANT_ID, role: "owner" },
    ]);
    await db.insert(refreshTokens).values({
      id: "old-deactivated-refresh-token",
      userId: oldMember.id,
      tenantId: TENANT_ID,
      tokenHash: "old-deactivated-refresh-hash",
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    const { runRetentionSweep } = await import("../services/retention");
    const results = await runRetentionSweep();
    expect(results.find((result) => result.table === "users.deactivated")?.deleted).toBe(1);

    const remainingUsers = await db
      .select({ id: users.id })
      .from(users)
      .where(inArray(users.id, [oldMember.id, freshMember.id, oldOwner.id]));
    const remainingIds = remainingUsers.map((row) => row.id);
    expect(remainingIds).not.toContain(oldMember.id);
    expect(remainingIds).toContain(freshMember.id);
    expect(remainingIds).toContain(oldOwner.id);

    const tokens = await db
      .select({ id: refreshTokens.id })
      .from(refreshTokens)
      .where(eq(refreshTokens.id, "old-deactivated-refresh-token"));
    expect(tokens).toHaveLength(0);
  });

  it("does not run without explicit delete confirmation", async () => {
    delete process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED;
    const { runRetentionSweep } = await import("../services/retention");
    const results = await runRetentionSweep();
    expect(results.find((result) => result.table === "users.deactivated")).toBeUndefined();
    process.env.STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED = "true";
  });
});

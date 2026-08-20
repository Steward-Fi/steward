import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq, inArray } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresDescribe =
  databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? describe : describe.skip;

realPostgresDescribe("tenant membership audit atomicity with real PostgreSQL", () => {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const tenantId = `membership-atomic-${suffix}`;
  const ownerA = crypto.randomUUID();
  const ownerB = crypto.randomUUID();
  const member = crypto.randomUUID();
  const triggerFunction = `fail_membership_audit_${suffix}`;
  const triggerName = `fail_membership_audit_${suffix}`;
  let admin: ReturnType<typeof createDb>;
  let app: Hono;
  let createSessionToken: typeof import("../routes/auth").createSessionToken;
  const previousJwtSecret = process.env.STEWARD_JWT_SECRET;
  const previousMasterPassword = process.env.STEWARD_MASTER_PASSWORD;
  const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
  const previousPlatformKeys = process.env.STEWARD_PLATFORM_KEYS;
  const previousPlatformKeyScopes = process.env.STEWARD_PLATFORM_KEY_SCOPES;

  beforeAll(async () => {
    admin = createDb(databaseUrl!);
    process.env.STEWARD_JWT_SECRET = `membership-jwt-${suffix}`;
    process.env.STEWARD_MASTER_PASSWORD = `membership-master-${suffix}`;
    process.env.STEWARD_AUDIT_HMAC_KEY = `membership-audit-key-${suffix}`;
    const platformKey = `membership-platform-key-${suffix}`;
    process.env.STEWARD_PLATFORM_KEYS = platformKey;
    process.env.STEWARD_PLATFORM_KEY_SCOPES = JSON.stringify({
      [platformKey]: ["platform:*"],
    });
    __resetAuditHmacKeyCacheForTests();
    await admin.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: `hash-${suffix}`,
    });
    await admin.db.insert(users).values([
      { id: ownerA, email: `owner-a-${suffix}@example.test`, emailVerified: true },
      { id: ownerB, email: `owner-b-${suffix}@example.test`, emailVerified: true },
      { id: member, email: `member-${suffix}@example.test`, emailVerified: true },
    ]);
    await admin.db.insert(userTenants).values([
      { userId: ownerA, tenantId, role: "owner" },
      { userId: ownerB, tenantId, role: "owner" },
      { userId: member, tenantId, role: "member" },
    ]);
    ({ createSessionToken } = await import("../routes/auth"));
    const { userRoutes } = await import("../routes/user");
    const { platformRoutes } = await import("../routes/platform");
    app = new Hono();
    app.use("*", correlationId);
    app.route("/user", userRoutes);
    app.route("/platform", platformRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  });

  afterAll(async () => {
    await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
    await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
    await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
    await admin.db.delete(users).where(inArray(users.id, [ownerA, ownerB, member]));
    await admin.client.end();
    if (previousJwtSecret === undefined) delete process.env.STEWARD_JWT_SECRET;
    else process.env.STEWARD_JWT_SECRET = previousJwtSecret;
    if (previousMasterPassword === undefined) delete process.env.STEWARD_MASTER_PASSWORD;
    else process.env.STEWARD_MASTER_PASSWORD = previousMasterPassword;
    if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
    else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
    if (previousPlatformKeys === undefined) delete process.env.STEWARD_PLATFORM_KEYS;
    else process.env.STEWARD_PLATFORM_KEYS = previousPlatformKeys;
    if (previousPlatformKeyScopes === undefined) delete process.env.STEWARD_PLATFORM_KEY_SCOPES;
    else process.env.STEWARD_PLATFORM_KEY_SCOPES = previousPlatformKeyScopes;
    __resetAuditHmacKeyCacheForTests();
  });

  async function tokenFor(userId: string): Promise<string> {
    return createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
      userId,
      tenantId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
  }

  it("allows only one concurrent owner demotion and preserves exactly one owner", async () => {
    const responses = await Promise.all([
      app.request(`/platform/tenants/${tenantId}/members/${ownerB}`, {
        method: "PATCH",
        headers: {
          "X-Steward-Platform-Key": process.env.STEWARD_PLATFORM_KEYS!,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "member" }),
      }),
      app.request(`/platform/tenants/${tenantId}/members/${ownerA}`, {
        method: "PATCH",
        headers: {
          "X-Steward-Platform-Key": process.env.STEWARD_PLATFORM_KEYS!,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "member" }),
      }),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([200, 409]);
    const owners = await admin.db
      .select({ userId: userTenants.userId })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.role, "owner")));
    expect(owners).toHaveLength(1);
    const completions = await admin.db
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          eq(auditEvents.action, "tenant.member.role.update"),
        ),
      );
    expect(completions).toHaveLength(1);
  });

  it("rolls back the role update when the required completion audit faults", async () => {
    await admin.client.unsafe(`
      create function "${triggerFunction}"() returns trigger language plpgsql as $$
      begin
        if new.action = 'tenant.member.role.update' and new.resource_id = '${member}' then
          raise exception 'forced membership completion audit failure';
        end if;
        return new;
      end
      $$
    `);
    await admin.client.unsafe(`
      create trigger "${triggerName}"
      before insert on audit_events
      for each row execute function "${triggerFunction}"()
    `);
    const [owner] = await admin.db
      .select({ userId: userTenants.userId })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.role, "owner")));
    const response = await app.request(`/user/me/tenants/${tenantId}/users/${member}/role`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${await tokenFor(owner.userId)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "viewer" }),
    });
    expect(response.status).toBe(500);
    const [stored] = await admin.db
      .select({ role: userTenants.role })
      .from(userTenants)
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, member)));
    expect(stored?.role).toBe("member");
    const completion = await admin.db
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          eq(auditEvents.action, "tenant.member.role.update"),
          eq(auditEvents.resourceId, member),
        ),
      );
    expect(completion).toHaveLength(0);
  });
});

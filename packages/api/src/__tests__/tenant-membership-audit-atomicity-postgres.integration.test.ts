import { afterAll, beforeAll, describe, expect, it, spyOn } from "bun:test";
import { revocationStore } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  auditChainHeads,
  auditEvents,
  createDb,
  tenantInvitations,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq, inArray, sql } from "drizzle-orm";
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
  const revokeUserTokens =
    databaseUrl && !process.env.STEWARD_PGLITE_MEMORY
      ? spyOn(revocationStore, "revokeUserTokens").mockResolvedValue(0)
      : null;
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
    const { userRoutes } = await import("../routes/user");
    const { platformRoutes } = await import("../routes/platform");
    app = new Hono();
    app.use("*", correlationId);
    app.route("/user", userRoutes);
    app.route("/platform", platformRoutes);
    app.onError((error, c) => c.json({ ok: false, error: error.message }, 500));
  });

  afterAll(async () => {
    revokeUserTokens?.mockRestore();
    await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
    await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
    await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
    await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
    await admin.db.delete(tenantInvitations).where(eq(tenantInvitations.tenantId, tenantId));
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

  it("allows only one concurrent owner demotion and preserves exactly one owner", async () => {
    const locker = await holdTenantLifecycleLock(admin, tenantId);
    const pendingResponses = Promise.all([
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
    await waitForAdvisoryWaiters(admin, 2);
    await locker`commit`;
    locker.release();
    const responses = await pendingResponses;
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

  it("serializes concurrent invitation replacement and leaves one audited pending token", async () => {
    const email = `invite-race-${suffix}@example.test`;
    const locker = await holdTenantLifecycleLock(admin, tenantId);
    const createInvitation = () =>
      app.request(`/platform/tenants/${tenantId}/invitations`, {
        method: "POST",
        headers: {
          "X-Steward-Platform-Key": process.env.STEWARD_PLATFORM_KEYS!,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, role: "member" }),
      });
    const pendingResponses = Promise.all([createInvitation(), createInvitation()]);
    await waitForAdvisoryWaiters(admin, 2);
    await locker`commit`;
    locker.release();

    const responses = await pendingResponses;
    expect(responses.map((response) => response.status)).toEqual([201, 201]);
    const pending = await admin.db
      .select({ id: tenantInvitations.id })
      .from(tenantInvitations)
      .where(
        and(
          eq(tenantInvitations.tenantId, tenantId),
          eq(tenantInvitations.email, email),
          eq(tenantInvitations.status, "pending"),
        ),
      );
    expect(pending).toHaveLength(1);
    const completions = await admin.db
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(eq(auditEvents.tenantId, tenantId), eq(auditEvents.action, "tenant.invitation.create")),
      );
    expect(completions).toHaveLength(2);
  });

  it("derives role-change revocation from the final locked membership", async () => {
    revokeUserTokens?.mockClear();
    await admin.db
      .update(userTenants)
      .set({ role: "member" })
      .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, member)));
    const gate = BigInt(`0x${suffix.slice(0, 14)}`).toString();
    const gateFunction = `gate_membership_authorized_${suffix}`;
    const gateTrigger = gateFunction;
    const locker = await admin.client.reserve();
    try {
      await admin.client.unsafe(`
        create function "${gateFunction}"() returns trigger language plpgsql as $$
        begin
          if new.action = 'tenant.member.role.update.authorized' and new.resource_id = '${member}' then
            perform pg_advisory_xact_lock(${gate});
          end if;
          return new;
        end
        $$
      `);
      await admin.client.unsafe(`
        create trigger "${gateTrigger}"
        before insert on audit_events
        for each row execute function "${gateFunction}"()
      `);
      await locker`select pg_advisory_lock(${gate})`;
      const responsePromise = app.request(`/platform/tenants/${tenantId}/members/${member}`, {
        method: "PATCH",
        headers: {
          "X-Steward-Platform-Key": process.env.STEWARD_PLATFORM_KEYS!,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ role: "member" }),
      });
      await waitForAdvisoryWaiters(admin, 1);
      await admin.db.transaction(async (tx) => {
        await tx.execute(
          sql`select pg_advisory_xact_lock(hashtextextended(${`tenant_owner_lifecycle_${tenantId}`}, 0))`,
        );
        await tx
          .update(userTenants)
          .set({ role: "owner" })
          .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, member)));
      });
      await locker`select pg_advisory_unlock(${gate})`;
      const response = await responsePromise;
      expect(response.status).toBe(200);
      expect(revokeUserTokens).toHaveBeenCalledTimes(1);
      expect(revokeUserTokens).toHaveBeenCalledWith(member, expect.any(Number));
      const [stored] = await admin.db
        .select({ role: userTenants.role })
        .from(userTenants)
        .where(and(eq(userTenants.tenantId, tenantId), eq(userTenants.userId, member)));
      expect(stored?.role).toBe("member");
    } finally {
      await locker`select pg_advisory_unlock(${gate})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${gateTrigger}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${gateFunction}"()`);
    }
  });

  it("rolls back the role update when the required completion audit faults", async () => {
    revokeUserTokens?.mockClear();
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
    const response = await app.request(`/platform/tenants/${tenantId}/members/${member}`, {
      method: "PATCH",
      headers: {
        "X-Steward-Platform-Key": process.env.STEWARD_PLATFORM_KEYS!,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ role: "admin" }),
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
    const authorization = await admin.db
      .select({ id: auditEvents.id })
      .from(auditEvents)
      .where(
        and(
          eq(auditEvents.tenantId, tenantId),
          eq(auditEvents.action, "tenant.member.role.update.authorized"),
          eq(auditEvents.resourceId, member),
        ),
      );
    expect(authorization).toHaveLength(1);
    expect(revokeUserTokens).toHaveBeenCalledTimes(1);
    expect(revokeUserTokens).toHaveBeenCalledWith(member, expect.any(Number));
  });
});

async function holdTenantLifecycleLock(admin: ReturnType<typeof createDb>, tenantId: string) {
  const locker = await admin.client.reserve();
  await locker`begin`;
  await locker`select pg_advisory_xact_lock(
    hashtextextended(${`tenant_owner_lifecycle_${tenantId}`}, 0)
  )`;
  return locker;
}

async function waitForAdvisoryWaiters(admin: ReturnType<typeof createDb>, minimum: number) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const [row] = await admin.client<{ count: string }[]>`
      select count(*)::text as count from pg_stat_activity where wait_event = 'advisory'
    `;
    if (Number(row?.count ?? "0") >= minimum) return;
    if (attempt === 199) throw new Error(`expected ${minimum} tenant lifecycle lock waiters`);
    await Bun.sleep(10);
  }
}

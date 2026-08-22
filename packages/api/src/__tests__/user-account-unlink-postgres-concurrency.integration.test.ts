import { expect, it } from "bun:test";
import { hashSha256Hex } from "@stwd/auth";
import {
  __resetAuditHmacKeyCacheForTests,
  accounts,
  auditChainHeads,
  auditEvents,
  createDb,
  refreshTokens,
  tenants,
  users,
  userTenants,
} from "@stwd/db";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { correlationId } from "../middleware/correlation";
import { lockUserSession } from "../services/session-lock";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

async function waitForAdvisoryWaiter(
  client: ReturnType<typeof createDb>["client"],
  queryPattern: string,
): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt++) {
    const [waiting] = await client<{ count: string }[]>`
      select count(*)::text as count
      from pg_stat_activity
      where wait_event = 'advisory' and query ilike ${queryPattern}
    `;
    if (Number(waiting?.count ?? "0") >= 1) return;
    if (attempt === 199) throw new Error(`expected advisory-lock waiter matching ${queryPattern}`);
    await Bun.sleep(10);
  }
}

type Fixture = Awaited<ReturnType<typeof createFixture>>;

async function createFixture(label: string) {
  const suffix = crypto.randomUUID().replaceAll("-", "");
  const userId = crypto.randomUUID();
  const tenantId = `personal-${userId}`;
  const providerAccountId = `${label}-${suffix}`;
  const rawRefreshToken = `refresh-${suffix}`;
  const refreshTokenId = `refresh-row-${suffix}`;
  const triggerFunction = `fail_unlink_audit_${suffix}`;
  const triggerName = `fail_unlink_audit_${suffix}`;
  const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
  const admin = createDb(databaseUrl!);
  const concurrent = createDb(databaseUrl!);
  const locker = await admin.client.reserve();

  await admin.db.insert(tenants).values({
    id: tenantId,
    name: `Unlink concurrency ${label}`,
    apiKeyHash: `unlink-concurrency-${suffix}`,
  });
  await admin.db.insert(users).values({
    id: userId,
    email: `${suffix}@example.test`,
    emailVerified: true,
  });
  await admin.db.insert(userTenants).values({ userId, tenantId, role: "owner" });
  const [account] = await admin.db
    .insert(accounts)
    .values({ userId, provider: "google", providerAccountId })
    .returning({ id: accounts.id });
  await admin.db.insert(refreshTokens).values({
    id: refreshTokenId,
    userId,
    tenantId,
    tokenHash: hashSha256Hex(rawRefreshToken),
    expiresAt: new Date(Date.now() + 60_000),
  });
  await admin.client.unsafe(`
    create function "${triggerFunction}"() returns trigger language plpgsql as $$
    begin
      if new.tenant_id = '${tenantId}' and new.action = 'user.account.unlink' then
        perform pg_advisory_xact_lock(${gateKey});
        raise exception 'forced unlink completion audit failure';
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
  await locker`select pg_advisory_lock(${gateKey})`;

  const [{ createSessionToken, initAuthStores, authRoutes }, { userRoutes }] = await Promise.all([
    import("../routes/auth"),
    import("../routes/user"),
  ]);
  await initAuthStores(false);
  const token = await createSessionToken("0x0000000000000000000000000000000000000000", tenantId, {
    userId,
    tenantId,
    mfaVerifiedAt: Date.now(),
    mfaMethod: "totp",
  });
  const app = new Hono();
  app.use("*", correlationId);
  app.route("/user", userRoutes);
  app.route("/auth", authRoutes);
  app.onError((error, c) =>
    c.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500),
  );

  return {
    accountId: account.id,
    admin,
    app,
    concurrent,
    gateKey,
    locker,
    providerAccountId,
    rawRefreshToken,
    refreshTokenId,
    tenantId,
    token,
    triggerFunction,
    triggerName,
    userId,
  };
}

async function startBlockedUnlink(fixture: Fixture): Promise<{ request: Promise<Response> }> {
  const request = fixture.app.request(
    `/user/me/accounts/google/${encodeURIComponent(fixture.providerAccountId)}`,
    { method: "DELETE", headers: { Authorization: `Bearer ${fixture.token}` } },
  );
  await waitForAdvisoryWaiter(fixture.admin.client, "%INSERT INTO audit_events%");
  return { request };
}

async function releaseGate(fixture: Fixture): Promise<void> {
  await fixture.locker`select pg_advisory_unlock(${fixture.gateKey})`;
}

async function cleanupFixture(fixture: Fixture, gateLocked: boolean): Promise<void> {
  if (gateLocked) await releaseGate(fixture);
  fixture.locker.release();
  await fixture.admin.client.unsafe(
    `drop trigger if exists "${fixture.triggerName}" on audit_events`,
  );
  await fixture.admin.client.unsafe(`drop function if exists "${fixture.triggerFunction}"()`);
  await fixture.admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, fixture.tenantId));
  await fixture.admin.db
    .delete(auditChainHeads)
    .where(eq(auditChainHeads.tenantId, fixture.tenantId));
  await fixture.admin.db.delete(refreshTokens).where(eq(refreshTokens.userId, fixture.userId));
  await fixture.admin.db.delete(accounts).where(eq(accounts.userId, fixture.userId));
  await fixture.admin.db.delete(userTenants).where(eq(userTenants.userId, fixture.userId));
  await fixture.admin.db.delete(tenants).where(eq(tenants.id, fixture.tenantId));
  await fixture.admin.db.delete(users).where(eq(users.id, fixture.userId));
  await Promise.all([fixture.concurrent.client.end(), fixture.admin.client.end()]);
}

realPostgresIt(
  "rolls back unlink and rejects a refresh rotation queued behind the user lock",
  async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "unlink-concurrency-real-postgres-audit-key-with-enough-entropy";
    process.env.STEWARD_JWT_SECRET = "unlink-concurrency-real-postgres-jwt-key-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "unlink-concurrency-real-postgres-master-password";
    __resetAuditHmacKeyCacheForTests();
    const fixture = await createFixture("refresh");
    let gateLocked = true;
    try {
      const { request: unlinkRequest } = await startBlockedUnlink(fixture);
      const refreshRequest = fixture.app.request("/auth/refresh", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: fixture.rawRefreshToken }),
      });
      await waitForAdvisoryWaiter(fixture.admin.client, "%pg_advisory_xact_lock%");
      await releaseGate(fixture);
      gateLocked = false;

      const [unlinkResponse, refreshResponse] = await Promise.all([unlinkRequest, refreshRequest]);
      expect(unlinkResponse.status).toBe(500);
      expect(await unlinkResponse.json()).toMatchObject({
        ok: false,
        data: { accountUnlinked: false, sessionsRevoked: true },
      });
      expect(refreshResponse.status).toBe(401);
      expect(await refreshResponse.json()).toMatchObject({
        ok: false,
        error: "Session was revoked. Please sign in again.",
      });

      expect(
        await fixture.admin.db
          .select({ id: accounts.id })
          .from(accounts)
          .where(eq(accounts.id, fixture.accountId)),
      ).toEqual([{ id: fixture.accountId }]);
      expect(
        await fixture.admin.db
          .select({ id: refreshTokens.id })
          .from(refreshTokens)
          .where(eq(refreshTokens.userId, fixture.userId)),
      ).toHaveLength(0);
      expect(
        await fixture.admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, fixture.tenantId),
              eq(auditEvents.action, "user.account.unlink"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      await cleanupFixture(fixture, gateLocked);
    }
  },
  120_000,
);

realPostgresIt(
  "does not restore the stale linked-account row over a relink queued behind the user lock",
  async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "unlink-relink-real-postgres-audit-key-with-enough-entropy";
    process.env.STEWARD_JWT_SECRET = "unlink-relink-real-postgres-jwt-key-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "unlink-relink-real-postgres-master-password";
    __resetAuditHmacKeyCacheForTests();
    const fixture = await createFixture("relink");
    const freshAccountId = crypto.randomUUID();
    let gateLocked = true;
    try {
      const { request: unlinkRequest } = await startBlockedUnlink(fixture);
      const relink = fixture.concurrent.db.transaction(async (tx) => {
        await lockUserSession(tx, fixture.userId);
        await tx
          .delete(accounts)
          .where(
            and(
              eq(accounts.userId, fixture.userId),
              eq(accounts.provider, "google"),
              eq(accounts.providerAccountId, fixture.providerAccountId),
            ),
          );
        await tx.insert(accounts).values({
          id: freshAccountId,
          userId: fixture.userId,
          provider: "google",
          providerAccountId: fixture.providerAccountId,
        });
      });
      await waitForAdvisoryWaiter(fixture.admin.client, "%pg_advisory_xact_lock%");
      await releaseGate(fixture);
      gateLocked = false;
      const [unlinkResponse] = await Promise.all([unlinkRequest, relink]);

      expect(unlinkResponse.status).toBe(500);
      expect(
        await fixture.admin.db
          .select({ id: accounts.id })
          .from(accounts)
          .where(
            and(
              eq(accounts.userId, fixture.userId),
              eq(accounts.provider, "google"),
              eq(accounts.providerAccountId, fixture.providerAccountId),
            ),
          ),
      ).toEqual([{ id: freshAccountId }]);
      expect(
        await fixture.admin.db
          .select({ id: refreshTokens.id })
          .from(refreshTokens)
          .where(eq(refreshTokens.id, fixture.refreshTokenId)),
      ).toEqual([{ id: fixture.refreshTokenId }]);
      expect(
        await fixture.admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, fixture.tenantId),
              eq(auditEvents.action, "user.account.unlink"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      await cleanupFixture(fixture, gateLocked);
    }
  },
  120_000,
);

realPostgresIt(
  "serializes tenant wallet remediation with relink and never resurrects stale credentials",
  async () => {
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "wallet-remediation-real-postgres-audit-key-with-enough-entropy";
    process.env.STEWARD_JWT_SECRET = "wallet-remediation-real-postgres-jwt-key-with-enough-entropy";
    process.env.STEWARD_MASTER_PASSWORD = "wallet-remediation-real-postgres-master-password";
    __resetAuditHmacKeyCacheForTests();
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `remediation-${suffix}`;
    const adminUserId = crypto.randomUUID();
    const targetUserId = crypto.randomUUID();
    const providerAccountId = `SoRemediation${suffix}`;
    const freshAccountId = crypto.randomUUID();
    const triggerFunction = `fail_remediation_audit_${suffix}`;
    const triggerName = `fail_remediation_audit_${suffix}`;
    const gateKey = Number.parseInt(suffix.slice(0, 12), 16);
    const admin = createDb(databaseUrl!);
    const concurrent = createDb(databaseUrl!);
    const locker = await admin.client.reserve();
    let gateLocked = true;

    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: "Remediation concurrency",
        apiKeyHash: `remediation-${suffix}`,
      });
      await admin.db.insert(users).values([
        { id: adminUserId, email: `admin-${suffix}@example.test`, emailVerified: true },
        { id: targetUserId, email: `target-${suffix}@example.test`, emailVerified: true },
      ]);
      await admin.db.insert(userTenants).values([
        { userId: adminUserId, tenantId, role: "owner" },
        { userId: targetUserId, tenantId, role: "member" },
      ]);
      const [account] = await admin.db
        .insert(accounts)
        .values({ userId: targetUserId, provider: "wallet:solana", providerAccountId })
        .returning({ id: accounts.id });
      await admin.db.insert(refreshTokens).values({
        id: `remediation-refresh-${suffix}`,
        userId: targetUserId,
        tenantId,
        tokenHash: hashSha256Hex(`remediation-refresh-${suffix}`),
        expiresAt: new Date(Date.now() + 60_000),
      });
      await admin.client.unsafe(`
        create function "${triggerFunction}"() returns trigger language plpgsql as $$
        begin
          if new.tenant_id = '${tenantId}' and new.action = 'tenant.wallet_policy.remediation' then
            perform pg_advisory_xact_lock(${gateKey});
            raise exception 'forced remediation completion audit failure';
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
      await locker`select pg_advisory_lock(${gateKey})`;

      const [{ createSessionToken }, { userRoutes }] = await Promise.all([
        import("../routes/auth"),
        import("../routes/user"),
      ]);
      const token = await createSessionToken(
        "0x0000000000000000000000000000000000000000",
        tenantId,
        { userId: adminUserId, tenantId, mfaVerifiedAt: Date.now(), mfaMethod: "totp" },
      );
      const app = new Hono();
      app.use("*", correlationId);
      app.route("/user", userRoutes);
      app.onError((error, c) =>
        c.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 500),
      );

      const request = app.request(
        `/user/me/tenants/${tenantId}/users/${targetUserId}/wallet-policy/wallets/${account.id}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
      );
      await waitForAdvisoryWaiter(admin.client, "%INSERT INTO audit_events%");
      const relink = concurrent.db.transaction(async (tx) => {
        await lockUserSession(tx, targetUserId);
        await tx.delete(accounts).where(eq(accounts.id, account.id));
        await tx.insert(accounts).values({
          id: freshAccountId,
          userId: targetUserId,
          provider: "wallet:solana",
          providerAccountId,
        });
      });
      await waitForAdvisoryWaiter(admin.client, "%pg_advisory_xact_lock%");
      await locker`select pg_advisory_unlock(${gateKey})`;
      gateLocked = false;
      const [response] = await Promise.all([request, relink]);

      expect(response.status).toBe(500);
      expect(await response.json()).toMatchObject({
        ok: false,
        data: { accountUnlinked: false, sessionsRevoked: true },
      });
      expect(
        await admin.db
          .select({ id: accounts.id })
          .from(accounts)
          .where(
            and(
              eq(accounts.userId, targetUserId),
              eq(accounts.providerAccountId, providerAccountId),
            ),
          ),
      ).toEqual([{ id: freshAccountId }]);
      expect(
        await admin.db
          .select({ id: auditEvents.id })
          .from(auditEvents)
          .where(
            and(
              eq(auditEvents.tenantId, tenantId),
              eq(auditEvents.action, "tenant.wallet_policy.remediation"),
            ),
          ),
      ).toHaveLength(0);
    } finally {
      if (gateLocked) await locker`select pg_advisory_unlock(${gateKey})`;
      locker.release();
      await admin.client.unsafe(`drop trigger if exists "${triggerName}" on audit_events`);
      await admin.client.unsafe(`drop function if exists "${triggerFunction}"()`);
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(refreshTokens).where(eq(refreshTokens.userId, targetUserId));
      await admin.db.delete(accounts).where(eq(accounts.userId, targetUserId));
      await admin.db.delete(userTenants).where(eq(userTenants.tenantId, tenantId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.db.delete(users).where(eq(users.id, targetUserId));
      await admin.db.delete(users).where(eq(users.id, adminUserId));
      await Promise.all([concurrent.client.end(), admin.client.end()]);
    }
  },
  120_000,
);

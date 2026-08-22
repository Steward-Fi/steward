import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { createHash, randomUUID } from "node:crypto";
import { unlink } from "node:fs/promises";
import { generateTotp, signAccessToken, verifyToken } from "@stwd/auth";
import { createDb } from "@stwd/db";
import Redis from "ioredis";

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;
const servicesEnabled = Boolean(databaseUrl && redisUrl && !process.env.STEWARD_PGLITE_MEMORY);
const describeWithServices = servicesEnabled ? describe : describe.skip;

type ReplicaRequest = {
  method: string;
  path: string;
  body?: unknown;
  headers?: Record<string, string>;
};

type ReplicaResult = {
  status: number;
  body: Record<string, unknown> | null;
  storeSources: { mfa: string };
  diagnostics?: { stdout: string; stderr: string };
};

type Replica = {
  applicationName: string;
  outputPath: string;
  child: ReturnType<typeof Bun.spawn>;
  stdout: Promise<string>;
  stderr: Promise<string>;
};

const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
const fixturePath = new URL("./fixtures/auth-refresh-replica.ts", import.meta.url).pathname;
const repositoryRoot = new URL("../../../..", import.meta.url).pathname;
const platformKey = `platform-704-${suffix}`;
const jwtSecret = `jwt-704-${suffix}-with-at-least-thirty-two-bytes`;
const masterPassword = `master-704-${suffix}-with-at-least-thirty-two-bytes`;
const auditKey = `audit-704-${suffix}-with-at-least-thirty-two-bytes`;

function tokenHash(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

function databaseUrlFor(applicationName: string): string {
  const url = new URL(databaseUrl!);
  url.searchParams.set("application_name", applicationName);
  return url.toString();
}

function spawnReplica(applicationName: string, request: ReplicaRequest): Replica {
  const outputPath = `/tmp/steward-704-${suffix}-${applicationName}-${randomUUID()}.json`;
  const child = Bun.spawn([process.execPath, fixturePath], {
    cwd: repositoryRoot,
    env: {
      ...process.env,
      DATABASE_URL: databaseUrlFor(applicationName),
      REDIS_URL: redisUrl!,
      NODE_ENV: "test",
      STEWARD_MASTER_PASSWORD: masterPassword,
      STEWARD_JWT_SECRET: jwtSecret,
      STEWARD_AUDIT_HMAC_KEY: auditKey,
      STEWARD_PLATFORM_KEY: platformKey,
      STEWARD_PLATFORM_KEYS: platformKey,
      STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({ [platformKey]: ["platform:*"] }),
      TEST_REPLICA_REQUEST: Buffer.from(JSON.stringify(request)).toString("base64url"),
      TEST_REPLICA_OUTPUT: outputPath,
    },
    stdout: "pipe",
    stderr: "pipe",
  });
  return {
    applicationName,
    outputPath,
    child,
    stdout: new Response(child.stdout).text(),
    stderr: new Response(child.stderr).text(),
  };
}

async function finishReplica(replica: Replica): Promise<ReplicaResult> {
  const [exitCode, stdout, stderr] = await Promise.all([
    replica.child.exited,
    replica.stdout,
    replica.stderr,
  ]);
  if (exitCode !== 0) {
    throw new Error(`replica ${replica.applicationName} failed (${exitCode}): ${stderr || stdout}`);
  }
  try {
    const result = (await Bun.file(replica.outputPath).json()) as ReplicaResult;
    return result.status >= 500 ? { ...result, diagnostics: { stdout, stderr } } : result;
  } finally {
    await unlink(replica.outputPath).catch(() => undefined);
  }
}

describeWithServices("refresh lifecycle across real PostgreSQL/Redis replicas", () => {
  // Bun evaluates skipped describe callbacks while registering their tests.
  // Keep service clients lazy/offline when the integration environment is not
  // configured so ordinary unit-test jobs really skip this suite.
  const offlineDatabaseUrl = "postgresql://unused:unused@127.0.0.1:1/unused";
  const database = createDb(servicesEnabled ? databaseUrl! : offlineDatabaseUrl);
  const lockDatabase = createDb(servicesEnabled ? databaseUrl! : offlineDatabaseUrl);
  const sql = database.client;
  const lockConnection = lockDatabase.client;
  const redis = new Redis(servicesEnabled ? redisUrl! : "redis://127.0.0.1:1", {
    lazyConnect: !servicesEnabled,
    maxRetriesPerRequest: 1,
  });
  const tenantIds = new Set<string>();
  const userIds = new Set<string>();
  const refreshHashes = new Set<string>();

  beforeAll(async () => {
    process.env.STEWARD_JWT_SECRET = jwtSecret;
    process.env.STEWARD_MASTER_PASSWORD = masterPassword;
    process.env.STEWARD_AUDIT_HMAC_KEY = auditKey;
    expect(await redis.ping()).toBe("PONG");
    const [database] = await sql<{ server_version: string }[]>`show server_version`;
    expect(database?.server_version).toMatch(/^1[6-9]\./);
  });

  afterAll(async () => {
    for (const tenantId of tenantIds) {
      await sql`delete from audit_events where tenant_id = ${tenantId}`;
      await sql`delete from audit_chain_heads where tenant_id = ${tenantId}`;
    }
    if (userIds.size > 0) {
      await sql`delete from users where id in ${sql([...userIds])}`;
    }
    for (const tenantId of tenantIds) {
      await sql`delete from tenants where id = ${tenantId}`;
    }
    for (const userId of userIds) {
      await redis.del(
        `revoked-user:${userId}:issued-before`,
        `auth:mfa:totp:pending:${userId}`,
        `auth:mfa:totp:enabled:${userId}`,
        `auth:mfa:recovery:${userId}`,
      );
    }
    for (const hash of refreshHashes) {
      await redis.del(`auth:mfa:refresh:used:${hash}`, `auth:mfa:refresh:claims:${hash}`);
    }
    await Promise.all([sql.end(), lockConnection.end(), redis.quit()]);
  });

  async function seedSession(label: string, options: { targetTenant?: boolean } = {}) {
    const userId = randomUUID();
    const sourceTenantId = `personal-${userId}`;
    const targetTenantId = `t704-${label}-${suffix}`;
    const adminId = randomUUID();
    const rawRefreshToken = `refresh-${label}-${suffix}-${randomUUID()}`;
    const hash = tokenHash(rawRefreshToken);
    userIds.add(userId);
    userIds.add(adminId);
    tenantIds.add(sourceTenantId);
    tenantIds.add(targetTenantId);
    refreshHashes.add(hash);
    await sql`
      insert into tenants(id, name, api_key_hash) values
        (${sourceTenantId}, ${sourceTenantId}, ${`key-${sourceTenantId}`}),
        (${targetTenantId}, ${targetTenantId}, ${`key-${targetTenantId}`})
    `;
    await sql`
      insert into users(id, email) values
        (${userId}::uuid, ${`${label}-${suffix}@example.test`}),
        (${adminId}::uuid, ${`admin-${label}-${suffix}@example.test`})
    `;
    await sql`
      insert into user_tenants(user_id, tenant_id, role) values
        (${userId}::uuid, ${sourceTenantId}, 'owner'),
        (${userId}::uuid, ${targetTenantId}, 'member'),
        (${adminId}::uuid, ${targetTenantId}, 'owner')
    `;
    await sql`
      insert into refresh_tokens(id, user_id, tenant_id, token_hash, expires_at, created_at)
      values (
        ${`rt-${label}-${suffix}`}, ${userId}::uuid,
        ${options.targetTenant ? targetTenantId : sourceTenantId}, ${hash},
        now() + interval '1 day', now() - interval '2 seconds'
      )
    `;
    const userAccessToken = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: options.targetTenant ? targetTenantId : sourceTenantId,
      userId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const adminAccessToken = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: targetTenantId,
      userId: adminId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    return {
      userId,
      adminId,
      sourceTenantId,
      targetTenantId,
      rawRefreshToken,
      hash,
      userAccessToken,
      adminAccessToken,
    };
  }

  async function waitForAdvisoryWait(applicationName: string): Promise<void> {
    for (let attempt = 0; attempt < 3_000; attempt++) {
      const [row] = await sql<{ waiting: boolean }[]>`
        select exists(
          select 1 from pg_stat_activity
          where application_name = ${applicationName}
            and wait_event_type = 'Lock'
            and wait_event = 'advisory'
        ) as waiting
      `;
      if (row?.waiting) return;
      await Bun.sleep(10);
    }
    throw new Error(`replica ${applicationName} never reached the advisory-lock barrier`);
  }

  async function raceInOrder(
    userId: string,
    firstName: string,
    firstRequest: ReplicaRequest,
    secondName: string,
    secondRequest: ReplicaRequest,
  ): Promise<[ReplicaResult, ReplicaResult]> {
    await lockConnection`
      select pg_advisory_lock(hashtextextended(${`user_session_${userId}`}, 0))
    `;
    try {
      const first = spawnReplica(firstName, firstRequest);
      await waitForAdvisoryWait(firstName);
      const second = spawnReplica(secondName, secondRequest);
      await waitForAdvisoryWait(secondName);
      await lockConnection`
        select pg_advisory_unlock(hashtextextended(${`user_session_${userId}`}, 0))
      `;
      const results = await Promise.all([finishReplica(first), finishReplica(second)]);
      for (const result of results) expect(result.storeSources.mfa).toBe("redis");
      return results;
    } catch (error) {
      await lockConnection`
        select pg_advisory_unlock(hashtextextended(${`user_session_${userId}`}, 0))
      `;
      throw error;
    }
  }

  async function liveRefreshRows(userId: string) {
    return sql<{ token_hash: string; tenant_id: string }[]>`
      select token_hash, tenant_id from refresh_tokens where user_id = ${userId}::uuid
    `;
  }

  async function auditActions(tenantId: string) {
    const rows = await sql<{ action: string }[]>`
      select action from audit_events where tenant_id = ${tenantId} order by seq
    `;
    return rows.map((row) => row.action);
  }

  async function expectAuditActions(tenantId: string, expected: string[]) {
    // Concurrent routes append their own audit pairs after releasing the
    // session lock, so cross-request event ordering is intentionally not a
    // lifecycle guarantee. The exact action multiset is.
    expect((await auditActions(tenantId)).sort()).toEqual([...expected].sort());
  }

  test("one concurrent rotation wins, while replay revokes its successor family", async () => {
    const session = await seedSession("rotate");
    const request = {
      method: "POST",
      path: "/auth/refresh",
      body: { refreshToken: session.rawRefreshToken },
    };
    const [winner, loser] = await raceInOrder(
      session.userId,
      `rotate-a-${suffix}`,
      request,
      `rotate-b-${suffix}`,
      request,
    );
    expect(winner.status).toBe(200);
    expect(loser).toMatchObject({
      status: 401,
      body: { ok: false, error: "Refresh token reuse detected. Please sign in again." },
    });
    expect(await liveRefreshRows(session.userId)).toHaveLength(0);
    expect(await redis.get(`revoked-user:${session.userId}:issued-before`)).toMatch(/^\d+$/);
    await expectAuditActions(session.sourceTenantId, [
      "auth.refresh",
      "auth.refresh.reuse_detected",
    ]);
  }, 60_000);

  test("a committed predecessor replay cannot mint a second live successor", async () => {
    const session = await seedSession("replay");
    const first = await finishReplica(
      spawnReplica(`replay-winner-${suffix}`, {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: session.rawRefreshToken },
      }),
    );
    expect(first).toMatchObject({ status: 200 });
    const successor = (first.body?.refreshToken as string | undefined) ?? "";
    expect(successor).not.toBe("");
    refreshHashes.add(tokenHash(successor));
    const replay = await finishReplica(
      spawnReplica(`replay-loser-${suffix}`, {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: session.rawRefreshToken },
      }),
    );
    expect(replay.status).toBe(401);
    expect(await liveRefreshRows(session.userId)).toHaveLength(0);
    const successorAttempt = await finishReplica(
      spawnReplica(`replay-successor-${suffix}`, {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: successor },
      }),
    );
    expect(successorAttempt.status).toBe(401);
  }, 60_000);

  test("user-wide and single-session revocation cannot be escaped by rotation", async () => {
    const all = await seedSession("revoke-all");
    const [rotated, revokedAll] = await raceInOrder(
      all.userId,
      `all-rotate-${suffix}`,
      {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: all.rawRefreshToken },
      },
      `all-revoke-${suffix}`,
      {
        method: "DELETE",
        path: "/auth/sessions",
        headers: { authorization: `Bearer ${all.userAccessToken}` },
      },
    );
    expect([rotated.status, revokedAll.status]).toEqual([200, 200]);
    expect(await liveRefreshRows(all.userId)).toHaveLength(0);
    expect(await redis.get(`revoked-user:${all.userId}:issued-before`)).toMatch(/^\d+$/);
    await expectAuditActions(all.sourceTenantId, [
      "auth.refresh",
      "auth.sessions.revoke_all.authorized",
      "auth.sessions.revoke_all",
    ]);

    const single = await seedSession("revoke-one");
    const [singleRotate, singleRevoke] = await raceInOrder(
      single.userId,
      `one-rotate-${suffix}`,
      {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: single.rawRefreshToken },
      },
      `one-revoke-${suffix}`,
      {
        method: "POST",
        path: "/auth/revoke",
        body: { refreshToken: single.rawRefreshToken },
      },
    );
    expect([singleRotate.status, singleRevoke.status]).toEqual([200, 200]);
    expect(await liveRefreshRows(single.userId)).toHaveLength(0);
    await expectAuditActions(single.sourceTenantId, [
      "auth.refresh",
      "auth.refresh_token.revoke.authorized",
      "auth.refresh_token.revoke",
    ]);
  }, 60_000);

  test("tenant switch cannot escape concurrent membership removal or deactivation", async () => {
    const removed = await seedSession("member-remove");
    const [switchResult, removeResult] = await raceInOrder(
      removed.userId,
      `member-switch-${suffix}`,
      {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: removed.rawRefreshToken, tenantId: removed.targetTenantId },
      },
      `member-remove-${suffix}`,
      {
        method: "DELETE",
        path: `/user/me/tenants/${removed.targetTenantId}/users/${removed.userId}`,
        headers: { authorization: `Bearer ${removed.adminAccessToken}` },
      },
    );
    expect([switchResult.status, removeResult.status]).toEqual([200, 200]);
    expect(await verifyToken(String(switchResult.body?.token))).toMatchObject({
      userId: removed.userId,
      tenantId: removed.targetTenantId,
    });
    expect(await liveRefreshRows(removed.userId)).toHaveLength(0);
    const [membership] = await sql<{ present: boolean }[]>`
      select exists(
        select 1 from user_tenants
        where user_id = ${removed.userId}::uuid and tenant_id = ${removed.targetTenantId}
      ) as present
    `;
    expect(membership?.present).toBe(false);
    expect(await redis.get(`revoked-user:${removed.userId}:issued-before`)).toMatch(/^\d+$/);

    const deactivated = await seedSession("deactivate");
    const [deactivateSwitch, deactivateResult] = await raceInOrder(
      deactivated.userId,
      `deactivate-switch-${suffix}`,
      {
        method: "POST",
        path: "/auth/refresh",
        body: {
          refreshToken: deactivated.rawRefreshToken,
          tenantId: deactivated.targetTenantId,
        },
      },
      `deactivate-user-${suffix}`,
      {
        method: "PATCH",
        path: `/user/me/tenants/${deactivated.targetTenantId}/users/${deactivated.userId}/deactivate`,
        headers: { authorization: `Bearer ${deactivated.adminAccessToken}` },
        body: { deactivated: true },
      },
    );
    expect([deactivateSwitch.status, deactivateResult.status]).toEqual([200, 200]);
    expect(await verifyToken(String(deactivateSwitch.body?.token))).toMatchObject({
      userId: deactivated.userId,
      tenantId: deactivated.targetTenantId,
    });
    expect(await liveRefreshRows(deactivated.userId)).toHaveLength(0);
    expect(await redis.get(`revoked-user:${deactivated.userId}:issued-before`)).toMatch(/^\d+$/);
    const [user] = await sql<{ deactivated_at: string | null }[]>`
      select deactivated_at from users where id = ${deactivated.userId}::uuid
    `;
    expect(Number.isFinite(Date.parse(user?.deactivated_at ?? ""))).toBe(true);
  }, 60_000);

  test("MFA enable and disable revoke a concurrently rotated successor", async () => {
    const session = await seedSession("mfa", { targetTenant: true });
    const enroll = await finishReplica(
      spawnReplica(`mfa-enroll-${suffix}`, {
        method: "POST",
        path: "/auth/mfa/totp/enroll",
        headers: { authorization: `Bearer ${session.userAccessToken}` },
        body: {},
      }),
    );
    expect(enroll).toMatchObject({ status: 200 });
    const secret = enroll.body?.secret as string;
    const enableCode = await generateTotp(secret);
    const [enableRotate, enable] = await raceInOrder(
      session.userId,
      `mfa-enable-rotate-${suffix}`,
      {
        method: "POST",
        path: "/auth/refresh",
        body: { refreshToken: session.rawRefreshToken },
      },
      `mfa-enable-${suffix}`,
      {
        method: "POST",
        path: "/auth/mfa/totp/verify",
        headers: { authorization: `Bearer ${session.userAccessToken}` },
        body: { code: enableCode },
      },
    );
    expect([enableRotate.status, enable.status]).toEqual([200, 200]);
    expect(await liveRefreshRows(session.userId)).toHaveLength(0);
    expect(await redis.get(`revoked-user:${session.userId}:issued-before`)).toMatch(/^\d+$/);
    await expectAuditActions(session.targetTenantId, [
      "auth.refresh",
      "mfa.enable.authorized",
      "mfa.enabled",
    ]);

    await Bun.sleep(1_100);
    const disableRaw = `refresh-mfa-disable-${suffix}-${randomUUID()}`;
    const disableHash = tokenHash(disableRaw);
    refreshHashes.add(disableHash);
    await sql`
      insert into refresh_tokens(id, user_id, tenant_id, token_hash, expires_at, created_at)
      values (
        ${`rt-mfa-disable-${suffix}`}, ${session.userId}::uuid, ${session.targetTenantId},
        ${disableHash}, now() + interval '1 day', now()
      )
    `;
    const postEnableAccess = await signAccessToken({
      address: "0x0000000000000000000000000000000000000000",
      tenantId: session.targetTenantId,
      userId: session.userId,
      mfaVerifiedAt: Date.now(),
      mfaMethod: "totp",
    });
    const disableCode = await generateTotp(secret, { time: Date.now() + 30_000 });
    const [disableRotate, disable] = await raceInOrder(
      session.userId,
      `mfa-disable-rotate-${suffix}`,
      { method: "POST", path: "/auth/refresh", body: { refreshToken: disableRaw } },
      `mfa-disable-${suffix}`,
      {
        method: "POST",
        path: "/auth/mfa/totp/unenroll",
        headers: { authorization: `Bearer ${postEnableAccess}` },
        body: { code: disableCode },
      },
    );
    expect([disableRotate.status, disable.status]).toEqual([200, 200]);
    expect(await liveRefreshRows(session.userId)).toHaveLength(0);
    expect(await redis.get(`auth:mfa:totp:enabled:${session.userId}`)).toBeNull();
    await expectAuditActions(session.targetTenantId, [
      "auth.refresh",
      "mfa.enable.authorized",
      "mfa.enabled",
      "auth.refresh",
      "mfa.disable.authorized",
      "mfa.disabled",
    ]);
  }, 90_000);
});

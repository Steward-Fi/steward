import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import postgres from "postgres";
import { runMigrations } from "../migrate";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
setDefaultTimeout(240_000);

const repoRoot = new URL("../../../../", import.meta.url).pathname;
const migrationsRoot = new URL("../../drizzle/", import.meta.url).pathname;
const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
const databaseName = `steward_personal_${suffix}`;
const appRole = `steward_app_${suffix}`;
const migrationRole = `steward_migrator_${suffix}`;
const bootstrapRole = `steward_bootstrap_${suffix}`;
const platformRole = `steward_platform_${suffix}`;
const rolePassword = randomUUID().replaceAll("-", "");

type JournalEntry = { idx: number; tag: string; when: number };
const journal = JSON.parse(readFileSync(`${migrationsRoot}meta/_journal.json`, "utf8")) as {
  entries: JournalEntry[];
};

function databaseUrl(database = databaseName, role?: string): string {
  const url = new URL(process.env.DATABASE_URL as string);
  url.pathname = `/${database}`;
  if (role) {
    url.username = role;
    url.password = rolePassword;
  }
  return url.toString();
}

async function command(argv: string[], env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn(argv, {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) throw new Error(stderr || stdout);
  return stdout;
}

function operatorArgs(script: string, role?: string): string[] {
  return [
    "psql",
    "--no-psqlrc",
    "--dbname",
    databaseUrl(databaseName, role),
    "-v",
    `steward_app_role=${appRole}`,
    "-v",
    `steward_migration_role=${migrationRole}`,
    "-v",
    `steward_bootstrap_role=${bootstrapRole}`,
    "-v",
    `steward_platform_role=${platformRole}`,
    "-f",
    script,
  ];
}

function migrationHash(tag: string): string {
  return createHash("sha256")
    .update(readFileSync(`${migrationsRoot}${tag}.sql`))
    .digest("hex");
}

async function expectDatabaseRejection(action: Promise<unknown>, message: RegExp): Promise<void> {
  let rejection: unknown;
  try {
    await action;
  } catch (error) {
    rejection = error;
  }
  expect(rejection).toBeInstanceOf(Error);
  const error = rejection as Error & { cause?: unknown };
  expect(`${error.message}\n${String(error.cause ?? "")}`).toMatch(message);
}

describeWithPostgres("personal lifecycle production upgrade topology", () => {
  const admin = postgres(process.env.DATABASE_URL as string, { max: 1 });

  afterAll(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    for (const role of [appRole, migrationRole, bootstrapRole, platformRole]) {
      await admin.unsafe(`DROP ROLE IF EXISTS ${role}`);
    }
    await admin.end();
  });

  test("upgrades privileged functions, preserves evidence, and serializes both race winners", async () => {
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);
    expect(migrationHash("0113_personal_tenant_account_lifecycle")).toBe(
      "81e4d8907075ce85c5b4d46c43623b849bf9f26af1d90ad5dc7caa74f739d534",
    );
    const through0113 = journal.entries.filter((entry) => entry.idx <= 113);
    const migrationArgs = ["psql", "--no-psqlrc", "--dbname", databaseUrl()];
    for (const entry of through0113) {
      migrationArgs.push("-f", `${migrationsRoot}${entry.tag}.sql`);
    }
    await command(migrationArgs);

    const db = postgres(databaseUrl(), { max: 1 });
    await db`CREATE SCHEMA IF NOT EXISTS drizzle`;
    await db`CREATE TABLE drizzle.__drizzle_migrations (
      id serial PRIMARY KEY, hash text NOT NULL, created_at bigint
    )`;
    for (const entry of through0113) {
      await db`INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
        VALUES (${migrationHash(entry.tag)}, ${entry.when})`;
    }

    await command(operatorArgs("scripts/postgres/rls-bootstrap.sql"));
    await admin.unsafe(`ALTER ROLE ${appRole} PASSWORD '${rolePassword}'`);
    await admin.unsafe(`ALTER ROLE ${migrationRole} PASSWORD '${rolePassword}'`);
    await admin.unsafe(`ALTER ROLE ${platformRole} PASSWORD '${rolePassword}'`);

    const migrator = postgres(databaseUrl(databaseName, migrationRole), { max: 1 });
    const [beforeUpgrade] = await db<{ owner: string; acl: string | null }[]>`
      SELECT pg_get_userbyid(p.proowner) AS owner, p.proacl::text AS acl
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'steward_bootstrap' AND p.proname = 'platform_delete_user'
    `;
    expect(beforeUpgrade?.owner).toBe(bootstrapRole);

    const originalDatabaseUrl = process.env.DATABASE_URL;
    let applied: string[];
    try {
      process.env.DATABASE_URL = databaseUrl(databaseName, migrationRole);
      ({ applied } = await runMigrations());
    } finally {
      process.env.DATABASE_URL = originalDatabaseUrl;
    }
    expect(applied).toContain("0114_personal_lifecycle_invariants");
    await command(operatorArgs("scripts/postgres/rls-bootstrap.sql"));
    await command(operatorArgs("scripts/postgres/rls-upgrade-personal-lifecycle.sql"));
    await command(operatorArgs("scripts/postgres/rls-upgrade-personal-lifecycle.sql"));

    const [afterUpgrade] = await db<{ owner: string; acl: string | null }[]>`
      SELECT pg_get_userbyid(p.proowner) AS owner, p.proacl::text AS acl
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'steward_bootstrap' AND p.proname = 'platform_delete_user'
    `;
    expect(afterUpgrade).toEqual(beforeUpgrade);

    const [lockPrivileges] = await db<{ app: boolean; bootstrap: boolean; platform: boolean }[]>`
      SELECT
        has_function_privilege(${appRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS app,
        has_function_privilege(${bootstrapRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS bootstrap,
        has_function_privilege(${platformRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS platform
    `;
    expect(lockPrivileges).toEqual({ app: true, bootstrap: true, platform: false });
    const [lifecycleFunctionPrivileges] = await db<
      {
        appReadsBoundary: boolean;
        appCallsMutation: boolean;
        appCallsImplementation: boolean;
        platformCallsMutation: boolean;
      }[]
    >`
      SELECT
        has_function_privilege(${appRole}, 'steward_bootstrap.user_token_revocation_subject(uuid)', 'EXECUTE') AS "appReadsBoundary",
        has_function_privilege(${appRole}, 'steward_bootstrap.platform_set_user_deactivation(uuid,boolean)', 'EXECUTE') AS "appCallsMutation",
        has_function_privilege(${appRole}, 'public.steward_user_token_revocation_subject_v1(uuid)', 'EXECUTE') AS "appCallsImplementation",
        has_function_privilege(${platformRole}, 'steward_bootstrap.platform_set_user_deactivation(uuid,boolean)', 'EXECUTE') AS "platformCallsMutation"
    `;
    expect(lifecycleFunctionPrivileges).toEqual({
      appReadsBoundary: true,
      appCallsMutation: false,
      appCallsImplementation: false,
      platformCallsMutation: true,
    });
    const [tombstonePrivileges] = await db<{ app: boolean; bootstrap: boolean }[]>`
      SELECT
        has_table_privilege(${appRole}, 'public.user_identity_subjects', 'SELECT,INSERT,UPDATE,DELETE') AS app,
        has_table_privilege(${bootstrapRole}, 'public.user_identity_subjects', 'SELECT,UPDATE') AS bootstrap
    `;
    expect(tombstonePrivileges).toEqual({ app: false, bootstrap: true });
    const [userLifecyclePrivileges] = await db<
      {
        updateName: boolean;
        updateDeactivated: boolean;
        updateTokenBoundary: boolean;
        insertDeactivated: boolean;
        insertTokenBoundary: boolean;
        deleteUser: boolean;
      }[]
    >`
      SELECT
        has_column_privilege(${appRole}, 'public.users', 'name', 'UPDATE') AS "updateName",
        has_column_privilege(${appRole}, 'public.users', 'deactivated_at', 'UPDATE') AS "updateDeactivated",
        has_column_privilege(${appRole}, 'public.users', 'tokens_revoked_before', 'UPDATE') AS "updateTokenBoundary",
        has_column_privilege(${appRole}, 'public.users', 'deactivated_at', 'INSERT') AS "insertDeactivated",
        has_column_privilege(${appRole}, 'public.users', 'tokens_revoked_before', 'INSERT') AS "insertTokenBoundary",
        has_table_privilege(${appRole}, 'public.users', 'DELETE') AS "deleteUser"
    `;
    expect(userLifecyclePrivileges).toEqual({
      updateName: true,
      updateDeactivated: false,
      updateTokenBoundary: false,
      insertDeactivated: false,
      insertTokenBoundary: false,
      deleteUser: false,
    });

    const [restricted] = await migrator<{ rolsuper: boolean; rolbypassrls: boolean }[]>`
      SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user
    `;
    expect(restricted).toEqual({ rolsuper: false, rolbypassrls: false });
    let assumeBootstrapError: unknown;
    try {
      await migrator.unsafe(`SET ROLE ${bootstrapRole}`);
    } catch (error) {
      assumeBootstrapError = error;
    }
    expect(assumeBootstrapError).toBeInstanceOf(Error);

    const userId = randomUUID();
    const otherOwnerId = randomUUID();
    const personalTenantId = `personal-${userId}`;
    await db`INSERT INTO users (id,email,email_verified) VALUES
      (${userId}, 'deleted-owner@example.test', true),
      (${otherOwnerId}, 'surviving-owner@example.test', true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash) VALUES
      (${personalTenantId}, 'Personal lifecycle race', 'personal-hash'),
      ('shared-provenance', 'Shared provenance', 'shared-hash')`;
    await db`INSERT INTO user_tenants (user_id,tenant_id,role) VALUES
      (${userId}, ${personalTenantId}, 'owner'),
      (${userId}, 'shared-provenance', 'owner'),
      (${otherOwnerId}, 'shared-provenance', 'owner')`;

    const mountedOwnerId = randomUUID();
    const mountedPersonalTenantId = `personal-${mountedOwnerId}`;
    await db`INSERT INTO users (id,email,email_verified)
      VALUES (${mountedOwnerId}, 'mounted-personal-owner@example.test', true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES (${mountedPersonalTenantId}, 'Mounted personal lifecycle', 'mounted-personal-hash')`;
    await db`INSERT INTO user_tenants (user_id,tenant_id,role)
      VALUES (${mountedOwnerId}, ${mountedPersonalTenantId}, 'owner')`;
    const teamAdminId = randomUUID();
    const teamTargetId = randomUUID();
    const teamTenantId = `team-lifecycle-${suffix}`;
    await db`INSERT INTO users (id,email,email_verified) VALUES
      (${teamAdminId}, 'mounted-team-admin@example.test', true),
      (${teamTargetId}, 'mounted-team-target@example.test', true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES (${teamTenantId}, 'Mounted team lifecycle', 'mounted-team-hash')`;
    await db`INSERT INTO user_tenants (user_id,tenant_id,role) VALUES
      (${teamAdminId}, ${teamTenantId}, 'owner'),
      (${teamTargetId}, ${teamTenantId}, 'member')`;
    const platformKey = `personal-lifecycle-platform-key-${suffix}`;
    const mountedEvidence = await command(
      ["bun", "run", "packages/api/src/__tests__/fixtures/personal-lifecycle-app-delete.ts"],
      {
        DATABASE_URL: databaseUrl(databaseName, appRole),
        DATABASE_DRIVER: "postgres-js",
        STEWARD_APP_DATABASE_ROLE: appRole,
        STEWARD_PLATFORM_DATABASE_URL: databaseUrl(databaseName, platformRole),
        STEWARD_PLATFORM_DATABASE_ROLE: platformRole,
        NODE_ENV: "test",
        APP_URL: "https://steward.test",
        JWT_SECRET: `personal-lifecycle-jwt-${suffix}-0123456789abcdef`,
        STEWARD_JWT_SECRET: `personal-lifecycle-jwt-${suffix}-0123456789abcdef`,
        STEWARD_AUDIT_HMAC_KEY: "ab".repeat(32),
        STEWARD_DEFAULT_TENANT_KEY: `personal-lifecycle-default-${suffix}`,
        STEWARD_MASTER_PASSWORD: `personal-lifecycle-master-${suffix}`,
        STEWARD_PLATFORM_KEYS: platformKey,
        STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({
          [platformKey]: [
            "platform:write",
            "platform:tenant:delete",
            "platform:user-lifecycle:write",
          ],
        }),
        STEWARD_PERSONAL_LIFECYCLE_TEST_TENANT: mountedPersonalTenantId,
        STEWARD_PERSONAL_LIFECYCLE_TEST_USER: mountedOwnerId,
        STEWARD_PERSONAL_LIFECYCLE_TEAM_TENANT: teamTenantId,
        STEWARD_PERSONAL_LIFECYCLE_TEAM_ADMIN: teamAdminId,
        STEWARD_PERSONAL_LIFECYCLE_TEAM_TARGET: teamTargetId,
        STEWARD_REDIS_REQUIRED: "false",
        STEWARD_ALLOW_INSECURE_AUTH_STORES: "true",
      },
    );
    expect(
      mountedEvidence
        .trim()
        .split("\n")
        .findLast((line) => line === '{"ok":true,"deleted":true,"lifecycle":true}'),
    ).toBeDefined();
    expect(await db`SELECT id FROM tenants WHERE id = ${mountedPersonalTenantId}`).toHaveLength(0);

    const evmOwnerId = randomUUID();
    const solanaOwnerId = randomUUID();
    const legacyOwnerId = randomUUID();
    const evmAddress = "0x2222222222222222222222222222222222222222";
    const solanaAddress = "zshVFXnC99G1ijob5dm9xS1hhSsgzC5PbDaLzSXPdct";
    await db`INSERT INTO users (id,email,email_verified,wallet_address,wallet_chain) VALUES
      (${evmOwnerId}, NULL, false, ${evmAddress}, 'ethereum'),
      (${solanaOwnerId}, NULL, false, ${solanaAddress}, 'solana'),
      (${legacyOwnerId}, NULL, false, '0x3333333333333333333333333333333333333333', 'ethereum')`;
    await db`INSERT INTO tenants (id,name,api_key_hash,owner_address) VALUES
      (${`eth:${evmAddress}`}, 'EVM wallet owner', 'evm-wallet-hash', ${evmAddress}),
      (${`solana:${solanaAddress}`}, 'Solana wallet owner', 'solana-wallet-hash', ${`solana:${solanaAddress}`}),
      ('t-legacy-wallet-owner', 'Legacy wallet owner', 'legacy-wallet-hash', '0x3333333333333333333333333333333333333333')`;
    const appWriter = postgres(databaseUrl(databaseName, appRole), { max: 1 });
    const [appCreatedUser] = await appWriter<{ id: string }[]>`
      INSERT INTO users (email,email_verified,name)
      VALUES ('app-created-profile@example.test', true, 'App-created profile')
      RETURNING id
    `;
    expect(appCreatedUser?.id).toBeDefined();
    await expectDatabaseRejection(
      appWriter`INSERT INTO users (email,deactivated_at)
        VALUES ('app-forged-lifecycle@example.test', now())`,
      /permission denied for table users/,
    );
    await appWriter.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', ${personalTenantId}, true)`;
      await tx`SELECT set_config('steward.user_id', ${userId}, true)`;
      await tx`UPDATE users SET name = 'Allowed profile update' WHERE id = ${userId}`;
      const [boundary] = await tx<{ value: bigint }[]>`
        SELECT steward_bootstrap.user_token_revocation_subject(${userId}::uuid) AS value
      `;
      expect(Number(boundary?.value)).toBe(-1);
    });
    await expectDatabaseRejection(
      appWriter.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${personalTenantId}, true)`;
        await tx`SELECT set_config('steward.user_id', ${userId}, true)`;
        await tx`UPDATE users SET deactivated_at = now() WHERE id = ${userId}`;
      }),
      /permission denied for table users/,
    );
    await expectDatabaseRejection(
      appWriter.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${personalTenantId}, true)`;
        await tx`SELECT set_config('steward.user_id', ${userId}, true)`;
        await tx`UPDATE users SET tokens_revoked_before = 0 WHERE id = ${userId}`;
      }),
      /permission denied for table users/,
    );
    await expectDatabaseRejection(
      appWriter.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${personalTenantId}, true)`;
        await tx`SELECT set_config('steward.user_id', ${userId}, true)`;
        await tx`DELETE FROM users WHERE id = ${userId}`;
      }),
      /permission denied for table users/,
    );
    for (const [walletUserId, walletTenantId] of [
      [evmOwnerId, `eth:${evmAddress}`],
      [solanaOwnerId, `solana:${solanaAddress}`],
      [legacyOwnerId, "t-legacy-wallet-owner"],
    ] as const) {
      await appWriter.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', ${walletTenantId}, true)`;
        await tx`SELECT set_config('steward.user_id', ${walletUserId}, true)`;
        await tx`INSERT INTO user_tenants (user_id,tenant_id,role)
          VALUES (${walletUserId}, ${walletTenantId}, 'owner')`;
      });
    }
    expect(
      await db`SELECT tenant_id, role FROM user_tenants
        WHERE user_id IN (${evmOwnerId}, ${solanaOwnerId}, ${legacyOwnerId})
        ORDER BY tenant_id`,
    ).toEqual([
      { tenant_id: `eth:${evmAddress}`, role: "owner" },
      { tenant_id: `solana:${solanaAddress}`, role: "owner" },
      { tenant_id: "t-legacy-wallet-owner", role: "owner" },
    ]);
    await expectDatabaseRejection(
      appWriter`UPDATE users
        SET wallet_address = '0x4444444444444444444444444444444444444444'
        WHERE id = ${evmOwnerId}`,
      /Wallet tenant owner identity is immutable while membership exists/,
    );
    await expectDatabaseRejection(
      appWriter`UPDATE tenants
        SET owner_address = '0x4444444444444444444444444444444444444444'
        WHERE id = ${`eth:${evmAddress}`}`,
      /Wallet tenant owner identity is immutable while membership exists/,
    );
    await expectDatabaseRejection(
      db`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${otherOwnerId}, ${`eth:${evmAddress}`}, 'owner')`,
      /Reserved tenant membership is immutable/,
    );

    for (const reservedTenantId of [
      "platform",
      "system",
      "personal",
      "personal-invalid-owner",
      "eth:reserved-real-pg",
      "t-reserved-real-pg",
      "solana:reserved-real-pg",
    ]) {
      await db`INSERT INTO tenants (id,name,api_key_hash)
        VALUES (${reservedTenantId}, ${`Reserved ${reservedTenantId}`}, ${`hash-${reservedTenantId}`})
        ON CONFLICT (id) DO NOTHING`;
      await expectDatabaseRejection(
        db`INSERT INTO user_tenants (user_id,tenant_id,role)
          VALUES (${otherOwnerId}, ${reservedTenantId}, 'member')`,
        /Reserved tenant membership is immutable/,
      );
      await expectDatabaseRejection(
        db`INSERT INTO tenant_invitations
          (tenant_id,email,role,token_hash,expires_at)
          VALUES (
            ${reservedTenantId}, ${`blocked-${reservedTenantId.replaceAll(":", "-")}@example.test`},
            'member', ${`token-${reservedTenantId}`}, now() + interval '1 hour'
          )`,
        /Reserved tenant invitations are forbidden/,
      );
    }
    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES ('default', 'Default auth tenant', 'default-auth-hash')
      ON CONFLICT (id) DO NOTHING`;
    await expectDatabaseRejection(
      db`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${otherOwnerId}, 'default', 'member')`,
      /Reserved tenant membership is immutable/,
    );
    await appWriter.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', 'default', true)`;
      await tx`SELECT set_config('steward.user_id', ${otherOwnerId}, true)`;
      await tx`SELECT steward_bootstrap.ensure_default_membership(
        ${otherOwnerId}::uuid, 'member'
      )`;
    });
    await expectDatabaseRejection(
      db`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${otherOwnerId}, 'default', 'owner')`,
      /Reserved tenant membership is immutable/,
    );
    await expectDatabaseRejection(
      db`INSERT INTO tenant_invitations
        (tenant_id,email,role,token_hash,expires_at)
        VALUES ('default', 'blocked-default@example.test', 'member', 'token-default', now() + interval '1 hour')`,
      /Reserved tenant invitations are forbidden/,
    );

    await expectDatabaseRejection(
      db`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${otherOwnerId}, ${personalTenantId}, 'member')`,
      /Reserved tenant membership is immutable/,
    );
    await expectDatabaseRejection(
      db`INSERT INTO tenant_invitations
        (tenant_id,email,role,token_hash,invited_by_user_id,expires_at)
        VALUES (${personalTenantId}, 'blocked@example.test', 'member', 'blocked-hash', ${userId}, now() + interval '1 hour')`,
      /Reserved tenant invitations are forbidden/,
    );

    const writer = postgres(databaseUrl(), { max: 1 });
    const deleter = postgres(databaseUrl(), { max: 1 });
    const platform = postgres(databaseUrl(databaseName, platformRole), { max: 1 });
    const [{ pid: writerPid }] = await writer<{ pid: number }[]>`SELECT pg_backend_pid() AS pid`;
    const [{ pid: deleterPid }] = await deleter<{ pid: number }[]>`SELECT pg_backend_pid() AS pid`;
    const [{ pid: platformPid }] = await platform<
      { pid: number }[]
    >`SELECT pg_backend_pid() AS pid`;
    const waitForAdvisoryWait = async (pid: number) => {
      for (let attempt = 0; attempt < 100; attempt += 1) {
        const [activity] = await admin<{ waiting: boolean }[]>`
          SELECT EXISTS (
            SELECT 1 FROM pg_stat_activity
            WHERE datname = ${databaseName}
              AND pid = ${pid}
              AND wait_event_type = 'Lock'
              AND wait_event = 'advisory'
          ) AS waiting
        `;
        if (activity?.waiting) return;
        await Bun.sleep(20);
      }
      throw new Error(`backend ${pid} did not reach the personal lifecycle advisory lock`);
    };

    const walletRaceUserId = randomUUID();
    const walletRaceAddress = "0x5555555555555555555555555555555555555555";
    const walletRaceTenantId = `eth:${walletRaceAddress}`;
    await db`INSERT INTO users (id,email,email_verified,wallet_address,wallet_chain)
      VALUES (${walletRaceUserId}, 'wallet-race@example.test', true, ${walletRaceAddress}, 'ethereum')`;
    await db`INSERT INTO tenants (id,name,api_key_hash,owner_address)
      VALUES (${walletRaceTenantId}, 'Wallet identity race', 'wallet-race-hash', ${walletRaceAddress})`;

    let identityFirstMembership: Promise<unknown> | undefined;
    await writer.begin(async (tx) => {
      await tx`UPDATE users
        SET wallet_address = '0x6666666666666666666666666666666666666666'
        WHERE id = ${walletRaceUserId}`;
      identityFirstMembership = deleter.begin(async (other) => {
        await other`INSERT INTO user_tenants (user_id,tenant_id,role)
          VALUES (${walletRaceUserId}, ${walletRaceTenantId}, 'owner')`;
      });
      await waitForAdvisoryWait(deleterPid);
    });
    await expectDatabaseRejection(
      identityFirstMembership as Promise<unknown>,
      /Reserved tenant membership is immutable/,
    );

    await db`UPDATE users SET wallet_address = ${walletRaceAddress}
      WHERE id = ${walletRaceUserId}`;
    let membershipFirstIdentity: Promise<unknown> | undefined;
    await deleter.begin(async (tx) => {
      await tx`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${walletRaceUserId}, ${walletRaceTenantId}, 'owner')`;
      membershipFirstIdentity = writer.begin(async (other) => {
        await other`UPDATE users
          SET wallet_address = '0x7777777777777777777777777777777777777777'
          WHERE id = ${walletRaceUserId}`;
      });
      await waitForAdvisoryWait(writerPid);
    });
    await expectDatabaseRejection(
      membershipFirstIdentity as Promise<unknown>,
      /Wallet tenant owner identity is immutable while membership exists/,
    );

    let writerFirstCompeting: Promise<unknown> | undefined;
    await writer.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
      await tx`SELECT * FROM steward_bootstrap.platform_set_user_deactivation(${userId}::uuid, true)`;
      writerFirstCompeting = deleter.begin(async (other) => {
        await other`SELECT * FROM public.steward_lock_personal_lifecycle(
          ${userId}::uuid, ${personalTenantId}, true
        )`;
      });
      await waitForAdvisoryWait(deleterPid);
    });
    await writerFirstCompeting;

    let deleterFirstCompeting: Promise<unknown> | undefined;
    await deleter.begin(async (tx) => {
      await tx`SELECT * FROM public.steward_lock_personal_lifecycle(
        ${userId}::uuid, ${personalTenantId}, true
      )`;
      deleterFirstCompeting = writer.begin(async (other) => {
        await other`SELECT set_config('steward.tenant_id', 'platform', true)`;
        await other`SELECT * FROM steward_bootstrap.platform_set_user_deactivation(${userId}::uuid, true)`;
      });
      await waitForAdvisoryWait(writerPid);
    });
    await deleterFirstCompeting;

    const membershipRaceUserId = randomUUID();
    await db`INSERT INTO users (id,email,email_verified)
      VALUES (${membershipRaceUserId}, 'membership-race@example.test', true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES ('membership-race-tenant', 'Membership race', 'membership-race-hash')`;

    let writerFirstDeactivation: Promise<unknown> | undefined;
    await writer.begin(async (tx) => {
      await tx`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${membershipRaceUserId}, 'membership-race-tenant', 'owner')`;
      writerFirstDeactivation = platform.begin(async (other) => {
        await other`SELECT set_config('steward.tenant_id', 'platform', true)`;
        await other`SELECT * FROM steward_bootstrap.platform_set_user_deactivation(
          ${membershipRaceUserId}::uuid, true
        )`;
      });
      await waitForAdvisoryWait(platformPid);
    });
    await expectDatabaseRejection(
      writerFirstDeactivation as Promise<unknown>,
      /Cannot deactivate the sole active tenant owner/,
    );

    await db`DELETE FROM user_tenants
      WHERE user_id = ${membershipRaceUserId} AND tenant_id = 'membership-race-tenant'`;
    let deactivationFirstWriter: Promise<unknown> | undefined;
    await platform.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
      await tx`SELECT * FROM steward_bootstrap.platform_set_user_deactivation(
        ${membershipRaceUserId}::uuid, true
      )`;
      deactivationFirstWriter = writer.begin(async (other) => {
        await other`INSERT INTO user_tenants (user_id,tenant_id,role)
          VALUES (${membershipRaceUserId}, 'membership-race-tenant', 'owner')`;
      });
      await waitForAdvisoryWait(writerPid);
    });
    await expectDatabaseRejection(
      deactivationFirstWriter as Promise<unknown>,
      /Inactive user cannot own a tenant/,
    );

    const deleteRaceUserId = randomUUID();
    const deleteRaceTenantId = `personal-${deleteRaceUserId}`;
    await db`INSERT INTO users (id,email,email_verified)
      VALUES (${deleteRaceUserId}, 'membership-delete-race@example.test', true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES (${deleteRaceTenantId}, 'Membership delete race', 'membership-delete-race-hash')`;

    let writerFirstDelete: Promise<unknown> | undefined;
    await writer.begin(async (tx) => {
      await tx`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${deleteRaceUserId}, ${deleteRaceTenantId}, 'owner')`;
      writerFirstDelete = deleter.begin(async (other) => {
        await other`SELECT * FROM public.steward_lock_personal_lifecycle(
          ${deleteRaceUserId}::uuid, ${deleteRaceTenantId}, true
        )`;
        await other`DELETE FROM tenants WHERE id = ${deleteRaceTenantId}`;
      });
      await waitForAdvisoryWait(deleterPid);
    });
    await writerFirstDelete;
    expect(await db`SELECT id FROM tenants WHERE id = ${deleteRaceTenantId}`).toHaveLength(0);

    await db`INSERT INTO tenants (id,name,api_key_hash)
      VALUES (${deleteRaceTenantId}, 'Membership delete race', 'membership-delete-race-hash-2')`;
    let deleteFirstWriter: Promise<unknown> | undefined;
    await deleter.begin(async (tx) => {
      await tx`SELECT * FROM public.steward_lock_personal_lifecycle(
        ${deleteRaceUserId}::uuid, ${deleteRaceTenantId}, true
      )`;
      await tx`DELETE FROM tenants WHERE id = ${deleteRaceTenantId}`;
      deleteFirstWriter = writer.begin(async (other) => {
        await other`INSERT INTO user_tenants (user_id,tenant_id,role)
          VALUES (${deleteRaceUserId}, ${deleteRaceTenantId}, 'owner')`;
      });
      await waitForAdvisoryWait(writerPid);
    });
    await expectDatabaseRejection(deleteFirstWriter as Promise<unknown>, /foreign key constraint/);

    await db`DELETE FROM tenants WHERE id = ${personalTenantId}`;
    const accountId = randomUUID();
    const workspaceId = randomUUID();
    const providerAccountId = randomUUID();
    const bindingId = randomUUID();
    const grantId = randomUUID();
    await db`INSERT INTO accounts (
      id,user_id,provider,provider_account_id,access_token_encrypted,refresh_token_encrypted
    ) VALUES (${accountId}, ${userId}, 'google', 'retained-google-subject', 'ciphertext', 'ciphertext')`;
    await db`INSERT INTO agents (id,tenant_id,name,wallet_address)
      VALUES ('provenance-agent', 'shared-provenance', 'Provenance', '0x1111111111111111111111111111111111111111')`;
    await db`INSERT INTO workspaces (id,tenant_id,key,name,environment,created_by)
      VALUES (${workspaceId}, 'shared-provenance', 'prod', 'Production', 'production', ${userId})`;
    await db`INSERT INTO provider_accounts (
      id,tenant_id,workspace_id,adapter_key,external_ref,display_name
    ) VALUES (${providerAccountId}, 'shared-provenance', ${workspaceId}, 'github', 'ref', 'GitHub')`;
    await db`INSERT INTO provider_role_bindings (
      id,tenant_id,principal_type,principal_id,role_key,granted_by_user_id,reason
    ) VALUES (${bindingId}, 'shared-provenance', 'human', ${otherOwnerId}, 'tenant_authority_admin', ${userId}, 'retained actor')`;
    await db`INSERT INTO provider_grants (
      id,tenant_id,workspace_id,provider_account_id,agent_id,operation_keys,expires_at,
      granted_by_user_id,reason,revoked_at,revoked_by_user_id,revocation_reason
    ) VALUES (
      ${grantId}, 'shared-provenance', ${workspaceId}, ${providerAccountId}, 'provenance-agent',
      ARRAY['github.issue.list'], now() + interval '1 hour', ${userId}, 'retained grant',
      now(), ${userId}, 'retained revoke'
    )`;

    await expectDatabaseRejection(
      platform.begin(async (tx) => {
        await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
        await tx`SELECT * FROM steward_bootstrap.platform_delete_user(${userId}::uuid)`;
        throw new Error("forced required audit failure");
      }),
      /forced required audit failure/,
    );
    expect(await db`SELECT id FROM users WHERE id = ${userId}`).toHaveLength(1);
    expect(await db`SELECT id FROM accounts WHERE id = ${accountId}`).toHaveLength(1);
    expect(
      await db`SELECT account_id FROM retained_user_provider_evidence WHERE account_id = ${accountId}`,
    ).toHaveLength(0);

    await platform.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
      await tx`SELECT * FROM steward_bootstrap.platform_delete_user(${userId}::uuid)`;
    });
    expect(await db`SELECT id FROM users WHERE id = ${userId}`).toHaveLength(0);
    expect(await db`SELECT id FROM accounts WHERE id = ${accountId}`).toHaveLength(0);
    expect(
      await db`SELECT deleted_user_id, provider, provider_account_id
      FROM retained_user_provider_evidence WHERE account_id = ${accountId}`,
    ).toEqual([
      {
        deleted_user_id: userId,
        provider: "google",
        provider_account_id: "retained-google-subject",
      },
    ]);
    expect(await db`SELECT created_by FROM workspaces WHERE id = ${workspaceId}`).toEqual([
      { created_by: userId },
    ]);
    expect(
      await db`SELECT granted_by_user_id FROM provider_role_bindings WHERE id = ${bindingId}`,
    ).toEqual([{ granted_by_user_id: userId }]);
    expect(
      await db`SELECT granted_by_user_id, revoked_by_user_id FROM provider_grants WHERE id = ${grantId}`,
    ).toEqual([{ granted_by_user_id: userId, revoked_by_user_id: userId }]);
    expect(
      await db`SELECT user_id, retired_at IS NOT NULL AS retired
        FROM user_identity_subjects WHERE user_id = ${userId}`,
    ).toEqual([{ user_id: userId, retired: true }]);
    await expectDatabaseRejection(
      db`INSERT INTO users (id,email,email_verified)
        VALUES (${userId}, 'forbidden-reuse@example.test', true)`,
      /Retired user identity cannot be reused/,
    );
    await expectDatabaseRejection(
      db`INSERT INTO workspaces (id,tenant_id,key,name,environment,created_by)
        VALUES (
          ${randomUUID()}, 'shared-provenance', 'invalid-actor', 'Invalid actor', 'production',
          ${randomUUID()}
        )`,
      /foreign key constraint/,
    );

    await platform.end();
    await appWriter.end();
    await writer.end();
    await deleter.end();
    await migrator.end();
    await db.end();
  });
});

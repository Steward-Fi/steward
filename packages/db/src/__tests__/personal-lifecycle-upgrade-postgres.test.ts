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
    const through0112 = journal.entries.filter((entry) => entry.idx <= 112);
    const migrationArgs = ["psql", "--no-psqlrc", "--dbname", databaseUrl()];
    for (const entry of through0112) {
      migrationArgs.push("-f", `${migrationsRoot}${entry.tag}.sql`);
    }
    await command(migrationArgs);

    const db = postgres(databaseUrl(), { max: 1 });
    await db`CREATE SCHEMA IF NOT EXISTS drizzle`;
    await db`CREATE TABLE drizzle.__drizzle_migrations (
      id serial PRIMARY KEY, hash text NOT NULL, created_at bigint
    )`;
    for (const entry of through0112) {
      await db`INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
        VALUES (${migrationHash(entry.tag)}, ${entry.when})`;
    }

    await command(operatorArgs("scripts/postgres/rls-bootstrap.sql"));
    await admin.unsafe(`ALTER ROLE ${migrationRole} PASSWORD '${rolePassword}'`);
    await admin.unsafe(`ALTER ROLE ${platformRole} PASSWORD '${rolePassword}'`);

    // 0113 is deliberately ordinary SQL and succeeds as the restricted owner.
    await command(
      operatorArgs(`${migrationsRoot}0113_personal_tenant_account_lifecycle.sql`, migrationRole),
    );
    const entry0113 = journal.entries.find((entry) => entry.idx === 113) as JournalEntry;
    const migrator = postgres(databaseUrl(databaseName, migrationRole), { max: 1 });
    await migrator`INSERT INTO drizzle.__drizzle_migrations (hash, created_at)
      VALUES (${migrationHash(entry0113.tag)}, ${entry0113.when})`;

    const [beforeUpgrade] = await db<{ owner: string; acl: string | null }[]>`
      SELECT pg_get_userbyid(p.proowner) AS owner, p.proacl::text AS acl
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'steward_bootstrap' AND p.proname = 'platform_delete_user'
    `;
    expect(beforeUpgrade?.owner).toBe(bootstrapRole);
    await command(operatorArgs("scripts/postgres/rls-upgrade-personal-lifecycle.sql"));
    await command(operatorArgs("scripts/postgres/rls-upgrade-personal-lifecycle.sql"));

    const [afterUpgrade] = await db<{ owner: string; acl: string | null }[]>`
      SELECT pg_get_userbyid(p.proowner) AS owner, p.proacl::text AS acl
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'steward_bootstrap' AND p.proname = 'platform_delete_user'
    `;
    expect(afterUpgrade).toEqual(beforeUpgrade);

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
    await command(operatorArgs("scripts/postgres/rls-activate.sql"));

    const [lockPrivileges] = await db<
      {
        app: boolean;
        app_wrapper: boolean;
        bootstrap: boolean;
        platform: boolean;
        platform_wrapper: boolean;
        platform_tenants_select: boolean;
        platform_memberships_select: boolean;
      }[]
    >`
      SELECT
        has_function_privilege(${appRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS app,
        has_function_privilege(${appRole}, 'steward_bootstrap.platform_personal_tenant_delete(text,boolean)', 'EXECUTE') AS app_wrapper,
        has_function_privilege(${bootstrapRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS bootstrap,
        has_function_privilege(${platformRole}, 'public.steward_lock_personal_lifecycle(uuid,text,boolean)', 'EXECUTE') AS platform,
        has_function_privilege(${platformRole}, 'steward_bootstrap.platform_personal_tenant_delete(text,boolean)', 'EXECUTE') AS platform_wrapper,
        has_table_privilege(${platformRole}, 'public.tenants', 'SELECT') AS platform_tenants_select,
        has_table_privilege(${platformRole}, 'public.user_tenants', 'SELECT') AS platform_memberships_select
    `;
    expect(lockPrivileges).toEqual({
      app: false,
      app_wrapper: false,
      bootstrap: true,
      platform: false,
      platform_wrapper: true,
      platform_tenants_select: false,
      platform_memberships_select: false,
    });
    const functions = await db<
      { name: string; owner: string; security_definer: boolean; config: string[] | null }[]
    >`
      SELECT p.proname AS name, pg_get_userbyid(p.proowner) AS owner,
        p.prosecdef AS security_definer, p.proconfig AS config
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE (n.nspname = 'public' AND p.proname = 'steward_platform_personal_tenant_delete_v2')
         OR (n.nspname = 'steward_bootstrap' AND p.proname = 'platform_personal_tenant_delete')
      ORDER BY n.nspname
    `;
    expect(functions).toEqual([
      {
        name: "steward_platform_personal_tenant_delete_v2",
        owner: migrationRole,
        security_definer: true,
        config: ["search_path=pg_catalog"],
      },
      {
        name: "platform_personal_tenant_delete",
        owner: bootstrapRole,
        security_definer: true,
        config: ["search_path=pg_catalog"],
      },
    ]);

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

    const mountedSharedTenantId = `mounted-shared-${suffix}`;
    const mountedSharedOwnerId = randomUUID();
    const mountedOtherOwnerId = randomUUID();
    const mountedDeleteUserId = randomUUID();
    const mountedDeleteTenantId = `personal-${mountedDeleteUserId}`;
    await db`INSERT INTO users (id,email,email_verified) VALUES
      (${mountedSharedOwnerId}, ${`mounted-owner-${suffix}@example.test`}, true),
      (${mountedOtherOwnerId}, ${`mounted-other-${suffix}@example.test`}, true),
      (${mountedDeleteUserId}, ${`mounted-delete-${suffix}@example.test`}, true)`;
    await db`INSERT INTO tenants (id,name,api_key_hash) VALUES
      (${mountedSharedTenantId}, 'Mounted shared lifecycle', ${`mounted-shared-${suffix}`}),
      (${mountedDeleteTenantId}, 'Mounted personal deletion', ${`mounted-delete-${suffix}`})`;
    await db`INSERT INTO user_tenants (user_id,tenant_id,role) VALUES
      (${mountedSharedOwnerId}, ${mountedSharedTenantId}, 'owner'),
      (${mountedOtherOwnerId}, ${mountedSharedTenantId}, 'owner'),
      (${mountedDeleteUserId}, ${mountedDeleteTenantId}, 'owner')`;
    await db`INSERT INTO tenant_configs (tenant_id,email_config)
      VALUES (${mountedDeleteTenantId}, ${db.json({ from: "personal@example.test" })})`;
    const platformKey = `mounted-platform-${suffix}`;
    const mountedOutput = await command(
      ["bun", "run", "packages/api/src/__tests__/fixtures/personal-lifecycle-split-routes.ts"],
      {
        DATABASE_URL: databaseUrl(databaseName, appRole),
        STEWARD_PLATFORM_DATABASE_URL: databaseUrl(databaseName, platformRole),
        STEWARD_PLATFORM_DATABASE_ROLE: platformRole,
        STEWARD_PLATFORM_KEYS: platformKey,
        STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({
          [platformKey]: [
            "platform:write",
            "platform:user-lifecycle:write",
            "platform:user:delete",
            "platform:tenant:delete",
            "platform:tenant-email-config:write",
          ],
        }),
        STEWARD_JWT_SECRET: "mounted-split-role-jwt-secret-with-enough-entropy",
        STEWARD_AUDIT_HMAC_KEY: "mounted-split-role-audit-hmac-key-with-enough-entropy",
        STEWARD_MASTER_PASSWORD: "mounted-split-role-master-password",
        TEST_ADMIN_DATABASE_URL: databaseUrl(),
        TEST_SHARED_TENANT_ID: mountedSharedTenantId,
        TEST_SHARED_OWNER_ID: mountedSharedOwnerId,
        TEST_PERSONAL_DELETE_TENANT_ID: mountedDeleteTenantId,
        TEST_PERSONAL_DELETE_USER_ID: mountedDeleteUserId,
        TEST_PLATFORM_KEY: platformKey,
      },
    );
    expect(mountedOutput).toContain("mounted split-role lifecycle routes passed");

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

    await expectDatabaseRejection(
      db`INSERT INTO user_tenants (user_id,tenant_id,role)
        VALUES (${otherOwnerId}, ${personalTenantId}, 'member')`,
      /Personal tenant membership is immutable/,
    );
    await expectDatabaseRejection(
      db`INSERT INTO tenant_invitations
        (tenant_id,email,role,token_hash,invited_by_user_id,expires_at)
        VALUES (${personalTenantId}, 'blocked@example.test', 'member', 'blocked-hash', ${userId}, now() + interval '1 hour')`,
      /Personal tenant invitations are forbidden/,
    );

    const writer = postgres(databaseUrl(), { max: 1 });
    const deleter = postgres(databaseUrl(), { max: 1 });
    const waitBlocked = async (promise: Promise<unknown>) =>
      Promise.race([promise.then(() => "completed"), Bun.sleep(150).then(() => "blocked")]);

    let writerFirstCompeting: Promise<unknown> | undefined;
    await writer.begin(async (tx) => {
      await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
      await tx`SELECT * FROM steward_bootstrap.platform_set_user_deactivation(${userId}::uuid, true)`;
      writerFirstCompeting = deleter.begin(async (other) => {
        await other`SELECT * FROM public.steward_lock_personal_lifecycle(
          ${userId}::uuid, ${personalTenantId}, true
        )`;
      });
      expect(await waitBlocked(writerFirstCompeting)).toBe("blocked");
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
      expect(await waitBlocked(deleterFirstCompeting)).toBe("blocked");
    });
    await deleterFirstCompeting;

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

    const platform = postgres(databaseUrl(databaseName, platformRole), { max: 1 });
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

    await platform.end();
    await writer.end();
    await deleter.end();
    await migrator.end();
    await db.end();
  });
});

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";
import { createDb } from "../client";
import {
  assertPlatformDatabaseAuthority,
  assertRlsDeploymentSafety,
} from "../rls-deployment-safety";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
setDefaultTimeout(180_000);

const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
const databaseName = `steward_rls_${suffix}`;
const appRole = `steward_app_${suffix}`;
const migrationRole = `steward_migrator_${suffix}`;
const definerRole = `steward_definer_${suffix}`;
const platformRole = `steward_platform_${suffix}`;
const appRolePassword = randomUUID().replaceAll("-", "");
const migrationRolePassword = randomUUID().replaceAll("-", "");
const platformRolePassword = randomUUID().replaceAll("-", "");

function databaseUrl(database: string): string {
  const url = new URL(process.env.DATABASE_URL as string);
  url.pathname = `/${database}`;
  return url.toString();
}

function appDatabaseUrl(): string {
  const url = new URL(databaseUrl(databaseName));
  url.username = appRole;
  url.password = appRolePassword;
  return url.toString();
}

function platformDatabaseUrl(): string {
  const url = new URL(databaseUrl(databaseName));
  url.username = platformRole;
  url.password = platformRolePassword;
  return url.toString();
}

function migrationDatabaseUrl(): string {
  const url = new URL(databaseUrl(databaseName));
  url.username = migrationRole;
  url.password = migrationRolePassword;
  return url.toString();
}

async function runCommand(command: string[], env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn(command, {
    cwd: new URL("../../../../", import.meta.url).pathname,
    env: { ...process.env, ...env },
    stdout: "pipe",
    stderr: "pipe",
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ]);
  if (exitCode !== 0) {
    throw new Error(`operator command failed (${exitCode}): ${stderr || stdout}`);
  }
  return stdout;
}

async function runOperatorScript(name: string, includeRoles = false) {
  const command = ["psql", "--no-psqlrc", "--dbname", databaseUrl(databaseName)];
  if (includeRoles) {
    command.push(
      "-v",
      `steward_app_role=${appRole}`,
      "-v",
      `steward_migration_role=${migrationRole}`,
      "-v",
      `steward_bootstrap_role=${definerRole}`,
      "-v",
      `steward_platform_role=${platformRole}`,
    );
  } else if (name === "rls-activate.sql") {
    command.push(
      "-v",
      `steward_app_role=${appRole}`,
      "-v",
      `steward_migration_role=${migrationRole}`,
      "-v",
      `steward_platform_role=${platformRole}`,
      "-v",
      `steward_bootstrap_role=${definerRole}`,
    );
  }
  command.push("-f", `scripts/postgres/${name}`);
  return runCommand(command);
}

describeWithPostgres("SEC-169 operator lifecycle on the real Steward schema", () => {
  const admin = postgres(process.env.DATABASE_URL as string, { max: 1 });

  afterAll(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${appRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${migrationRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${definerRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${platformRole}`);
    await admin.end();
  });

  test("bootstraps, activates, rolls back, reactivates, and reruns the migrator", async () => {
    const [adminRole] = await admin<{ rolsuper: boolean }[]>`
      SELECT rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    expect(adminRole?.rolsuper).toBe(true);
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);

    const firstMigration = await runCommand(["bun", "run", "packages/db/src/migrate.ts"], {
      DATABASE_URL: databaseUrl(databaseName),
    });
    expect(firstMigration).toContain("0114_personal_lifecycle_invariants");

    const db = postgres(databaseUrl(databaseName), { max: 1 });
    try {
      const [installed] = await db<{ relations: number; policies: number }[]>`
        SELECT count(DISTINCT c.relname)::int AS relations, count(*)::int AS policies
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
      `;
      expect(installed).toEqual({ relations: 71, policies: 73 });

      await runOperatorScript("rls-bootstrap.sql", true);
      await runOperatorScript("rls-upgrade-personal-lifecycle.sql", true);
      await admin.unsafe(`ALTER ROLE ${appRole} PASSWORD '${appRolePassword}'`);
      await admin.unsafe(`ALTER ROLE ${migrationRole} PASSWORD '${migrationRolePassword}'`);
      await admin.unsafe(`ALTER ROLE ${platformRole} PASSWORD '${platformRolePassword}'`);

      // Core upgrades intentionally retain the database-owner/operator URL:
      // core migrations can replace the non-login definer's ABI, while the
      // restricted plugin migrator cannot mutate that privileged schema.
      const postSplitCore = await runCommand(
        ["bun", "run", "packages/api/scripts/migrate-production.ts", "core"],
        {
          DATABASE_URL: databaseUrl(databaseName),
          MIGRATION_DATABASE_URL: databaseUrl(databaseName),
        },
      );
      expect(postSplitCore).toContain('"phase":"core"');
      const restricted = postgres(migrationDatabaseUrl(), { max: 1 });
      try {
        let restrictedUpgradeError: unknown;
        try {
          await restricted.unsafe(`
            CREATE OR REPLACE FUNCTION steward_bootstrap.platform_stats()
            RETURNS TABLE (tenant_count bigint, agent_count bigint, transaction_count bigint)
            LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $$
              SELECT
                (SELECT count(*) FROM public.tenants),
                (SELECT count(*) FROM public.agents),
                (SELECT count(*) FROM public.transactions)
            $$
          `);
        } catch (error) {
          restrictedUpgradeError = error;
        }
        expect(restrictedUpgradeError).toMatchObject({ code: "42501" });
      } finally {
        await restricted.end();
      }

      // This is a real post-split schema upgrade through the restricted
      // plugin migrator login—not an owner connection that merely reports up to date.
      const pluginMigration = await runCommand(
        ["bun", "run", "packages/api/scripts/migrate-production.ts", "plugins"],
        {
          DATABASE_URL: migrationDatabaseUrl(),
          MIGRATION_DATABASE_URL: migrationDatabaseUrl(),
          STEWARD_PLUGINS: "capabilities",
          STEWARD_MASTER_PASSWORD: "test-restricted-migrator-master-password",
          STEWARD_AUDIT_HMAC_KEY:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          STEWARD_KDF_SALT: "0123456789abcdef0123456789abcdef",
        },
      );
      expect(pluginMigration).toContain('"pluginName":"capabilities"');
      const roleRows = await db<
        {
          rolname: string;
          rolcanlogin: boolean;
          rolbypassrls: boolean;
          rolreplication: boolean;
          rolsuper: boolean;
        }[]
      >`
        SELECT rolname, rolcanlogin, rolbypassrls, rolreplication, rolsuper
        FROM pg_roles WHERE rolname IN (${appRole}, ${migrationRole}, ${definerRole}, ${platformRole})
        ORDER BY rolname
      `;
      expect(roleRows).toHaveLength(4);
      expect(roleRows.find((row) => row.rolname === appRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolreplication: false,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === migrationRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolreplication: false,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === definerRole)).toMatchObject({
        rolcanlogin: false,
        rolbypassrls: true,
        rolreplication: false,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === platformRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolreplication: false,
        rolsuper: false,
      });
      const [platformRlsPrivileges] = await db<
        {
          schema_usage: boolean;
          tenant_id_execute: boolean;
          user_id_execute: boolean;
          public_lock_execute: boolean;
          audit_sequence_usage: boolean;
          other_sequence_usage: boolean;
          default_sequence_grant: boolean;
        }[]
      >`
        SELECT
          has_schema_privilege(${platformRole}, 'steward_rls', 'USAGE') AS schema_usage,
          has_function_privilege(${platformRole}, 'steward_rls.tenant_id()', 'EXECUTE') AS tenant_id_execute,
          has_function_privilege(${platformRole}, 'steward_rls.user_id()', 'EXECUTE') AS user_id_execute,
          has_function_privilege(${platformRole}, 'public.steward_lock_tenant_deletion(text)', 'EXECUTE') AS public_lock_execute,
          has_sequence_privilege(${platformRole}, 'public.audit_events_id_seq', 'USAGE,SELECT') AS audit_sequence_usage,
          has_sequence_privilege(${platformRole}, 'public.audit_checkpoints_id_seq', 'USAGE') AS other_sequence_usage,
          EXISTS (
            SELECT 1
            FROM pg_default_acl defaults
            CROSS JOIN LATERAL aclexplode(defaults.defaclacl) privilege
            JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
            WHERE defaults.defaclobjtype = 'S' AND granted_role.rolname = ${platformRole}
          ) AS default_sequence_grant
      `;
      expect(platformRlsPrivileges).toEqual({
        schema_usage: true,
        tenant_id_execute: true,
        user_id_execute: false,
        public_lock_execute: false,
        audit_sequence_usage: true,
        other_sequence_usage: false,
        default_sequence_grant: false,
      });

      const expectedPlatformAcls = [
        "function:steward_bootstrap.platform_delete_user(p_user_id uuid):EXECUTE:false",
        "function:steward_bootstrap.platform_revoke_user_refresh_tokens(p_user_id uuid):EXECUTE:false",
        "function:steward_bootstrap.platform_set_user_deactivation(p_user_id uuid, p_deactivated boolean):EXECUTE:false",
        "function:steward_bootstrap.platform_stats():EXECUTE:false",
        "function:steward_bootstrap.platform_tenants(p_limit integer, p_offset integer):EXECUTE:false",
        "function:steward_bootstrap.retention_delete_deactivated_users(p_days integer):EXECUTE:false",
        "function:steward_rls.tenant_id():EXECUTE:false",
        "relation:public.audit_chain_heads:INSERT:false",
        "relation:public.audit_chain_heads:SELECT:false",
        "relation:public.audit_chain_heads:UPDATE:false",
        "relation:public.audit_events:INSERT:false",
        "relation:public.audit_events:SELECT:false",
        "relation:public.audit_events_id_seq:SELECT:false",
        "relation:public.audit_events_id_seq:USAGE:false",
        "schema:steward_bootstrap:USAGE:false",
        "schema:steward_rls:USAGE:false",
      ];
      const platformNamedAcls = async () => {
        const rows = await db<{ acl: string }[]>`
          SELECT 'schema:' || namespace.nspname || ':' || privilege.privilege_type || ':' ||
            privilege.is_grantable AS acl
          FROM pg_namespace namespace
          CROSS JOIN LATERAL aclexplode(namespace.nspacl) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE granted_role.rolname = ${platformRole}
          UNION ALL
          SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
            privilege.privilege_type || ':' || privilege.is_grantable AS acl
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL aclexplode(relation.relacl) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
            AND granted_role.rolname = ${platformRole}
          UNION ALL
          SELECT 'function:' || namespace.nspname || '.' || function_object.proname || '(' ||
            pg_get_function_identity_arguments(function_object.oid) || '):' ||
            privilege.privilege_type || ':' || privilege.is_grantable AS acl
          FROM pg_proc function_object
          JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
          CROSS JOIN LATERAL aclexplode(function_object.proacl) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE granted_role.rolname = ${platformRole}
          ORDER BY acl
        `;
        return rows.map((row) => row.acl);
      };
      expect(await platformNamedAcls()).toEqual(expectedPlatformAcls);

      const [connectPosture] = await db<
        {
          app_connect: boolean;
          migration_connect: boolean;
          platform_connect: boolean;
          public_connect: boolean;
        }[]
      >`
        SELECT
          has_database_privilege(${appRole}, current_database(), 'CONNECT') AS app_connect,
          has_database_privilege(${migrationRole}, current_database(), 'CONNECT') AS migration_connect,
          has_database_privilege(${platformRole}, current_database(), 'CONNECT') AS platform_connect,
          EXISTS (
            SELECT 1 FROM pg_database database_object
            CROSS JOIN LATERAL aclexplode(
              COALESCE(database_object.datacl, acldefault('d', database_object.datdba))
            ) privilege
            WHERE database_object.datname = current_database()
              AND privilege.grantee = 0 AND privilege.privilege_type = 'CONNECT'
          ) AS public_connect
      `;
      expect(connectPosture).toEqual({
        app_connect: true,
        migration_connect: true,
        platform_connect: true,
        public_connect: false,
      });

      await expect(
        db.begin(async (tx) => {
          await tx.unsafe(`SET LOCAL ROLE ${appRole}`);
          return tx.unsafe("SELECT * FROM steward_bootstrap.platform_stats()");
        }),
      ).rejects.toMatchObject({ code: "42501" });
      const [platformStats] = await db.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE ${platformRole}`);
        return tx<{ tenant_count: number }[]>`
          SELECT tenant_count::int FROM steward_bootstrap.platform_stats()
        `;
      });
      expect(platformStats?.tenant_count).toBeGreaterThanOrEqual(0);

      await db.unsafe(`
        CREATE FUNCTION steward_bootstrap.unknown_authority_probe()
        RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'
      `);
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "bootstrap SECURITY DEFINER inventory drift",
        );
      } finally {
        await db.unsafe("DROP FUNCTION steward_bootstrap.unknown_authority_probe()");
      }

      await db.unsafe(`GRANT USAGE ON SCHEMA public TO ${platformRole}`);
      await db.unsafe(`GRANT UPDATE ON public.audit_events TO ${platformRole} WITH GRANT OPTION`);
      await db.unsafe(`GRANT USAGE ON SEQUENCE public.audit_checkpoints_id_seq TO ${platformRole}`);
      await db.unsafe(
        `GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_stats() TO ${platformRole} WITH GRANT OPTION`,
      );
      await admin.unsafe(`ALTER ROLE ${platformRole} WITH REPLICATION`);
      await runOperatorScript("rls-bootstrap.sql", true);
      expect(await platformNamedAcls()).toEqual(expectedPlatformAcls);
      const [resetPlatformRole] = await db<{ rolreplication: boolean }[]>`
        SELECT rolreplication FROM pg_roles WHERE rolname = ${platformRole}
      `;
      expect(resetPlatformRole).toEqual({ rolreplication: false });

      await db.unsafe(
        "CREATE PROCEDURE public.platform_authority_probe() LANGUAGE SQL AS 'SELECT 1'",
      );
      await db.unsafe(
        `GRANT EXECUTE ON PROCEDURE public.platform_authority_probe() TO ${platformRole}`,
      );
      await runOperatorScript("rls-bootstrap.sql", true);
      const [procedureAccess] = await db<{ can_execute: boolean }[]>`
        SELECT has_function_privilege(
          ${platformRole}, 'public.platform_authority_probe()'::regprocedure, 'EXECUTE'
        ) AS can_execute
      `;
      expect(procedureAccess).toEqual({ can_execute: false });
      await db.unsafe("DROP PROCEDURE public.platform_authority_probe()");

      await admin.unsafe(`GRANT CONNECT ON DATABASE postgres TO ${platformRole}`);
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "platform database ACL drift",
        );
      } finally {
        await admin.unsafe(`REVOKE CONNECT ON DATABASE postgres FROM ${platformRole}`);
      }

      await admin.unsafe(`GRANT ${definerRole} TO ${platformRole}`);
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "platform role must not inherit, assume, or be assumable by another role",
        );
      } finally {
        await admin.unsafe(`REVOKE ${definerRole} FROM ${platformRole}`);
      }

      await db.unsafe("CREATE SEQUENCE public.platform_owned_authority_probe");
      await db.unsafe(
        `ALTER SEQUENCE public.platform_owned_authority_probe OWNER TO ${platformRole}`,
      );
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "platform role must not own database objects",
        );
      } finally {
        await db.unsafe("DROP SEQUENCE public.platform_owned_authority_probe");
      }
      await runOperatorScript("rls-bootstrap.sql", true);
      expect(await platformNamedAcls()).toEqual(expectedPlatformAcls);

      await runOperatorScript("rls-activate.sql");
      const [activated] = await db<{ enabled: number; forced: number; maintenance: number }[]>`
        SELECT
          count(DISTINCT c.oid) FILTER (WHERE c.relrowsecurity)::int AS enabled,
          count(DISTINCT c.oid) FILTER (WHERE c.relforcerowsecurity)::int AS forced,
          count(*) FILTER (WHERE p.polname = 'steward_migration_maintenance')::int AS maintenance
        FROM pg_policy p
        JOIN pg_class c ON c.oid = p.polrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND p.polname LIKE 'steward_%'
      `;
      // Retained provider evidence is permanently forced with no app policy,
      // so it is intentionally absent from the 71 policy-bearing relations.
      expect(activated).toEqual({ enabled: 71, forced: 71, maintenance: 71 });

      // Exercise the same load-bearing runtime gates used by the API and proxy
      // through their real restricted login connections. This catches query
      // binding errors that source assertions and mocked executors cannot.
      const appHandle = createDb(appDatabaseUrl());
      try {
        await assertRlsDeploymentSafety(appHandle.db, {
          expectedRole: appRole,
          expectedPlatformRole: platformRole,
          expectedBootstrapRole: definerRole,
          expectedMigrationRole: migrationRole,
        });
      } finally {
        await appHandle.client.end({ timeout: 5 });
      }
      const platformHandle = createDb(platformDatabaseUrl());
      try {
        await assertPlatformDatabaseAuthority(platformHandle.db, platformRole);
      } finally {
        await platformHandle.client.end({ timeout: 5 });
      }

      await db`ALTER FUNCTION steward_bootstrap.platform_stats() VOLATILE`;
      const driftedApp = createDb(appDatabaseUrl());
      try {
        await expect(
          assertRlsDeploymentSafety(driftedApp.db, {
            expectedRole: appRole,
            expectedPlatformRole: platformRole,
            expectedBootstrapRole: definerRole,
            expectedMigrationRole: migrationRole,
          }),
        ).rejects.toThrow("RLS_DEPLOYMENT_FUNCTION_DEFINITION_DRIFT");
        await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
          "privileged function semantic manifest drift",
        );
      } finally {
        await driftedApp.client.end({ timeout: 5 });
        await db`ALTER FUNCTION steward_bootstrap.platform_stats() STABLE`;
      }

      await db.unsafe(`
        CREATE FUNCTION public.steward_test_unknown_definer_${suffix}()
        RETURNS integer LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog
        AS 'SELECT 1'
      `);
      await db.unsafe(
        `REVOKE ALL ON FUNCTION public.steward_test_unknown_definer_${suffix}() FROM PUBLIC`,
      );
      await db.unsafe(
        `GRANT EXECUTE ON FUNCTION public.steward_test_unknown_definer_${suffix}() TO ${appRole}`,
      );
      const hostileDefinerApp = createDb(appDatabaseUrl());
      try {
        await expect(
          assertRlsDeploymentSafety(hostileDefinerApp.db, {
            expectedRole: appRole,
            expectedPlatformRole: platformRole,
            expectedBootstrapRole: definerRole,
            expectedMigrationRole: migrationRole,
          }),
        ).rejects.toThrow("RLS_DEPLOYMENT_UNKNOWN_EXECUTABLE_SECURITY_DEFINER");
        await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
          "unknown executable public SECURITY DEFINER function",
        );
      } finally {
        await hostileDefinerApp.client.end({ timeout: 5 });
        await db.unsafe(`DROP FUNCTION public.steward_test_unknown_definer_${suffix}()`);
      }

      const refreshUserId = randomUUID();
      const sourceTenant = `source-${suffix}`;
      const targetTenant = `target-${suffix}`;
      const sourceHash = `source-hash-${suffix}`;
      await db`
        INSERT INTO public.tenants(id, name, api_key_hash) VALUES
          (${sourceTenant}, 'RLS source', ${`source-key-${suffix}`}),
          (${targetTenant}, 'RLS target', ${`target-key-${suffix}`})
      `;
      await db`
        INSERT INTO public.users(id, email) VALUES
          (${refreshUserId}::uuid, ${`${suffix}@example.test`})
      `;
      await db`
        INSERT INTO public.user_tenants(user_id, tenant_id, role) VALUES
          (${refreshUserId}::uuid, ${sourceTenant}, 'member'),
          (${refreshUserId}::uuid, ${targetTenant}, 'member')
      `;
      await db`
        INSERT INTO public.refresh_tokens(id, user_id, tenant_id, token_hash, expires_at)
        VALUES (${`source-id-${suffix}`}, ${refreshUserId}::uuid, ${sourceTenant}, ${sourceHash}, now() + interval '1 day')
      `;

      const deniedRotation = await db.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE ${appRole}`);
        return tx`
          SELECT * FROM steward_bootstrap.auth_rotate_refresh_token(
            ${sourceHash}, ${targetTenant}, ${`denied-id-${suffix}`},
            ${`denied-hash-${suffix}`}, now() + interval '1 day'
          )
        `;
      });
      expect(deniedRotation).toHaveLength(0);

      const allowedRotation = await db.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE ${appRole}`);
        await tx`SELECT set_config('steward.tenant_id', ${sourceTenant}, true)`;
        await tx`SELECT set_config('steward.user_id', ${refreshUserId}, true)`;
        return tx`
          SELECT * FROM steward_bootstrap.auth_rotate_refresh_token(
            ${sourceHash}, ${targetTenant}, ${`successor-id-${suffix}`},
            ${`successor-hash-${suffix}`}, now() + interval '1 day'
          )
        `;
      });
      expect(allowedRotation).toHaveLength(1);
      expect(allowedRotation[0]).toMatchObject({
        user_id: refreshUserId,
        tenant_id: targetTenant,
      });

      const soleOwnerId = randomUUID();
      await db`
        INSERT INTO public.users(id, email) VALUES
          (${soleOwnerId}::uuid, ${`sole-owner-${suffix}@example.test`})
      `;
      await db`
        INSERT INTO public.user_tenants(user_id, tenant_id, role)
        VALUES (${soleOwnerId}::uuid, ${sourceTenant}, 'owner')
      `;
      await expect(
        db.begin(async (tx) => {
          await tx.unsafe(`SET LOCAL ROLE ${appRole}`);
          await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
          await tx`
            SELECT * FROM steward_bootstrap.platform_set_user_deactivation(
              ${soleOwnerId}::uuid,
              true
            )
          `;
        }),
      ).rejects.toThrow(/permission denied/i);
      await expect(
        db.begin(async (tx) => {
          await tx.unsafe(`SET LOCAL ROLE ${platformRole}`);
          await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
          await tx`
            SELECT * FROM steward_bootstrap.platform_set_user_deactivation(
              ${soleOwnerId}::uuid,
              true
            )
          `;
        }),
      ).rejects.toThrow("Cannot deactivate the sole active tenant owner");

      const personalOwnerId = randomUUID();
      const personalTenant = `personal-${personalOwnerId}`;
      await db`
        INSERT INTO public.tenants(id, name, api_key_hash)
        VALUES (${personalTenant}, 'Personal lifecycle owner', ${`personal-key-${suffix}`})
      `;
      await db`
        INSERT INTO public.users(id, email)
        VALUES (${personalOwnerId}::uuid, ${`personal-owner-${suffix}@example.test`})
      `;
      await db`
        INSERT INTO public.user_tenants(user_id, tenant_id, role)
        VALUES (${personalOwnerId}::uuid, ${personalTenant}, 'owner')
      `;
      const personalDeactivation = await db.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE ${platformRole}`);
        await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
        return tx`
          SELECT user_id, deactivated_at
          FROM steward_bootstrap.platform_set_user_deactivation(
            ${personalOwnerId}::uuid,
            true
          )
        `;
      });
      expect(personalDeactivation).toHaveLength(1);
      expect(personalDeactivation[0]?.user_id).toBe(personalOwnerId);
      expect(personalDeactivation[0]?.deactivated_at).toBeInstanceOf(Date);

      for (const extraRole of ["member", "owner"] as const) {
        const malformedOwnerId = randomUUID();
        const malformedExtraId = randomUUID();
        const malformedTenant = `personal-${malformedOwnerId}`;
        await db`
          INSERT INTO public.tenants(id, name, api_key_hash)
          VALUES (
            ${malformedTenant},
            ${`Malformed personal ${extraRole}`},
            ${`malformed-personal-${extraRole}-${suffix}`}
          )
        `;
        await db`
          INSERT INTO public.users(id, email)
          VALUES
            (${malformedOwnerId}::uuid, ${`malformed-${extraRole}-owner-${suffix}@example.test`}),
            (${malformedExtraId}::uuid, ${`malformed-${extraRole}-extra-${suffix}@example.test`})
        `;
        await db`ALTER TABLE public.user_tenants DISABLE TRIGGER user_tenants_personal_authority_guard`;
        try {
          await db`
            INSERT INTO public.user_tenants(user_id, tenant_id, role)
            VALUES
              (${malformedOwnerId}::uuid, ${malformedTenant}, 'owner'),
              (${malformedExtraId}::uuid, ${malformedTenant}, ${extraRole})
          `;
        } finally {
          await db`ALTER TABLE public.user_tenants ENABLE TRIGGER user_tenants_personal_authority_guard`;
        }
        await db`
          INSERT INTO public.refresh_tokens(id, user_id, tenant_id, token_hash, expires_at)
          VALUES (
            ${`malformed-personal-${extraRole}-${suffix}`},
            ${malformedOwnerId},
            ${malformedTenant},
            ${`malformed-personal-${extraRole}-refresh-${suffix}`},
            now() + interval '1 hour'
          )
        `;

        await expect(
          db.begin(async (tx) => {
            await tx.unsafe(`SET LOCAL ROLE ${platformRole}`);
            await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
            await tx`
              SELECT *
              FROM steward_bootstrap.platform_set_user_deactivation(
                ${malformedOwnerId}::uuid,
                true
              )
            `;
          }),
        ).rejects.toThrow("Personal tenant membership invariant violated");

        await expect(
          db.begin(async (tx) => {
            await tx.unsafe(`SET LOCAL ROLE ${platformRole}`);
            await tx`SELECT set_config('steward.tenant_id', 'platform', true)`;
            await tx`
              SELECT *
              FROM steward_bootstrap.platform_delete_user(${malformedOwnerId}::uuid)
            `;
          }),
        ).rejects.toThrow("Personal tenant membership invariant violated");

        const [unchangedUser] = await db<{ deactivated_at: Date | null }[]>`
          SELECT deactivated_at
          FROM public.users
          WHERE id = ${malformedOwnerId}::uuid
        `;
        expect(unchangedUser?.deactivated_at).toBeNull();
        const [refreshEvidence] = await db<{ count: number }[]>`
          SELECT count(*)::int AS count
          FROM public.refresh_tokens
          WHERE user_id = ${malformedOwnerId}
        `;
        expect(refreshEvidence?.count).toBe(1);
      }

      const platformKey = `rls-platform-key-${suffix}`;
      const appRoleEvidence = await runCommand(
        ["bun", "run", "packages/api/src/__tests__/fixtures/rls-app-role-exercise.ts"],
        {
          DATABASE_URL: appDatabaseUrl(),
          DATABASE_DRIVER: "postgres-js",
          STEWARD_PLATFORM_DATABASE_URL: platformDatabaseUrl(),
          STEWARD_PLATFORM_DATABASE_ROLE: platformRole,
          STEWARD_BOOTSTRAP_DATABASE_ROLE: definerRole,
          NODE_ENV: "test",
          APP_URL: "https://steward.test",
          JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
          STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
          STEWARD_AUDIT_HMAC_KEY: "ab".repeat(32),
          STEWARD_DEFAULT_TENANT_KEY: `default-key-${suffix}`,
          STEWARD_MASTER_PASSWORD: `rls-master-password-${suffix}`,
          STEWARD_PLATFORM_KEYS: platformKey,
          STEWARD_PLATFORM_KEY_SCOPES: JSON.stringify({ [platformKey]: ["platform:*"] }),
          STEWARD_RLS_TEST_TENANT: targetTenant,
          STEWARD_RLS_TEST_SUFFIX: suffix,
          STEWARD_REDIS_REQUIRED: "false",
          STEWARD_ALLOW_INSECURE_AUTH_STORES: "true",
          STEWARD_RETENTION_DEACTIVATED_USERS_DAYS: undefined,
          STEWARD_RETENTION_DEACTIVATED_USERS_DELETE_CONFIRMED: undefined,
        },
      );
      const evidenceLine = appRoleEvidence
        .trim()
        .split("\n")
        .findLast((line) => line.startsWith('{"ok":true'));
      expect(evidenceLine).toBeDefined();
      const evidence = JSON.parse(evidenceLine as string) as {
        ok: boolean;
        platformAuditActions: string[];
      };
      expect(evidence.ok).toBe(true);
      expect(evidence.platformAuditActions).toEqual([
        "user.deactivate",
        "user.deactivate.authorized",
      ]);

      await runOperatorScript("rls-rollback.sql");
      const [rolledBack] = await db<{ enabled: number; forced: number }[]>`
        SELECT
          count(*) FILTER (WHERE relrowsecurity)::int AS enabled,
          count(*) FILTER (WHERE relforcerowsecurity)::int AS forced
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname IN (
          SELECT c2.relname FROM pg_policy p2 JOIN pg_class c2 ON c2.oid = p2.polrelid
          WHERE p2.polname LIKE 'steward_%'
        )
      `;
      expect(rolledBack).toEqual({ enabled: 0, forced: 0 });

      await runOperatorScript("rls-activate.sql");
      const rerun = await runCommand(
        ["bun", "run", "packages/api/scripts/migrate-production.ts", "plugins"],
        {
          DATABASE_URL: migrationDatabaseUrl(),
          MIGRATION_DATABASE_URL: migrationDatabaseUrl(),
          STEWARD_PLUGINS: "capabilities",
          STEWARD_MASTER_PASSWORD: "test-restricted-migrator-master-password",
          STEWARD_AUDIT_HMAC_KEY:
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          STEWARD_KDF_SALT: "0123456789abcdef0123456789abcdef",
        },
      );
      expect(rerun).toContain('"pluginName":"capabilities"');
    } finally {
      await db.end();
    }
  });
});

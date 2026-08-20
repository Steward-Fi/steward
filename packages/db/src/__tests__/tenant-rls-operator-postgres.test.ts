import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
setDefaultTimeout(180_000);

const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
const databaseName = `steward_rls_${suffix}`;
const appRole = `steward_app_${suffix}`;
const migrationRole = `steward_migrator_${suffix}`;
const definerRole = `steward_definer_${suffix}`;
const platformRole = `steward_platform_${suffix}`;
const appRolePassword = randomUUID().replaceAll("-", "");
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
    expect(firstMigration).toContain("0111_tenant_rls_policy_install");

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
      await admin.unsafe(`ALTER ROLE ${appRole} PASSWORD '${appRolePassword}'`);
      await admin.unsafe(`ALTER ROLE ${platformRole} PASSWORD '${platformRolePassword}'`);
      const roleRows = await db<
        {
          rolname: string;
          rolcanlogin: boolean;
          rolbypassrls: boolean;
          rolsuper: boolean;
        }[]
      >`
        SELECT rolname, rolcanlogin, rolbypassrls, rolsuper
        FROM pg_roles WHERE rolname IN (${appRole}, ${migrationRole}, ${definerRole}, ${platformRole})
        ORDER BY rolname
      `;
      expect(roleRows).toHaveLength(4);
      expect(roleRows.find((row) => row.rolname === appRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === migrationRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === definerRole)).toMatchObject({
        rolcanlogin: false,
        rolbypassrls: true,
        rolsuper: false,
      });
      expect(roleRows.find((row) => row.rolname === platformRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolsuper: false,
      });
      const [platformRlsPrivileges] = await db<
        {
          schema_usage: boolean;
          tenant_id_execute: boolean;
          user_id_execute: boolean;
          audit_sequence_usage: boolean;
          other_sequence_usage: boolean;
          default_sequence_grant: boolean;
        }[]
      >`
        SELECT
          has_schema_privilege(${platformRole}, 'steward_rls', 'USAGE') AS schema_usage,
          has_function_privilege(${platformRole}, 'steward_rls.tenant_id()', 'EXECUTE') AS tenant_id_execute,
          has_function_privilege(${platformRole}, 'steward_rls.user_id()', 'EXECUTE') AS user_id_execute,
          has_sequence_privilege(${platformRole}, 'public.audit_events_id_seq', 'USAGE,SELECT') AS audit_sequence_usage,
          has_sequence_privilege(${platformRole}, 'public.audit_checkpoints_id_seq', 'USAGE') AS other_sequence_usage,
          EXISTS (
            SELECT 1
            FROM pg_default_acl defaults
            CROSS JOIN LATERAL aclexplode(COALESCE(defaults.defaclacl, '{}'::aclitem[])) privilege
            JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
            WHERE defaults.defaclobjtype = 'S' AND granted_role.rolname = ${platformRole}
          ) AS default_sequence_grant
      `;
      expect(platformRlsPrivileges).toEqual({
        schema_usage: true,
        tenant_id_execute: true,
        user_id_execute: false,
        audit_sequence_usage: true,
        other_sequence_usage: false,
        default_sequence_grant: false,
      });

      const expectedPlatformAcls = [
        "function:steward_bootstrap.platform_delete_user(p_user_id uuid):EXECUTE:false",
        "function:steward_bootstrap.platform_revoke_user_refresh_tokens(p_user_id uuid):EXECUTE:false",
        "function:steward_bootstrap.platform_set_user_deactivation(p_user_id uuid, p_deactivated boolean):EXECUTE:false",
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
          CROSS JOIN LATERAL aclexplode(COALESCE(namespace.nspacl, acldefault('n', namespace.nspowner))) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE granted_role.rolname = ${platformRole}
          UNION ALL
          SELECT 'relation:' || namespace.nspname || '.' || relation.relname || ':' ||
            privilege.privilege_type || ':' || privilege.is_grantable AS acl
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace
          CROSS JOIN LATERAL aclexplode(COALESCE(
            relation.relacl,
            acldefault(CASE WHEN relation.relkind = 'S' THEN 'S'::"char" ELSE 'r'::"char" END, relation.relowner)
          )) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
            AND granted_role.rolname = ${platformRole}
          UNION ALL
          SELECT 'function:' || namespace.nspname || '.' || function_object.proname || '(' ||
            pg_get_function_identity_arguments(function_object.oid) || '):' ||
            privilege.privilege_type || ':' || privilege.is_grantable AS acl
          FROM pg_proc function_object
          JOIN pg_namespace namespace ON namespace.oid = function_object.pronamespace
          CROSS JOIN LATERAL aclexplode(COALESCE(function_object.proacl, acldefault('f', function_object.proowner))) privilege
          JOIN pg_roles granted_role ON granted_role.oid = privilege.grantee
          WHERE granted_role.rolname = ${platformRole}
          ORDER BY acl
        `;
        return rows.map((row) => row.acl);
      };
      expect(await platformNamedAcls()).toEqual(expectedPlatformAcls);

      await db.unsafe(`GRANT USAGE ON SCHEMA public TO ${platformRole}`);
      await db.unsafe(`GRANT UPDATE ON public.audit_events TO ${platformRole} WITH GRANT OPTION`);
      await db.unsafe(`GRANT USAGE ON SEQUENCE public.audit_checkpoints_id_seq TO ${platformRole}`);
      await db.unsafe(
        `GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_stats() TO ${platformRole} WITH GRANT OPTION`,
      );
      await runOperatorScript("rls-bootstrap.sql", true);
      expect(await platformNamedAcls()).toEqual(expectedPlatformAcls);

      await admin.unsafe(`GRANT ${definerRole} TO ${platformRole}`);
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "platform role must not inherit, assume, or be assumable by another role",
        );
      } finally {
        await admin.unsafe(`REVOKE ${definerRole} FROM ${platformRole}`);
      }

      await db.unsafe("CREATE SCHEMA platform_authority_probe");
      await db.unsafe("CREATE SEQUENCE platform_authority_probe.platform_owned_authority_probe");
      await db.unsafe(
        `ALTER SEQUENCE platform_authority_probe.platform_owned_authority_probe OWNER TO ${platformRole}`,
      );
      try {
        await expect(runOperatorScript("rls-bootstrap.sql", true)).rejects.toThrow(
          "platform role must not own database objects",
        );
      } finally {
        await db.unsafe("DROP SCHEMA IF EXISTS platform_authority_probe CASCADE");
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
      expect(activated).toEqual({ enabled: 71, forced: 71, maintenance: 71 });

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

      const platformKey = `rls-platform-key-${suffix}`;
      const appRoleEvidence = await runCommand(
        ["bun", "run", "packages/api/src/__tests__/fixtures/rls-app-role-exercise.ts"],
        {
          DATABASE_URL: appDatabaseUrl(),
          DATABASE_DRIVER: "postgres-js",
          STEWARD_PLATFORM_DATABASE_URL: platformDatabaseUrl(),
          STEWARD_PLATFORM_DATABASE_ROLE: platformRole,
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
      const rerun = await runCommand(["bun", "run", "packages/db/src/migrate.ts"], {
        DATABASE_URL: databaseUrl(databaseName),
      });
      expect(rerun).toContain("Already up to date");
    } finally {
      await db.end();
    }
  });
});

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { randomUUID } from "node:crypto";
import postgres from "postgres";

const describeWithPostgres = process.env.DATABASE_URL ? describe : describe.skip;
setDefaultTimeout(300_000);

const suffix = randomUUID().replaceAll("-", "").slice(0, 16);
const databaseName = `steward_rls_${suffix}`;
const appRole = `steward_app_${suffix}`;
const migrationRole = `steward_migrator_${suffix}`;
const definerRole = `steward_definer_${suffix}`;
const appRolePassword = randomUUID().replaceAll("-", "");
const migrationRolePassword = randomUUID().replaceAll("-", "");

function databaseUrl(database: string): string {
  const url = new URL(process.env.DATABASE_URL as string);
  url.pathname = `/${database}`;
  return url.toString();
}

function appDatabaseUrl(): string {
  const url = new URL(databaseUrl(databaseName));
  if (!url.hostname) throw new Error("RLS operator test requires a host-bearing DATABASE_URL");
  url.username = appRole;
  url.password = appRolePassword;
  return url.toString();
}

function migrationDatabaseUrl(): string {
  const url = new URL(databaseUrl(databaseName));
  if (!url.hostname) throw new Error("RLS operator test requires a host-bearing DATABASE_URL");
  url.username = migrationRole;
  url.password = migrationRolePassword;
  return url.toString();
}

function appRuntimeEnvironment(): Record<string, string> {
  return {
    DATABASE_URL: appDatabaseUrl(),
    DATABASE_DRIVER: "postgres-js",
    NODE_ENV: "production",
    SKIP_MIGRATIONS: "1",
    STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
  };
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

async function runOperatorScript(
  name: string,
  includeRoles = false,
  env: Record<string, string | undefined> = {},
) {
  const command = ["psql", "--no-psqlrc", "--dbname", databaseUrl(databaseName)];
  if (includeRoles) {
    command.push(
      "-v",
      `steward_app_role=${appRole}`,
      "-v",
      `steward_migration_role=${migrationRole}`,
      "-v",
      `steward_bootstrap_role=${definerRole}`,
    );
  } else if (name === "rls-activate.sql") {
    command.push(
      "-v",
      `steward_app_role=${appRole}`,
      "-v",
      `steward_migration_role=${migrationRole}`,
    );
  }
  command.push("-f", `scripts/postgres/${name}`);
  return runCommand(command, env);
}

describeWithPostgres("SEC-169 operator lifecycle on the real Steward schema", () => {
  const admin = postgres(process.env.DATABASE_URL as string, { max: 1 });

  afterAll(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${appRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${migrationRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${definerRole}`);
    await admin.end();
  });

  test("bootstraps, activates, rolls back, reactivates, and reruns the migrator", async () => {
    const [adminRole] = await admin<{ rolsuper: boolean }[]>`
      SELECT rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    expect(adminRole?.rolsuper).toBe(true);
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);

    const freshImport = await runCommand(
      ["bun", "run", "packages/db/src/__tests__/fixtures/import-api-context-before-migrations.ts"],
      {
        DATABASE_URL: databaseUrl(databaseName),
        NODE_ENV: "test",
        STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
        STEWARD_MASTER_PASSWORD: `rls-master-password-${suffix}`,
      },
    );
    expect(freshImport).toContain("API_CONTEXT_IMPORT_NO_DATABASE_IO");
    await expect(
      runCommand(["bun", "run", "packages/api/src/index.ts"], {
        DATABASE_URL: databaseUrl(databaseName),
        DATABASE_DRIVER: "postgres-js",
        NODE_ENV: "production",
        SKIP_MIGRATIONS: undefined,
        STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
        STEWARD_MASTER_PASSWORD: `rls-master-password-${suffix}`,
      }),
    ).rejects.toThrow("PRODUCTION_RLS_REQUIRES_OUT_OF_BAND_MIGRATIONS");
    await expect(
      runCommand(["bun", "run", "packages/api/src/index.ts"], {
        DATABASE_URL: databaseUrl(databaseName),
        DATABASE_DRIVER: "postgres-js",
        NODE_ENV: "production",
        SKIP_MIGRATIONS: "1",
        STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
        STEWARD_MASTER_PASSWORD: `rls-master-password-${suffix}`,
      }),
    ).rejects.toThrow("Tenant RLS readiness failed");

    const firstMigration = await runCommand(
      ["bun", "run", "packages/api/scripts/migrate-production.ts", "core"],
      { DATABASE_URL: undefined, MIGRATION_DATABASE_URL: databaseUrl(databaseName) },
    );
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

      await runOperatorScript("rls-compose-bootstrap.sql", true, {
        STEWARD_DB_APP_PASSWORD: appRolePassword,
        STEWARD_DB_MIGRATION_PASSWORD: migrationRolePassword,
        STEWARD_BOOTSTRAP_SET_ROLE_PASSWORDS: "true",
      });
      const roleRows = await db<
        {
          rolname: string;
          rolcanlogin: boolean;
          rolbypassrls: boolean;
          rolsuper: boolean;
        }[]
      >`
        SELECT rolname, rolcanlogin, rolbypassrls, rolsuper
        FROM pg_roles WHERE rolname IN (${appRole}, ${migrationRole}, ${definerRole})
        ORDER BY rolname
      `;
      expect(roleRows).toHaveLength(3);
      expect(roleRows.find((row) => row.rolname === appRole)).toMatchObject({
        rolcanlogin: true,
        rolbypassrls: false,
        rolsuper: false,
      });
      // External providers pre-provision login credentials. Re-running the
      // Compose wrapper in preserve mode must accept empty password env and
      // leave both existing credentials usable.
      await runOperatorScript("rls-compose-bootstrap.sql", true, {
        STEWARD_DB_APP_PASSWORD: "",
        STEWARD_DB_MIGRATION_PASSWORD: "",
        STEWARD_BOOTSTRAP_SET_ROLE_PASSWORDS: "false",
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

      await runOperatorScript("rls-activate.sql");

      const pluginMigration = await runCommand(
        ["bun", "run", "packages/api/scripts/migrate-production.ts", "plugins"],
        {
          DATABASE_URL: undefined,
          MIGRATION_DATABASE_URL: migrationDatabaseUrl(),
          STEWARD_PLUGINS: "capabilities",
          STEWARD_MASTER_PASSWORD: `rls-master-password-${suffix}`,
          STEWARD_JWT_SECRET: `rls-jwt-secret-${suffix}-0123456789abcdef`,
          STEWARD_AUDIT_HMAC_KEY: "ab".repeat(32),
        },
      );
      expect(pluginMigration).toContain("__drizzle_migrations_plugin_capabilities");
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
      expect(activated).toEqual({ enabled: 74, forced: 74, maintenance: 74 });

      expect(
        await runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).toContain("RLS_READY");

      await db.unsafe(`
        CREATE ROLE rls_creator_${suffix} NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
        GRANT CREATE ON SCHEMA public TO rls_creator_${suffix};
        GRANT rls_creator_${suffix} TO ${appRole};
      `);
      await expect(
        runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).rejects.toThrow("RLS_APP_ROLE_UNSAFE");
      await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
        "app role has assumable bypass or schema-owner authority",
      );
      await db.unsafe(`
        REVOKE rls_creator_${suffix} FROM ${appRole};
        REVOKE CREATE ON SCHEMA public FROM rls_creator_${suffix};
        DROP ROLE rls_creator_${suffix};
      `);

      await db.unsafe(`
        INSERT INTO public.tenants(id, name, api_key_hash) VALUES
          ('leak-a-${suffix}', 'leak probe A', 'leak-key-a-${suffix}'),
          ('leak-b-${suffix}', 'leak probe B', 'leak-key-b-${suffix}');
        CREATE FUNCTION steward_bootstrap.dump_tenants_${suffix}()
        RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog
        AS $$ SELECT count(*) FROM public.tenants $$;
        ALTER FUNCTION steward_bootstrap.dump_tenants_${suffix}() OWNER TO ${definerRole};
        REVOKE ALL ON FUNCTION steward_bootstrap.dump_tenants_${suffix}() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION steward_bootstrap.dump_tenants_${suffix}() TO ${appRole};
      `);
      const leakProbe = postgres(appDatabaseUrl(), { max: 1 });
      try {
        const [leaked] = await leakProbe.unsafe<{ count: number }[]>(
          `SELECT steward_bootstrap.dump_tenants_${suffix}()::int AS count`,
        );
        expect(leaked?.count).toBeGreaterThanOrEqual(2);
      } finally {
        await leakProbe.end();
      }
      await expect(
        runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).rejects.toThrow("RLS_BOOTSTRAP_FUNCTION_DRIFT");
      await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
        "bootstrap function inventory is unsafe",
      );
      await db.unsafe(`DROP FUNCTION steward_bootstrap.dump_tenants_${suffix}()`);
      await db.unsafe(`
        DELETE FROM public.tenants
        WHERE id IN ('leak-a-${suffix}', 'leak-b-${suffix}')
      `);

      await db.unsafe(`
        CREATE ROLE rls_function_grantee_${suffix} LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;
        GRANT USAGE ON SCHEMA steward_bootstrap TO rls_function_grantee_${suffix};
        GRANT EXECUTE ON FUNCTION steward_bootstrap.platform_tenants(integer, integer)
          TO rls_function_grantee_${suffix};
      `);
      await expect(
        runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).rejects.toThrow("RLS_BOOTSTRAP_ACL_DRIFT");
      await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
        "bootstrap/helper ACL inventory is unsafe",
      );
      await db.unsafe(`
        REVOKE EXECUTE ON FUNCTION steward_bootstrap.platform_tenants(integer, integer)
          FROM rls_function_grantee_${suffix};
        REVOKE USAGE ON SCHEMA steward_bootstrap FROM rls_function_grantee_${suffix};
        DROP ROLE rls_function_grantee_${suffix};
      `);

      await db.unsafe(`
        CREATE OR REPLACE FUNCTION steward_rls.tenant_id()
        RETURNS text LANGUAGE sql STABLE PARALLEL SAFE
        SET search_path = pg_catalog
        AS $$ SELECT COALESCE(NULLIF(current_setting('steward.tenant_id', true), ''), 'other') $$
      `);
      await expect(
        runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).rejects.toThrow("RLS_HELPER_DRIFT:tenant_id");
      await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
        "tenant helper definitions are unsafe",
      );
      await db.unsafe(`
        CREATE OR REPLACE FUNCTION steward_rls.tenant_id()
        RETURNS text LANGUAGE sql STABLE PARALLEL SAFE
        SET search_path = pg_catalog
        AS $$ SELECT NULLIF(current_setting('steward.tenant_id', true), '') $$
      `);

      await db.unsafe(`
        DROP POLICY steward_tenant_isolation ON public.agents;
        ALTER TABLE public.agents
          ADD COLUMN "tenant_id=steward_rls.tenant_id" boolean NOT NULL DEFAULT true;
        CREATE POLICY steward_tenant_isolation ON public.agents FOR ALL
          USING ("tenant_id=steward_rls.tenant_id")
          WITH CHECK ("tenant_id=steward_rls.tenant_id")
      `);
      await expect(
        runCommand(
          ["bun", "run", "packages/db/src/__tests__/fixtures/assert-rls-ready.ts"],
          appRuntimeEnvironment(),
        ),
      ).rejects.toThrow("RLS_POLICY_DRIFT:agents");
      await expect(runOperatorScript("rls-activate.sql")).rejects.toThrow(
        "installed policies drift from inventory",
      );
      await db.unsafe(`
        DROP POLICY steward_tenant_isolation ON public.agents;
        ALTER TABLE public.agents DROP COLUMN "tenant_id=steward_rls.tenant_id";
        CREATE POLICY steward_tenant_isolation ON public.agents FOR ALL
          USING ((tenant_id = steward_rls.tenant_id()))
          WITH CHECK ((tenant_id = steward_rls.tenant_id()))
      `);

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

      const sourceAgent = `source-agent-${suffix}`;
      const targetAgent = `target-agent-${suffix}`;
      await db`
        INSERT INTO public.agents(id, tenant_id, name, wallet_address) VALUES
          (${sourceAgent}, ${sourceTenant}, 'source agent', ${`0xsource${suffix}`}),
          (${targetAgent}, ${targetTenant}, 'target agent', ${`0xtarget${suffix}`})
      `;
      await db`
        INSERT INTO public.policies(id, agent_id, type, config) VALUES
          (${`source-policy-${suffix}`}, ${sourceAgent}, 'rate-limit', '{}'),
          (${`target-policy-${suffix}`}, ${targetAgent}, 'rate-limit', '{}')
      `;

      const appSql = postgres(appDatabaseUrl(), { max: 1 });
      try {
        const tenantBoundary = await appSql.begin(async (tx) => {
          await tx`SELECT set_config('steward.tenant_id', ${sourceTenant}, true)`;
          const joined = await tx`
            SELECT a.id, p.id AS policy_id
            FROM public.agents a JOIN public.policies p ON p.agent_id = a.id
            ORDER BY a.id
          `;
          const updated = await tx`
            UPDATE public.agents SET name = 'cross update'
            WHERE id = ${targetAgent} RETURNING id
          `;
          const deleted = await tx`
            DELETE FROM public.agents WHERE id = ${targetAgent} RETURNING id
          `;
          return { joined, updated, deleted };
        });
        expect(tenantBoundary.joined).toEqual([
          { id: sourceAgent, policy_id: `source-policy-${suffix}` },
        ]);
        expect(tenantBoundary.updated).toHaveLength(0);
        expect(tenantBoundary.deleted).toHaveLength(0);

        await expect(
          appSql.begin(async (tx) => {
            await tx`SELECT set_config('steward.tenant_id', ${sourceTenant}, true)`;
            await tx`
              INSERT INTO public.agents(id, tenant_id, name, wallet_address)
              VALUES (${`cross-insert-${suffix}`}, ${targetTenant}, 'cross insert', ${`0xcross${suffix}`})
            `;
          }),
        ).rejects.toMatchObject({ code: "42501" });
        await expect(
          appSql.begin(async (tx) => {
            await tx`SELECT set_config('steward.tenant_id', ${sourceTenant}, true)`;
            await tx`
              INSERT INTO public.agents(id, tenant_id, name, wallet_address)
              VALUES (${targetAgent}, ${targetTenant}, 'cross upsert', ${`0xupsert${suffix}`})
              ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
            `;
          }),
        ).rejects.toMatchObject({ code: "42501" });
      } finally {
        await appSql.end();
      }

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
      ).rejects.toThrow("Cannot deactivate the sole active tenant owner");

      const platformKey = `rls-platform-key-${suffix}`;
      const appRoleEvidence = await runCommand(
        ["bun", "run", "packages/api/src/__tests__/fixtures/rls-app-role-exercise.ts"],
        {
          DATABASE_URL: appDatabaseUrl(),
          DATABASE_DRIVER: "postgres-js",
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
      expect(appRoleEvidence).toContain('"ok":true');
      expect(appRoleEvidence).toContain('"platformAuditActions"');

      await db`CREATE VIEW public.rls_unclassified_view AS SELECT id FROM public.tenants`;
      await runOperatorScript("rls-rollback.sql");
      await db`DROP VIEW public.rls_unclassified_view`;
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
        ["bun", "run", "packages/api/scripts/migrate-production.ts", "core"],
        { DATABASE_URL: undefined, MIGRATION_DATABASE_URL: databaseUrl(databaseName) },
      );
      expect(rerun).toContain('"applied":[]');
    } finally {
      await db.end();
    }
  });
});

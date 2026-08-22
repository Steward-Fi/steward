import { afterAll, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { createDb } from "@stwd/db";

const databaseUrl = process.env.DATABASE_URL;
const describePostgres = databaseUrl ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 16);
const databaseName = `steward_cap_rate_${suffix}`;
const appRole = `steward_cap_app_${suffix}`;
const migratorRole = `steward_cap_migrator_${suffix}`;
const bootstrapRole = `steward_cap_bootstrap_${suffix}`;
const platformRole = `steward_cap_platform_${suffix}`;
const appPassword = crypto.randomUUID().replaceAll("-", "");

setDefaultTimeout(120_000);

function urlFor(database: string, role?: { name: string; password: string }): string {
  const url = new URL(databaseUrl!);
  url.pathname = `/${database}`;
  if (role) {
    // WHATWG URLs discard credentials on a hostless `postgresql:///db` URL.
    // Use loopback for the restricted-role child so the fixture really proves
    // app-role ACL/RLS behavior when the parent test uses a local Unix socket.
    if (!url.hostname) url.hostname = "127.0.0.1";
    url.username = role.name;
    url.password = role.password;
  }
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
  if (exitCode !== 0) throw new Error(stderr || stdout || `command exited ${exitCode}`);
  return stdout;
}

describePostgres("capability rate limit through the restricted production app role", () => {
  const admin = createDb(databaseUrl!).client;

  beforeAll(async () => {
    const [role] = await admin<{ rolsuper: boolean }[]>`
      SELECT rolsuper FROM pg_roles WHERE rolname = current_user
    `;
    if (!role?.rolsuper)
      throw new Error("restricted app-role proof requires a bootstrap superuser");
    await admin.unsafe(`CREATE DATABASE ${databaseName}`);
  });

  afterAll(async () => {
    await admin.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${appRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${migratorRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${bootstrapRole}`);
    await admin.unsafe(`DROP ROLE IF EXISTS ${platformRole}`);
    await admin.end();
  });

  it("mounts agent HTTP and exercises readiness inside an RLS tenant transaction", async () => {
    const adminDatabaseUrl = urlFor(databaseName);
    await runCommand(["bun", "run", "packages/db/src/migrate.ts"], {
      DATABASE_URL: adminDatabaseUrl,
    });
    await runCommand(
      ["bun", "run", "packages/api/src/__tests__/fixtures/capability-rate-limit-plugin-migrate.ts"],
      { DATABASE_URL: adminDatabaseUrl, STEWARD_PLUGINS: "capabilities" },
    );
    await runCommand([
      "psql",
      "--no-psqlrc",
      "--dbname",
      adminDatabaseUrl,
      "-v",
      `steward_app_role=${appRole}`,
      "-v",
      `steward_migration_role=${migratorRole}`,
      "-v",
      `steward_bootstrap_role=${bootstrapRole}`,
      "-v",
      `steward_platform_role=${platformRole}`,
      "-f",
      "scripts/postgres/rls-bootstrap.sql",
    ]);
    await admin.unsafe(`ALTER ROLE ${appRole} PASSWORD '${appPassword}'`);

    const tenantId = `cap-rate-${suffix}`;
    const agentId = `cap-rate-agent-${suffix}`;
    const database = createDb(adminDatabaseUrl).client;
    try {
      await database`
        INSERT INTO public.tenants (id, name, api_key_hash)
        VALUES (${tenantId}, ${tenantId}, ${`rate-key-${suffix}`})
      `;
      await database`
        INSERT INTO public.agents (id, tenant_id, name, wallet_address)
        VALUES (
          ${agentId},
          ${tenantId},
          ${agentId},
          '0x1234567890123456789012345678901234567890'
        )
      `;
    } finally {
      await database.end();
    }

    const appEnvironment = {
      DATABASE_URL: urlFor(databaseName, { name: appRole, password: appPassword }),
      DATABASE_DRIVER: "postgres-js",
      NODE_ENV: "production",
      STEWARD_APP_DATABASE_ROLE: appRole,
      STEWARD_PLUGINS: "capabilities",
      STEWARD_CAPABILITY_RATE_TEST_TENANT: tenantId,
      STEWARD_CAPABILITY_RATE_TEST_AGENT: agentId,
      ELIZA_CLOUD_JWKS_URL: "https://jwks.capability-rate.test/keys",
      STEWARD_MASTER_PASSWORD: `capability-rate-master-${suffix}`,
      STEWARD_KDF_SALT: "cd".repeat(32),
      STEWARD_ACK_LOCAL_CUSTODY: "true",
      STEWARD_JWT_SECRET: `capability-rate-jwt-${suffix}-0123456789abcdef`,
      JWT_SECRET: `capability-rate-jwt-${suffix}-0123456789abcdef`,
      STEWARD_AUDIT_HMAC_KEY: "ab".repeat(32),
      STEWARD_REDIS_REQUIRED: "false",
      STEWARD_ALLOW_INSECURE_DB: "true",
    };
    const output = await runCommand(
      ["bun", "run", "packages/api/src/__tests__/fixtures/capability-rate-limit-app-role.ts"],
      appEnvironment,
    );
    const evidenceLine = output
      .trim()
      .split("\n")
      .findLast((line) => line.startsWith('{"ok":true'));
    expect(evidenceLine).toBeDefined();
    expect(JSON.parse(evidenceLine!)).toMatchObject({
      ok: true,
      routeStatus: 403,
      errorStatus: 500,
      reservationCommittedWhilePaused: true,
      readiness: { ok: true, source: "postgres" },
      bucketCount: 1,
    });

    const assertReadinessFails = async () => {
      const readinessOutput = await runCommand(
        ["bun", "run", "packages/api/src/__tests__/fixtures/capability-rate-limit-readiness.ts"],
        appEnvironment,
      );
      const line = readinessOutput
        .trim()
        .split("\n")
        .findLast((candidate) => candidate.startsWith("{"));
      expect(line).toBeDefined();
      expect(JSON.parse(line!)).toMatchObject({ ok: false, source: "postgres" });
    };

    const adminDatabase = createDb(adminDatabaseUrl).client;
    try {
      await adminDatabase.unsafe(
        `REVOKE INSERT ON public.capability_rate_limit_buckets FROM PUBLIC, ${appRole}`,
      );
      const [insertPrivilege] = await adminDatabase<{ allowed: boolean; acl: string }[]>`
        SELECT
          has_table_privilege(${appRole}, 'public.capability_rate_limit_buckets', 'INSERT') AS allowed,
          coalesce(relation.relacl::text, '') AS acl
        FROM pg_class relation
        WHERE relation.oid = 'public.capability_rate_limit_buckets'::regclass
      `;
      expect(insertPrivilege?.allowed, insertPrivilege?.acl).toBe(false);
      await assertReadinessFails();
      await adminDatabase.unsafe(
        `GRANT INSERT ON public.capability_rate_limit_buckets TO ${appRole}`,
      );

      await adminDatabase`ALTER TABLE public.capability_rate_limit_buckets DISABLE TRIGGER capability_rate_limit_bucket_agent_fence`;
      await assertReadinessFails();
      await adminDatabase`ALTER TABLE public.capability_rate_limit_buckets ENABLE TRIGGER capability_rate_limit_bucket_agent_fence`;

      await adminDatabase.unsafe(
        `REVOKE EXECUTE ON FUNCTION public.steward_lock_tenant_deletion(text) FROM PUBLIC, ${appRole}`,
      );
      await assertReadinessFails();
      await adminDatabase`GRANT EXECUTE ON FUNCTION public.steward_lock_tenant_deletion(text) TO PUBLIC`;
    } finally {
      await adminDatabase.end();
    }
  });
});

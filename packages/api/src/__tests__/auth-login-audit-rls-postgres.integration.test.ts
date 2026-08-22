import { afterAll, beforeAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { createDb } from "@stwd/db";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const databaseUrl = process.env.DATABASE_URL;
const describePostgres = databaseUrl ? describe : describe.skip;
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 16);
const databaseName = `steward_auth_audit_${suffix}`;
const appRole = `steward_auth_app_${suffix}`;
const migratorRole = `steward_auth_migrator_${suffix}`;
const bootstrapRole = `steward_auth_bootstrap_${suffix}`;
const platformRole = `steward_auth_platform_${suffix}`;
const appPassword = crypto.randomUUID().replaceAll("-", "");
const repositoryRoot = new URL("../../../..", import.meta.url).pathname;
const fixturePath = new URL("./fixtures/auth-login-audit-restricted-app.ts", import.meta.url)
  .pathname;

setDefaultTimeout(120_000);

function urlFor(database: string, role?: { name: string; password: string }): string {
  const url = new URL(databaseUrl!);
  url.pathname = `/${database}`;
  if (role) {
    if (!url.hostname) url.hostname = "127.0.0.1";
    url.username = role.name;
    url.password = role.password;
  }
  return url.toString();
}

async function runCommand(command: string[], env: Record<string, string | undefined> = {}) {
  const child = Bun.spawn(command, {
    cwd: repositoryRoot,
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

describePostgres("auth login audit through the restricted production app role", () => {
  let admin!: ReturnType<typeof createDb>["client"];

  beforeAll(async () => {
    admin = createDb(databaseUrl!).client;
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

  test("writes the SIWE auth.login event inside verified tenant RLS", async () => {
    const adminDatabaseUrl = urlFor(databaseName);
    await runCommand(["bun", "run", "packages/db/src/migrate.ts"], {
      DATABASE_URL: adminDatabaseUrl,
    });
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

    // Keep this proof focused on the login-audit boundary. First-time wallet
    // provisioning has its own ACL acceptance; seed a valid existing wallet
    // identity so the restricted app role exercises session finalization and
    // the audit write rather than bootstrap authority.
    const privateKey = generatePrivateKey();
    const account = privateKeyToAccount(privateKey);
    const address = account.address.toLowerCase();
    const tenantId = `eth:${address}`;
    const userId = crypto.randomUUID();
    const seedDatabase = createDb(adminDatabaseUrl).client;
    try {
      await seedDatabase`
        INSERT INTO public.tenants (id, name, api_key_hash, owner_address)
        VALUES (${tenantId}, ${tenantId}, ${`auth-audit-key-${suffix}`}, ${address})
      `;
      await seedDatabase`
        INSERT INTO public.users (id, wallet_address, wallet_chain)
        VALUES (${userId}::uuid, ${address}, 'ethereum')
      `;
      await seedDatabase`
        INSERT INTO public.user_tenants (user_id, tenant_id, role)
        VALUES (${userId}::uuid, ${tenantId}, 'owner')
      `;
    } finally {
      await seedDatabase.end();
    }

    const output = await runCommand([process.execPath, fixturePath], {
      DATABASE_URL: urlFor(databaseName, { name: appRole, password: appPassword }),
      DATABASE_DRIVER: "postgres-js",
      NODE_ENV: "production",
      STEWARD_APP_DATABASE_ROLE: appRole,
      STEWARD_MASTER_PASSWORD: `auth-audit-master-${suffix}-with-enough-entropy`,
      STEWARD_KDF_SALT: "ab".repeat(32),
      STEWARD_ACK_LOCAL_CUSTODY: "true",
      STEWARD_JWT_SECRET: `auth-audit-jwt-${suffix}-with-enough-entropy`,
      STEWARD_AUDIT_HMAC_KEY: "cd".repeat(32),
      STEWARD_REDIS_REQUIRED: "false",
      STEWARD_ALLOW_AUTH_RATE_LIMIT_SOFT_FAIL: "true",
      STEWARD_ALLOW_INSECURE_DB: "true",
      STEWARD_PGLITE_MEMORY: "false",
      STEWARD_TEST_SIWE_PRIVATE_KEY: privateKey,
      SIWE_ALLOWED_DOMAINS: "steward.fi",
    });
    const evidenceLine = output
      .trim()
      .split("\n")
      .findLast((line) => line.startsWith('{"ok":true'));
    expect(evidenceLine).toBeDefined();
    const evidence = JSON.parse(evidenceLine!) as {
      tenantId: string;
      userId: string;
      address: string;
      status: number;
    };
    expect(evidence.status).toBe(200);

    const database = createDb(adminDatabaseUrl).client;
    try {
      const events = await database<
        Array<{
          tenant_id: string;
          actor_id: string;
          metadata: Record<string, unknown>;
          request_id: string | null;
        }>
      >`
        SELECT tenant_id, actor_id, metadata, request_id
        FROM public.audit_events
        WHERE tenant_id = ${evidence.tenantId}
          AND actor_id = ${evidence.userId}
          AND action = 'auth.login'
      `;
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        tenant_id: evidence.tenantId,
        actor_id: evidence.userId,
        request_id: "restricted-auth-login-audit-proof",
        metadata: {
          method: "siwe",
          address: evidence.address,
          walletChain: "ethereum",
        },
      });
    } finally {
      await database.end();
    }
  });
});

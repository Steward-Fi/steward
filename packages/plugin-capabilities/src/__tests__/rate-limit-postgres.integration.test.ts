import { afterAll, beforeAll, expect, it } from "bun:test";
import { fileURLToPath } from "node:url";
import {
  agents,
  closeDb,
  createDb,
  runMigrations,
  runPluginMigrations,
  tenantContextFromAuthenticatedPrincipal,
  tenants,
  withTenantRlsTransaction,
} from "@stwd/db";
import { sql } from "drizzle-orm";
import { migrate as postgresMigrate } from "drizzle-orm/postgres-js/migrator";
import { CAPABILITY_INVOKE_RATE_LIMIT, enforceCapabilityRateLimit } from "../rate-limit";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;
const migrationsFolder = fileURLToPath(new URL("../../drizzle", import.meta.url));
const databaseName = `steward_cap_rate_concurrency_${crypto.randomUUID().replaceAll("-", "")}`;
const savedNodeEnv = process.env.NODE_ENV;
const savedAllowInsecureDb = process.env.STEWARD_ALLOW_INSECURE_DB;
const savedDatabaseUrl = process.env.DATABASE_URL;
let testDatabaseUrl = "";
let adminClient: ReturnType<typeof createDb>["client"] | null = null;

function urlForDatabase(name: string): string {
  const url = new URL(databaseUrl!);
  url.pathname = `/${name}`;
  return url.toString();
}

function databaseUrlWithApplicationName(name: string): string {
  const url = new URL(testDatabaseUrl);
  url.searchParams.set("application_name", name);
  return url.toString();
}

async function waitForBlockedWriter(
  observer: ReturnType<typeof createDb>["client"],
  applicationName: string,
): Promise<void> {
  for (let attempt = 0; attempt < 400; attempt += 1) {
    const [activity] = await observer<{ blocked: boolean }[]>`
      SELECT EXISTS (
        SELECT 1
        FROM pg_stat_activity
        WHERE application_name = ${applicationName}
          AND wait_event_type = 'Lock'
      ) AS blocked
    `;
    if (activity?.blocked) return;
    await Bun.sleep(10);
  }
  throw new Error(`writer ${applicationName} never blocked on deletion fence`);
}

beforeAll(async () => {
  if (!databaseUrl || process.env.STEWARD_PGLITE_MEMORY) return;
  adminClient = createDb(databaseUrl).client;
  const [role] = await adminClient<{ rolsuper: boolean }[]>`
    SELECT rolsuper FROM pg_roles WHERE rolname = current_user
  `;
  if (!role?.rolsuper) {
    throw new Error("capability rate-limit concurrency proof requires a bootstrap superuser");
  }
  await adminClient.unsafe(`CREATE DATABASE ${databaseName}`);
  testDatabaseUrl = urlForDatabase(databaseName);
  process.env.DATABASE_URL = testDatabaseUrl;
  process.env.STEWARD_ALLOW_INSECURE_DB = "true";
  await runMigrations();
  await runPluginMigrations(
    { id: "capabilities", migrationsFolder },
    { migrateFn: postgresMigrate as never },
  );
});

afterAll(async () => {
  await closeDb().catch(() => undefined);
  if (adminClient) {
    await adminClient.unsafe(`DROP DATABASE IF EXISTS ${databaseName} WITH (FORCE)`);
    await adminClient.end();
  }
  if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
  else process.env.NODE_ENV = savedNodeEnv;
  if (savedAllowInsecureDb === undefined) delete process.env.STEWARD_ALLOW_INSECURE_DB;
  else process.env.STEWARD_ALLOW_INSECURE_DB = savedAllowInsecureDb;
  if (savedDatabaseUrl === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = savedDatabaseUrl;
});

realPostgresIt(
  "serializes the exact boundary across independent connections and survives restart",
  async () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_INSECURE_DB = "true";
    const tenantId = `rate-tenant-${crypto.randomUUID()}`;
    const agentId = `rate-agent-${crypto.randomUUID()}`;
    const first = createDb(testDatabaseUrl);
    const second = createDb(testDatabaseUrl);
    await first.db.insert(tenants).values({
      id: tenantId,
      name: tenantId,
      apiKeyHash: `rate-key-${tenantId}`,
    });
    await first.db.insert(agents).values({
      id: agentId,
      tenantId,
      name: agentId,
      walletAddress: "0x1234567890123456789012345678901234567890",
    });
    const context = (db: typeof first.db) => ({
      db,
      getRedisClient: () => null,
      isRedisConfigured: () => false,
      withCapabilityTenantDatabase: <T>(
        _tenantId: string,
        use: (tenantDb: typeof db) => Promise<T>,
      ) =>
        withTenantRlsTransaction(
          db as never,
          "postgres-js",
          tenantContextFromAuthenticatedPrincipal({
            tenantId,
            method: "capability-rate-limit-test",
            subject: agentId,
          }),
          (tx) => use(tx as typeof db),
        ),
    });
    try {
      const attempts = Array.from(
        { length: CAPABILITY_INVOKE_RATE_LIMIT.maxRequests + 1 },
        (_, i) =>
          enforceCapabilityRateLimit(
            context(i % 2 === 0 ? first.db : second.db),
            "invoke",
            tenantId,
            agentId,
          ),
      );
      const results = await Promise.all(attempts);
      expect(results.filter((result) => result.allowed)).toHaveLength(
        CAPABILITY_INVOKE_RATE_LIMIT.maxRequests,
      );
      expect(results.filter((result) => !result.allowed)).toHaveLength(1);

      await Promise.all([first.client.end(), second.client.end()]);

      // Recreate the database client to model a service restart. Durable state
      // still rejects the next request in the same rolling window.
      const restarted = createDb(testDatabaseUrl);
      try {
        const afterRestart = await enforceCapabilityRateLimit(
          context(restarted.db),
          "invoke",
          tenantId,
          agentId,
        );
        expect(afterRestart.allowed).toBe(false);
        const [bucket] = await restarted.client<[{ reservation_count: number }]>`
          select cardinality(reservations)::int as reservation_count
          from capability_rate_limit_buckets
          where tenant_id = ${tenantId} and agent_id = ${agentId} and surface = 'invoke'
        `;
        expect(bucket.reservation_count).toBe(CAPABILITY_INVOKE_RATE_LIMIT.maxRequests);
        await restarted.client`
          delete from capability_rate_limit_buckets
          where tenant_id = ${tenantId} and agent_id = ${agentId}
        `;
      } finally {
        await restarted.client.end();
      }
    } finally {
      await first.client.end().catch(() => undefined);
      await second.client.end().catch(() => undefined);
    }
  },
  60_000,
);

realPostgresIt(
  "prevents bucket recreation across agent and tenant deletion commits",
  async () => {
    process.env.NODE_ENV = "production";
    process.env.STEWARD_ALLOW_INSECURE_DB = "true";
    const observer = createDb(testDatabaseUrl);
    try {
      for (const deletionKind of ["agent", "tenant"] as const) {
        const tenantId = `rate-delete-${deletionKind}-${crypto.randomUUID()}`;
        const agentId = `rate-delete-agent-${crypto.randomUUID()}`;
        const applicationName = `steward-rate-writer-${crypto.randomUUID()}`;
        const deleter = createDb(testDatabaseUrl);
        const writer = createDb(databaseUrlWithApplicationName(applicationName));
        await observer.db.insert(tenants).values({
          id: tenantId,
          name: tenantId,
          apiKeyHash: `rate-key-${tenantId}`,
        });
        await observer.db.insert(agents).values({
          id: agentId,
          tenantId,
          name: agentId,
          walletAddress: "0x1234567890123456789012345678901234567890",
        });

        let deletionReady!: () => void;
        const ready = new Promise<void>((resolve) => {
          deletionReady = resolve;
        });
        let releaseDeletion!: () => void;
        const release = new Promise<void>((resolve) => {
          releaseDeletion = resolve;
        });
        const deletion = deleter.client.begin(async (tx) => {
          await tx`SELECT public.steward_lock_tenant_deletion(${tenantId})`;
          if (deletionKind === "agent") {
            await tx`
              SELECT id FROM public.agents
              WHERE tenant_id = ${tenantId} AND id = ${agentId}
              FOR UPDATE
            `;
          } else {
            await tx`SELECT id FROM public.tenants WHERE id = ${tenantId} FOR UPDATE`;
          }
          await tx`
            DELETE FROM public.capability_rate_limit_buckets
            WHERE tenant_id = ${tenantId}
              AND (${deletionKind} = 'tenant' OR agent_id = ${agentId})
          `;
          deletionReady();
          await release;
          if (deletionKind === "agent") {
            await tx`
              DELETE FROM public.agents
              WHERE tenant_id = ${tenantId} AND id = ${agentId}
            `;
          } else {
            await tx`DELETE FROM public.tenants WHERE id = ${tenantId}`;
          }
        });
        await ready;

        const writerContext = {
          db: writer.db,
          getRedisClient: () => null,
          isRedisConfigured: () => false,
          withCapabilityTenantDatabase: <T>(
            _tenantId: string,
            use: (tenantDb: typeof writer.db) => Promise<T>,
          ) =>
            withTenantRlsTransaction(
              writer.db as never,
              "postgres-js",
              tenantContextFromAuthenticatedPrincipal({
                tenantId,
                method: "capability-rate-limit-delete-race",
                subject: agentId,
              }),
              (tx) => use(tx as typeof writer.db),
            ),
        };
        const reservation = enforceCapabilityRateLimit(writerContext, "invoke", tenantId, agentId);
        await waitForBlockedWriter(observer.client, applicationName);
        releaseDeletion();
        await deletion;
        expect(await reservation).toMatchObject({ allowed: false });
        const [bucket] = await observer.client<{ count: number }[]>`
          SELECT count(*)::int AS count
          FROM public.capability_rate_limit_buckets
          WHERE tenant_id = ${tenantId} AND agent_id = ${agentId}
        `;
        expect(bucket?.count).toBe(0);

        await Promise.all([deleter.client.end(), writer.client.end()]);
        if (deletionKind === "agent") {
          await observer.db.delete(tenants).where(sql`${tenants.id} = ${tenantId}`);
        }
      }
    } finally {
      await observer.client.end();
    }
  },
  60_000,
);

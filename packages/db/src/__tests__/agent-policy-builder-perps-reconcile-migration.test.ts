import { describe, expect, setDefaultTimeout, test } from "bun:test";
import { cp, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";
import { runMigrations } from "../migrate";

setDefaultTimeout(120_000);
const migrations = new URL("../../drizzle", import.meta.url).pathname;
const omittedMigration = "0073_agent_policy_builder_perps.sql";
const reconciliationMigration = "0109_agent_policy_builder_perps_reconcile.sql";

async function applyMigration(client: PGlite, file: string) {
  const migration = await readFile(join(migrations, file), "utf8");
  for (const statement of migration.split("--> statement-breakpoint")) {
    if (statement.trim()) await client.exec(statement);
  }
}

describe("0109 agent policy builder-perps reconciliation", () => {
  test("is the contiguous journal tip after the unjournaled 0073 file", async () => {
    const journal = JSON.parse(
      await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
    ) as { entries: Array<{ idx: number; tag: string }> };

    expect(journal.entries.some(({ tag }) => tag === omittedMigration.replace(/\.sql$/, ""))).toBe(
      false,
    );
    const nonceIndex = journal.entries.findIndex(
      ({ tag }) => tag === "0108_evm_nonce_tenant_ownership",
    );
    const reconciliationIndex = journal.entries.findIndex(
      ({ tag }) => tag === "0109_agent_policy_builder_perps_reconcile",
    );
    const deleteLifecycleIndex = journal.entries.findIndex(
      ({ tag }) => tag === "0110_agent_delete_lease_lifecycle",
    );
    expect(journal.entries[nonceIndex]).toMatchObject({
      idx: 108,
      tag: "0108_evm_nonce_tenant_ownership",
    });
    expect(journal.entries[reconciliationIndex]).toMatchObject({
      idx: 109,
      tag: "0109_agent_policy_builder_perps_reconcile",
    });
    expect(journal.entries[deleteLifecycleIndex]).toMatchObject({
      idx: 110,
      tag: "0110_agent_delete_lease_lifecycle",
    });
    expect(reconciliationIndex).toBe(nonceIndex + 1);
    expect(deleteLifecycleIndex).toBe(reconciliationIndex + 1);
  });

  test("repairs a production-journal schema that skipped 0073 and is idempotent", async () => {
    const client = new PGlite("memory://");
    try {
      const files = (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort();
      for (const file of files) {
        if (file === reconciliationMigration) break;
        if (file !== omittedMigration) await applyMigration(client, file);
      }

      const before = await client.query<{ exists: boolean }>(`
        SELECT EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
        ) AS exists
      `);
      expect(before.rows[0]?.exists).toBe(false);

      await applyMigration(client, reconciliationMigration);
      await applyMigration(client, reconciliationMigration);

      const after = await client.query<{
        column_default: string;
        is_nullable: string;
      }>(`
        SELECT column_default,is_nullable FROM information_schema.columns
        WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
      `);
      expect(after.rows).toEqual([{ column_default: "false", is_nullable: "NO" }]);
    } finally {
      await client.close();
    }
  });

  const realPostgresTest = process.env.DATABASE_URL ? test : test.skip;
  realPostgresTest(
    "upgrades a true journal-at-0108 database through the current tip exactly once",
    async () => {
      const originalDatabaseUrl = process.env.DATABASE_URL!;
      const maintenanceUrl = new URL(originalDatabaseUrl);
      maintenanceUrl.pathname = "/postgres";
      const admin = postgres(maintenanceUrl.toString(), { max: 1 });
      const databaseName = `steward_0109_${process.pid}_${crypto.randomUUID().replaceAll("-", "")}`;
      const databaseUrl = new URL(originalDatabaseUrl);
      databaseUrl.pathname = `/${databaseName}`;
      const migrationsAt0108 = await mkdtemp(join(tmpdir(), "steward-migrations-0108-"));
      let databaseCreated = false;
      try {
        const journal = JSON.parse(
          await readFile(join(migrations, "meta", "_journal.json"), "utf8"),
        ) as { entries: Array<{ idx: number; tag: string }> };
        await cp(migrations, migrationsAt0108, { recursive: true });
        await writeFile(
          join(migrationsAt0108, "meta", "_journal.json"),
          `${JSON.stringify(
            { ...journal, entries: journal.entries.filter(({ idx }) => idx <= 108) },
            null,
            2,
          )}\n`,
        );

        await admin`CREATE DATABASE ${admin(databaseName)}`;
        databaseCreated = true;
        const target = postgres(databaseUrl.toString(), { max: 1 });
        try {
          await migrate(drizzle(target), { migrationsFolder: migrationsAt0108 });
          // Model a capability plugin installed before the core 0110 upgrade.
          // Core cannot assume the plugin is currently enabled, but it must
          // still fence authority in tables left by that earlier installation.
          await target`
            CREATE TABLE capability_grants (
              id uuid PRIMARY KEY,
              tenant_id text NOT NULL,
              agent_id varchar(64) NOT NULL,
              secret_route_id uuid,
              status text NOT NULL
            )
          `;
          const before = await target<{ exists: boolean }[]>`
          SELECT EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
          ) AS exists
        `;
          expect(before).toEqual([{ exists: false }]);
        } finally {
          await target.end({ timeout: 5 });
        }

        process.env.DATABASE_URL = databaseUrl.toString();
        const first = await runMigrations();
        const expectedAfter0108 = journal.entries
          .filter(({ idx }) => idx > 108)
          .map(({ tag }) => tag);
        expect(first.applied).toEqual(expectedAfter0108);
        const second = await runMigrations();
        expect(second.applied).toEqual([]);

        const verified = postgres(databaseUrl.toString(), { max: 1 });
        try {
          const column = await verified<{ column_default: string; is_nullable: string }[]>`
          SELECT column_default,is_nullable FROM information_schema.columns
          WHERE table_name='agent_policies' AND column_name='allow_builder_perps'
        `;
          expect(column).toEqual([{ column_default: "false", is_nullable: "NO" }]);
          const leaseAgentFk = await verified<{ exists: boolean }[]>`
            SELECT EXISTS (
              SELECT 1 FROM pg_constraint
              WHERE conname='upstream_credential_leases_agent_fk'
            ) AS exists
          `;
          expect(leaseAgentFk).toEqual([{ exists: false }]);
          const leaseAgentFence = await verified<{ exists: boolean }[]>`
            SELECT EXISTS (
              SELECT 1 FROM pg_trigger
              WHERE tgname='upstream_credential_leases_agent_fence' AND NOT tgisinternal
            ) AS exists
          `;
          expect(leaseAgentFence).toEqual([{ exists: true }]);
          const fenceFunction = await verified<
            {
              definition: string;
              settings: string[] | null;
            }[]
          >`
            SELECT pg_get_functiondef(proc.oid) AS definition, proc.proconfig AS settings
            FROM pg_proc proc
            WHERE proc.oid = 'public.steward_fence_agent_authority_creation()'::regprocedure
          `;
          expect(fenceFunction[0]?.definition).toContain("FROM public.agents");
          expect(fenceFunction[0]?.settings).toContain("search_path=pg_catalog, public");
          const fenceDefinitions = await verified<{ name: string; definition: string }[]>`
            SELECT trigger.tgname AS name, pg_get_triggerdef(trigger.oid) AS definition
            FROM pg_trigger trigger
            WHERE trigger.tgname IN (
              'upstream_credential_leases_agent_fence',
              'secret_routes_agent_fence',
              'capability_grants_agent_fence'
            )
          `;
          expect(
            fenceDefinitions.find(({ name }) => name === "upstream_credential_leases_agent_fence")
              ?.definition,
          ).toContain("UPDATE OF tenant_id, agent_id, status, token_hash, token_ciphertext");
          expect(
            fenceDefinitions.find(({ name }) => name === "secret_routes_agent_fence")?.definition,
          ).toContain("UPDATE OF tenant_id, agent_id, enabled");
          expect(
            fenceDefinitions.find(({ name }) => name === "capability_grants_agent_fence")
              ?.definition,
          ).toContain("UPDATE OF tenant_id, agent_id, status, secret_route_id");
          const capabilityAgentFence = await verified<{ exists: boolean }[]>`
            SELECT EXISTS (
              SELECT 1 FROM pg_trigger
              WHERE tgname='capability_grants_agent_fence' AND NOT tgisinternal
            ) AS exists
          `;
          expect(capabilityAgentFence).toEqual([{ exists: true }]);
          const orphanGrantId = crypto.randomUUID();
          await verified`
            INSERT INTO capability_grants (id, tenant_id, agent_id, status)
            VALUES (${orphanGrantId}, 'orphan-tenant', 'deleted-agent', 'revoked')
          `;
          const reactivation = (async () => {
            await verified`
              UPDATE capability_grants SET status='active' WHERE id=${orphanGrantId}
            `;
          })();
          await expect(reactivation).rejects.toMatchObject({ code: "23503" });
          const applied = await verified<{ count: number }[]>`
          SELECT count(*)::int AS count FROM drizzle.__drizzle_migrations
        `;
          expect(applied).toEqual([{ count: journal.entries.length }]);
        } finally {
          await verified.end({ timeout: 5 });
        }
      } finally {
        process.env.DATABASE_URL = originalDatabaseUrl;
        try {
          if (databaseCreated) await admin`DROP DATABASE ${admin(databaseName)} WITH (FORCE)`;
        } finally {
          await admin.end({ timeout: 5 });
          await rm(migrationsAt0108, { recursive: true, force: true });
        }
      }
    },
  );
});

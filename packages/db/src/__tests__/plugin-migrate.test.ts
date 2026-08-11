/**
 * plugin-migrate.test.ts — proves the Phase 2c isolation guarantee: a plugin's
 * migrations are recorded ONLY in its own namespaced bookkeeping table, never in
 * the core's `drizzle.__drizzle_migrations`, and re-running is idempotent.
 *
 * Runs against PGLite (no pg_advisory_lock, so useAdvisoryLock:false) with the
 * pglite migrator injected via migrateFn — the runner is driver-neutral.
 */

import { afterAll, describe, expect, setDefaultTimeout, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrate as pgliteMigrate } from "drizzle-orm/pglite/migrator";

import { createPGLiteDb } from "../pglite";
import {
  pluginMigrationsTable,
  runPluginMigrations,
  sanitizePluginMigrationId,
} from "../plugin-migrate";

setDefaultTimeout(30000);

const cleanups: Array<() => Promise<void>> = [];
afterAll(async () => {
  for (const c of cleanups) await c().catch(() => {});
});

/**
 * Build a throwaway plugin migrations folder with one trivial migration + the
 * drizzle journal/meta that the migrator expects.
 */
async function makeMigrationsFolder(tag: string, sql: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "stwd-plugin-mig-"));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  await writeFile(join(dir, `${tag}.sql`), sql, "utf8");
  await mkdir(join(dir, "meta"), { recursive: true });
  await writeFile(
    join(dir, "meta", "_journal.json"),
    JSON.stringify({
      version: "7",
      dialect: "postgresql",
      entries: [{ idx: 0, version: "7", when: Date.now(), tag, breakpoints: true }],
    }),
    "utf8",
  );
  return dir;
}

describe("plugin migrations: namespaced-journal isolation", () => {
  test("sanitizePluginMigrationId is injection-safe and fail-closed on empty", () => {
    expect(sanitizePluginMigrationId("Trading")).toBe("trading");
    expect(sanitizePluginMigrationId("a-b.c/d")).toBe("a_b_c_d");
    expect(sanitizePluginMigrationId("__x__")).toBe("x");
    expect(() => sanitizePluginMigrationId("///")).toThrow();
    expect(() => sanitizePluginMigrationId("")).toThrow();
    // the derived table name carries the sanitized id, never raw input
    expect(pluginMigrationsTable("Trading")).toBe("__drizzle_migrations_plugin_trading");
  });

  test("records the plugin migration in its OWN table, never the core journal, idempotently", async () => {
    const { db, client } = await createPGLiteDb("memory://");
    cleanups.push(async () => {
      await client.close().catch(() => {});
    });

    const folder = await makeMigrationsFolder(
      "0000_plugin_test_2c",
      'CREATE TABLE "plugin_test_2c" ("id" integer PRIMARY KEY);',
    );

    const result = await runPluginMigrations(
      { id: "demo-plugin", migrationsFolder: folder },
      {
        db,
        client,
        useAdvisoryLock: false, // PGLite has no pg_advisory_lock
        migrateFn: pgliteMigrate as never,
      },
    );

    expect(result.id).toBe("demo-plugin");
    expect(result.migrationsTable).toBe("__drizzle_migrations_plugin_demo_plugin");

    // (a) the plugin's table was created
    const tbl = await client.query("SELECT to_regclass('public.plugin_test_2c') AS t");
    expect(tbl.rows[0].t).toBe("plugin_test_2c");

    // (b) recorded in the plugin's OWN namespaced bookkeeping table
    const pluginLedger = await client.query(
      `SELECT count(*)::int AS n FROM drizzle."__drizzle_migrations_plugin_demo_plugin"`,
    );
    expect(pluginLedger.rows[0].n).toBeGreaterThanOrEqual(1);

    // (c) the CORE __drizzle_migrations table is UNTOUCHED — it must not exist
    //     (this run never created or wrote it). to_regclass returns null when absent.
    const coreLedger = await client.query(
      "SELECT to_regclass('drizzle.__drizzle_migrations') AS t",
    );
    expect(coreLedger.rows[0].t).toBeNull();

    // (d) idempotent: a second run applies nothing and does not throw
    const again = await runPluginMigrations(
      { id: "demo-plugin", migrationsFolder: folder },
      { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
    );
    expect(again.migrationsTable).toBe("__drizzle_migrations_plugin_demo_plugin");
    const ledgerAfter = await client.query(
      `SELECT count(*)::int AS n FROM drizzle."__drizzle_migrations_plugin_demo_plugin"`,
    );
    expect(ledgerAfter.rows[0].n).toBe(pluginLedger.rows[0].n);
  });

  test("two plugins get distinct ledgers (no cross-plugin collision)", async () => {
    const { db, client } = await createPGLiteDb("memory://");
    cleanups.push(async () => {
      await client.close().catch(() => {});
    });

    const folderA = await makeMigrationsFolder(
      "0000_a",
      'CREATE TABLE "plugin_a_tbl" ("id" integer PRIMARY KEY);',
    );
    const folderB = await makeMigrationsFolder(
      "0000_b",
      'CREATE TABLE "plugin_b_tbl" ("id" integer PRIMARY KEY);',
    );

    const a = await runPluginMigrations(
      { id: "alpha", migrationsFolder: folderA },
      { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
    );
    const b = await runPluginMigrations(
      { id: "beta", migrationsFolder: folderB },
      { db, client, useAdvisoryLock: false, migrateFn: pgliteMigrate as never },
    );

    expect(a.migrationsTable).not.toBe(b.migrationsTable);
    expect(a.migrationsTable).toBe("__drizzle_migrations_plugin_alpha");
    expect(b.migrationsTable).toBe("__drizzle_migrations_plugin_beta");
  });
});

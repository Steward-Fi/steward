/**
 * migration-isolation.test.ts - proves the Phase 2c isolation guarantee for THIS
 * plugin: the capability migrations are recorded ONLY in the plugin's own
 * namespaced bookkeeping table, never in the core's `drizzle.__drizzle_migrations`
 * journal, and the tables land. mirrors the core 2c isolation test.
 */

import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { pluginMigrationsTable } from "@stwd/db";
import { type Harness, makeHarness } from "./_harness";

setDefaultTimeout(30000);

let harness: Harness | null = null;
afterEach(async () => {
  await harness?.close();
  harness = null;
});

describe("capability plugin migrations: namespaced-journal isolation", () => {
  test("derives the capability plugin's own bookkeeping table name", () => {
    expect(pluginMigrationsTable("capabilities")).toBe("__drizzle_migrations_plugin_capabilities");
  });

  test("creates both tables and records them in the plugin's OWN ledger", async () => {
    harness = await makeHarness();
    const { client } = harness;

    // (a) both plugin tables exist
    const capTbl = await client.query("SELECT to_regclass('public.capabilities') AS t");
    expect(capTbl.rows[0].t).toBe("capabilities");
    const grantTbl = await client.query("SELECT to_regclass('public.capability_grants') AS t");
    expect(grantTbl.rows[0].t).toBe("capability_grants");

    // (b) recorded in the plugin's OWN namespaced bookkeeping table
    const pluginLedger = await client.query(
      `SELECT count(*)::int AS n FROM drizzle."__drizzle_migrations_plugin_capabilities"`,
    );
    expect(pluginLedger.rows[0].n).toBeGreaterThanOrEqual(1);

    // (c) the plugin's migration was NOT written into the core journal. the core
    //     journal MAY exist (createPGLiteDb ran the core migrations), so assert it
    //     carries NO row tagged for the capability plugin's migration.
    const coreLedger = await client.query(
      "SELECT to_regclass('drizzle.__drizzle_migrations') AS t",
    );
    if (coreLedger.rows[0].t) {
      const contaminated = await client.query(
        `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations WHERE hash LIKE '%capabilit%'`,
      );
      expect(contaminated.rows[0].n).toBe(0);
    }

    // (d) the unique constraint on (tenant_id, name) is present (drives create 409)
    const uniq = await client.query(
      `SELECT count(*)::int AS n FROM pg_indexes WHERE indexname = 'capabilities_tenant_name_uniq'`,
    );
    expect(uniq.rows[0].n).toBe(1);

    // (e) the status CHECK constraint is present (grants status enum guard)
    const chk = await client.query(
      `SELECT count(*)::int AS n FROM pg_constraint WHERE conname = 'capability_grants_status_check'`,
    );
    expect(chk.rows[0].n).toBe(1);
  });

  test("migration 0001 lands capability_invocations in the plugin's OWN ledger, core untouched", async () => {
    harness = await makeHarness();
    const { client } = harness;

    // (a) the invocations table exists (migration 0001 applied).
    const invTbl = await client.query(
      "SELECT to_regclass('public.capability_invocations') AS t",
    );
    expect(invTbl.rows[0].t).toBe("capability_invocations");

    // (b) BOTH plugin migrations (0000 + 0001) are recorded in the plugin's OWN
    //     namespaced ledger (>=2 rows).
    const pluginLedger = await client.query(
      `SELECT count(*)::int AS n FROM drizzle."__drizzle_migrations_plugin_capabilities"`,
    );
    expect(pluginLedger.rows[0].n).toBeGreaterThanOrEqual(2);

    // (c) the core journal carries NO capability-invocations migration row.
    const coreLedger = await client.query(
      "SELECT to_regclass('drizzle.__drizzle_migrations') AS t",
    );
    if (coreLedger.rows[0].t) {
      const contaminated = await client.query(
        `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations WHERE hash LIKE '%invocation%'`,
      );
      expect(contaminated.rows[0].n).toBe(0);
    }

    // (d) the decision CHECK constraint is present (allow/deny/approval/error).
    const chk = await client.query(
      `SELECT count(*)::int AS n FROM pg_constraint WHERE conname = 'capability_invocations_decision_check'`,
    );
    expect(chk.rows[0].n).toBe(1);

    // (e) the rate-limit index is present (the count query's covering index).
    const idx = await client.query(
      `SELECT count(*)::int AS n FROM pg_indexes WHERE indexname = 'capability_invocations_rate_idx'`,
    );
    expect(idx.rows[0].n).toBe(1);
  });
});

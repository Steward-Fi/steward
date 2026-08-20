/**
 * migration-isolation.test.ts - proves the Phase 2c isolation guarantee for THIS
 * plugin: the capability migrations are recorded ONLY in the plugin's own
 * namespaced bookkeeping table, never in the core's `drizzle.__drizzle_migrations`
 * journal, and the tables land. mirrors the core 2c isolation test.
 */

import { afterEach, describe, expect, setDefaultTimeout, test } from "bun:test";
import { readFile } from "node:fs/promises";
import { pluginMigrationsTable, secretRoutes } from "@stwd/db";
import { eq } from "drizzle-orm";
import { capabilities, capabilityGrants } from "../schema";
import { ensureTenant, type Harness, makeHarness } from "./_harness";

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

  test("creates grant tables and the agent lifecycle fence in the plugin's OWN ledger", async () => {
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

    const fence = await client.query(
      `SELECT count(*)::int AS n FROM pg_trigger
       WHERE tgname = 'capability_grants_agent_fence' AND NOT tgisinternal`,
    );
    expect(fence.rows[0].n).toBe(1);
    const fenceDefinition = await client.query(
      `SELECT pg_get_triggerdef(oid) AS definition FROM pg_trigger
       WHERE tgname = 'capability_grants_agent_fence' AND NOT tgisinternal`,
    );
    expect(fenceDefinition.rows[0].definition).toContain(
      "UPDATE OF tenant_id, agent_id, status, secret_route_id",
    );
  });

  test("migration 0001 lands capability_invocations in the plugin's OWN ledger, core untouched", async () => {
    harness = await makeHarness();
    const { client } = harness;

    // (a) the invocations table exists (migration 0001 applied).
    const invTbl = await client.query("SELECT to_regclass('public.capability_invocations') AS t");
    expect(invTbl.rows[0].t).toBe("capability_invocations");

    // (b) all plugin migrations are recorded in the plugin's OWN namespaced
    //     ledger, including the agent lifecycle fence in 0002.
    const pluginLedger = await client.query(
      `SELECT count(*)::int AS n FROM drizzle."__drizzle_migrations_plugin_capabilities"`,
    );
    expect(pluginLedger.rows[0].n).toBeGreaterThanOrEqual(3);

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

    const bucketTable = await client.query(
      "SELECT to_regclass('public.capability_rate_limit_buckets') AS t",
    );
    expect(bucketTable.rows[0].t).toBe("capability_rate_limit_buckets");
    const bucketRls = await client.query(
      `SELECT relrowsecurity AS enabled, relforcerowsecurity AS forced
       FROM pg_class
       WHERE oid = 'public.capability_rate_limit_buckets'::regclass`,
    );
    expect(bucketRls.rows[0]).toEqual({ enabled: true, forced: true });
    const pluginRls = await client.query(
      `SELECT count(*)::int AS n
       FROM pg_class
       WHERE relname IN (
         'capabilities',
         'capability_grants',
         'capability_invocations',
         'capability_rate_limit_buckets'
       )
         AND relrowsecurity
         AND relforcerowsecurity`,
    );
    expect(pluginRls.rows[0].n).toBe(4);
    const bucketConstraint = await client.query(
      `SELECT count(*)::int AS n FROM pg_constraint
       WHERE conname = 'capability_rate_limit_buckets_surface_check'`,
    );
    expect(bucketConstraint.rows[0].n).toBe(1);
    const bucketIndex = await client.query(
      `SELECT count(*)::int AS n FROM pg_indexes
       WHERE indexname = 'capability_rate_limit_buckets_identity_uniq'`,
    );
    expect(bucketIndex.rows[0].n).toBe(1);
    const bucketFence = await client.query(
      `SELECT count(*)::int AS n
       FROM pg_trigger
       WHERE tgname = 'capability_rate_limit_bucket_agent_fence'
         AND NOT tgisinternal`,
    );
    expect(bucketFence.rows[0].n).toBe(1);
  });

  test("0002 revokes orphan grants without disabling a different tenant's route", async () => {
    harness = await makeHarness();
    const { client, db } = harness;
    const grantTenant = `grant-${crypto.randomUUID()}`;
    const routeTenant = `route-${crypto.randomUUID()}`;
    await ensureTenant(db, grantTenant);
    await ensureTenant(db, routeTenant);

    // Recreate the pre-0002 state, including a corrupt historical cross-tenant
    // route reference. The migration must retire the orphaned authority without
    // mutating another tenant's route.
    await client.exec(
      "DROP TRIGGER IF EXISTS capability_grants_agent_fence ON public.capability_grants",
    );
    const capabilityId = crypto.randomUUID();
    const routeId = crypto.randomUUID();
    const grantId = crypto.randomUUID();
    await db.insert(capabilities).values({
      id: capabilityId,
      tenantId: grantTenant,
      name: `migration-${capabilityId}`,
      secretId: crypto.randomUUID(),
      host: "api.example.test",
      pathPattern: "/v1/*",
      method: "POST",
      injectKey: "Authorization",
    });
    await db.insert(secretRoutes).values({
      id: routeId,
      tenantId: routeTenant,
      agentId: null,
      secretId: crypto.randomUUID(),
      hostPattern: "api.example.test",
      pathPattern: "/v1/*",
      method: "POST",
      injectAs: "header",
      injectKey: "Authorization",
      enabled: true,
    });
    await db.insert(capabilityGrants).values({
      id: grantId,
      tenantId: grantTenant,
      agentId: "deleted-agent",
      capabilityId,
      secretRouteId: routeId,
      status: "active",
    });

    const migration = await readFile(
      new URL("../../drizzle/0002_agent_grant_lifecycle.sql", import.meta.url),
      "utf8",
    );
    for (const statement of migration.split("--> statement-breakpoint")) {
      if (statement.trim()) await client.exec(statement);
    }

    expect(
      await db
        .select({ status: capabilityGrants.status })
        .from(capabilityGrants)
        .where(eq(capabilityGrants.id, grantId)),
    ).toEqual([{ status: "revoked" }]);
    expect(
      await db
        .select({ enabled: secretRoutes.enabled })
        .from(secretRoutes)
        .where(eq(secretRoutes.id, routeId)),
    ).toEqual([{ enabled: true }]);
  });
});

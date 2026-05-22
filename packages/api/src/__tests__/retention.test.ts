/**
 * Data-retention sweep — integration test.
 *
 * Requires DATABASE_URL pointing at a Postgres the test can write to.
 * Inserts rows older than their TTL and asserts they're deleted, while
 * fresh rows and protected rows (e.g. confirmed transactions) survive.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";

const SKIP = !process.env.DATABASE_URL;

const SUFFIX = `${Date.now()}`;
const TENANT = `retention-test-${SUFFIX}`;
const AGENT = `retention-agent-${SUFFIX}`;

async function cleanup(): Promise<void> {
  const db = getDb();
  await db.execute(sql`DELETE FROM proxy_audit_log WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM refresh_tokens WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM transactions WHERE agent_id = ${AGENT}`);
  await db.execute(sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT}`);
  await db.execute(sql`DELETE FROM auth_kv_store WHERE namespace = ${`retention-test-${SUFFIX}`}`);
}

beforeAll(async () => {
  if (SKIP) return;
  process.env.STEWARD_RETENTION_DISABLED = "true"; // scheduler off; we call runRetentionSweep directly
  await cleanup();
});

afterAll(async () => {
  if (SKIP) return;
  await cleanup();
});

describe.skipIf(SKIP)("retention sweep", () => {
  it("deletes old proxy_audit_log rows and keeps fresh ones", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    const db = getDb();
    // Old row (200 days ago — past the 90-day default).
    await db.execute(sql`
      INSERT INTO proxy_audit_log
        (agent_id, tenant_id, target_host, target_path, method, status_code, latency_ms, created_at)
      VALUES
        (${AGENT}, ${TENANT}, 'example.com', '/old', 'GET', 200, 12, now() - interval '200 days')
    `);
    // Fresh row.
    await db.execute(sql`
      INSERT INTO proxy_audit_log
        (agent_id, tenant_id, target_host, target_path, method, status_code, latency_ms, created_at)
      VALUES
        (${AGENT}, ${TENANT}, 'example.com', '/new', 'GET', 200, 12, now())
    `);

    const results = await runRetentionSweep();
    const proxy = results.find((r) => r.table === "proxy_audit_log");
    expect(proxy).toBeDefined();
    expect((proxy?.deleted ?? 0) >= 1).toBe(true);

    const survivors = (await db.execute(
      sql`SELECT target_path FROM proxy_audit_log WHERE tenant_id = ${TENANT}`,
    )) as Array<{ target_path: string }>;
    const paths = survivors.map((s) => s.target_path);
    expect(paths).toContain("/new");
    expect(paths).not.toContain("/old");
  });

  it("deletes refresh tokens past grace period", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    const db = getDb();
    // expired 30 days ago — past the 7-day grace.
    await db.execute(sql`
      INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at, created_at)
      VALUES (${`tok-old-${SUFFIX}`}, ${`u-${SUFFIX}`}, ${TENANT}, 'h1',
              now() - interval '30 days', now() - interval '60 days')
    `);
    // Still valid (1 day out).
    await db.execute(sql`
      INSERT INTO refresh_tokens (id, user_id, tenant_id, token_hash, expires_at, created_at)
      VALUES (${`tok-new-${SUFFIX}`}, ${`u-${SUFFIX}`}, ${TENANT}, 'h2',
              now() + interval '1 day', now())
    `);

    await runRetentionSweep();

    const ids = (await db.execute(
      sql`SELECT id FROM refresh_tokens WHERE tenant_id = ${TENANT}`,
    )) as Array<{ id: string }>;
    const idList = ids.map((r) => r.id);
    expect(idList).toContain(`tok-new-${SUFFIX}`);
    expect(idList).not.toContain(`tok-old-${SUFFIX}`);
  });

  it("only deletes failed/rejected transactions; keeps confirmed", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    const db = getDb();

    // We need a real agent FK; create a minimal tenant + agent.
    await db.execute(sql`
      INSERT INTO tenants (id, name) VALUES (${TENANT}, 'retention-test')
      ON CONFLICT (id) DO NOTHING
    `);
    await db.execute(sql`
      INSERT INTO agents (id, tenant_id, name) VALUES (${AGENT}, ${TENANT}, 'retention-agent')
      ON CONFLICT (id) DO NOTHING
    `);

    await db.execute(sql`
      INSERT INTO transactions (id, agent_id, status, to_address, value, chain_id, created_at)
      VALUES (${`tx-failed-old-${SUFFIX}`}, ${AGENT}, 'failed', '0xabc', '0', 1,
              now() - interval '400 days')
    `);
    await db.execute(sql`
      INSERT INTO transactions (id, agent_id, status, to_address, value, chain_id, created_at)
      VALUES (${`tx-confirmed-old-${SUFFIX}`}, ${AGENT}, 'confirmed', '0xabc', '0', 1,
              now() - interval '400 days')
    `);

    await runRetentionSweep();

    const rows = (await db.execute(
      sql`SELECT id, status FROM transactions WHERE agent_id = ${AGENT}`,
    )) as Array<{ id: string; status: string }>;
    const ids = rows.map((r) => r.id);
    expect(ids).not.toContain(`tx-failed-old-${SUFFIX}`);
    expect(ids).toContain(`tx-confirmed-old-${SUFFIX}`);
  });

  it("does not delete audit_events by default (no env override)", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    delete process.env.STEWARD_RETENTION_AUDIT_EVENTS_DAYS;
    const db = getDb();
    // Insert an ancient audit event directly (bypassing the chain — just for retention assertion).
    await db.execute(sql`
      INSERT INTO audit_events
        (tenant_id, seq, prev_hash, hmac, actor_type, action, created_at)
      VALUES
        (${TENANT}, 1, '\\x00'::bytea, '\\x00'::bytea, 'system', 'test.old',
         now() - interval '1000 days')
    `);

    const results = await runRetentionSweep();
    expect(results.find((r) => r.table === "audit_events")).toBeUndefined();

    const rows = (await db.execute(
      sql`SELECT seq FROM audit_events WHERE tenant_id = ${TENANT}`,
    )) as Array<{ seq: number | string }>;
    expect(rows.length).toBe(1);
  });

  it("deletes expired auth_kv_store rows", async () => {
    const { runRetentionSweep } = await import("../services/retention");
    const db = getDb();
    const ns = `retention-test-${SUFFIX}`;
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS auth_kv_store (
        id          TEXT NOT NULL,
        namespace   TEXT NOT NULL,
        value       TEXT NOT NULL,
        expires_at  TIMESTAMPTZ NOT NULL,
        PRIMARY KEY (namespace, id)
      )
    `);
    await db.execute(sql`
      INSERT INTO auth_kv_store (id, namespace, value, expires_at)
      VALUES ('expired', ${ns}, 'x', now() - interval '1 hour')
      ON CONFLICT (namespace, id) DO UPDATE SET expires_at = EXCLUDED.expires_at
    `);
    await db.execute(sql`
      INSERT INTO auth_kv_store (id, namespace, value, expires_at)
      VALUES ('live', ${ns}, 'x', now() + interval '1 hour')
      ON CONFLICT (namespace, id) DO UPDATE SET expires_at = EXCLUDED.expires_at
    `);

    await runRetentionSweep();

    const rows = (await db.execute(
      sql`SELECT id FROM auth_kv_store WHERE namespace = ${ns}`,
    )) as Array<{ id: string }>;
    const ids = rows.map((r) => r.id);
    expect(ids).toContain("live");
    expect(ids).not.toContain("expired");
  });
});

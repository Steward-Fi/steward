/**
 * Tamper-evident audit chain — integration test.
 *
 * Requires DATABASE_URL pointing at a Postgres the test can write to.
 * The chain is per-tenant; each test uses a fresh tenantId so runs are
 * independent and parallel-safe.
 */

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { getDb } from "@stwd/db";
import { sql } from "drizzle-orm";

const SKIP = !process.env.DATABASE_URL;

import { trackAuditEvent, verifyAuditChain, writeAuditEvent } from "../services/audit";

const TENANT_OK = `audit-test-ok-${Date.now()}`;
const TENANT_TAMPER = `audit-test-tamper-${Date.now()}`;
const TENANT_TRUNCATE = `audit-test-truncate-${Date.now()}`;
const TENANT_TAIL = `audit-test-tail-${Date.now()}`;
const TENANT_WIPE = `audit-test-wipe-${Date.now()}`;
const TENANT_EMPTY = `audit-test-empty-${Date.now()}`;

const ALL_TENANTS = [
  TENANT_OK,
  TENANT_TAMPER,
  TENANT_TRUNCATE,
  TENANT_TAIL,
  TENANT_WIPE,
  TENANT_EMPTY,
];

async function cleanup(): Promise<void> {
  const db = getDb();
  const ids = sql.join(
    ALL_TENANTS.map((t) => sql`${t}`),
    sql`, `,
  );
  // Heads + events first: both FK tenants(id) ON DELETE RESTRICT.
  await db.execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id IN (${ids})`);
  await db.execute(sql`DELETE FROM audit_events WHERE tenant_id IN (${ids})`);
  await db.execute(sql`DELETE FROM tenants WHERE id IN (${ids})`);
}

beforeAll(async () => {
  if (SKIP) return;
  const db = getDb();
  // Pre-clean in case a previous run with the same timestamp aborted.
  await cleanup();
  // audit_events.tenant_id now FKs tenants(id) ON DELETE RESTRICT — create rows.
  for (const t of ALL_TENANTS) {
    await db.execute(sql`
      INSERT INTO tenants (id, name, api_key_hash)
      VALUES (${t}, 'audit-chain-test', ${`hash-${t}`})
      ON CONFLICT (id) DO NOTHING
    `);
  }
});

afterAll(async () => {
  if (SKIP) return;
  await cleanup();
});

describe.skipIf(SKIP)("audit chain", () => {
  it("verifies a freshly-written chain", async () => {
    for (let i = 0; i < 5; i++) {
      await writeAuditEvent({
        tenantId: TENANT_OK,
        actorType: "user",
        actorId: "alice",
        action: "test.event",
        metadata: { i },
      });
    }
    const result = await verifyAuditChain(TENANT_OK);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.count).toBe(5);
  });

  it("detects tampering with a historical row", async () => {
    for (let i = 0; i < 4; i++) {
      await writeAuditEvent({
        tenantId: TENANT_TAMPER,
        actorType: "agent",
        actorId: "bot-1",
        action: "test.event",
        metadata: { i },
      });
    }
    // Tamper: rewrite the metadata of seq=2 without recomputing the chain.
    const db = getDb();
    await db.execute(
      sql`UPDATE audit_events SET metadata = ${sql.raw("'{\"i\":999}'::jsonb")} WHERE tenant_id = ${TENANT_TAMPER} AND seq = 2`,
    );

    const result = await verifyAuditChain(TENANT_TAMPER);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.brokenAt).toBe(2);
  });

  it("detects deleted tail rows in a requested verification range", async () => {
    for (let i = 0; i < 3; i++) {
      await writeAuditEvent({
        tenantId: TENANT_TRUNCATE,
        actorType: "user",
        actorId: "alice",
        action: "test.event",
        metadata: { i },
      });
    }

    const db = getDb();
    await db.execute(
      sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT_TRUNCATE} AND seq = 3`,
    );

    const result = await verifyAuditChain(TENANT_TRUNCATE, { fromSeq: 1, toSeq: 3 });
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.brokenAt).toBe(3);
  });

  it("detects open-ended tail truncation via the high-water-mark", async () => {
    for (let i = 0; i < 4; i++) {
      await writeAuditEvent({
        tenantId: TENANT_TAIL,
        actorType: "user",
        actorId: "alice",
        action: "test.event",
        metadata: { i },
      });
    }
    // Delete the newest row out-of-band (no toSeq cap on verify).
    const db = getDb();
    await db.execute(sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT_TAIL} AND seq = 4`);

    const result = await verifyAuditChain(TENANT_TAIL);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.brokenAt).toBe(4);
  });

  it("detects whole-chain deletion via the high-water-mark", async () => {
    for (let i = 0; i < 3; i++) {
      await writeAuditEvent({
        tenantId: TENANT_WIPE,
        actorType: "user",
        actorId: "alice",
        action: "test.event",
        metadata: { i },
      });
    }
    // Wipe every row but leave the head high-water-mark behind.
    const db = getDb();
    await db.execute(sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT_WIPE}`);

    const result = await verifyAuditChain(TENANT_WIPE);
    expect(result.valid).toBe(false);
    if (!result.valid) expect(result.brokenAt).toBe(1);
  });

  it("verifies a genuinely empty, never-written tenant", async () => {
    // No head row, no events: nothing to truncate, so this is valid+empty.
    const result = await verifyAuditChain(TENANT_EMPTY);
    expect(result.valid).toBe(true);
    if (result.valid) expect(result.count).toBe(0);
  });

  it("trackAuditEvent does not throw on success", () => {
    expect(() =>
      trackAuditEvent({
        tenantId: TENANT_OK,
        actorType: "system",
        action: "test.event",
      }),
    ).not.toThrow();
  });
});

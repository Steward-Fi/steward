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

beforeAll(async () => {
  if (SKIP) return;
  // Pre-clean in case a previous run with the same timestamp aborted.
  const db = getDb();
  await db.execute(
    sql`DELETE FROM audit_events WHERE tenant_id IN (${TENANT_OK}, ${TENANT_TAMPER})`,
  );
});

afterAll(async () => {
  if (SKIP) return;
  const db = getDb();
  await db.execute(
    sql`DELETE FROM audit_events WHERE tenant_id IN (${TENANT_OK}, ${TENANT_TAMPER})`,
  );
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

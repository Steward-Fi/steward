import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { closeDb, getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq, sql } from "drizzle-orm";
import { verifyAuditChain, writeAuditEvent } from "../services/audit";

const TENANT_ID = `audit-strict-${Date.now()}`;
const EMPTY_TENANT_ID = `audit-strict-empty-${Date.now()}`;

describe("strict audit chain verification", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_AUDIT_HMAC_KEY =
      "audit-strict-test-hmac-key-0123456789abcdef0123456789abcdef";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
    await getDb()
      .insert(tenants)
      .values([
        { id: TENANT_ID, name: "Audit Strict Tenant", apiKeyHash: "hash-strict" },
        { id: EMPTY_TENANT_ID, name: "Audit Strict Empty Tenant", apiKeyHash: "hash-empty" },
      ]);
  }, 120_000);

  afterAll(async () => {
    await getDb().delete(tenants).where(eq(tenants.id, TENANT_ID));
    await getDb().delete(tenants).where(eq(tenants.id, EMPTY_TENANT_ID));
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
    delete process.env.STEWARD_AUDIT_HMAC_KEY;
  });

  it("fails strict verification when events and the chain head are both deleted", async () => {
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "auditor",
      action: "test.audit.strict",
      metadata: { i: 1 },
    });
    await writeAuditEvent({
      tenantId: TENANT_ID,
      actorType: "user",
      actorId: "auditor",
      action: "test.audit.strict",
      metadata: { i: 2 },
    });

    expect(await verifyAuditChain(TENANT_ID, { requireHead: true })).toMatchObject({
      valid: true,
      count: 2,
    });

    await getDb().execute(sql`DELETE FROM audit_events WHERE tenant_id = ${TENANT_ID}`);
    await getDb().execute(sql`DELETE FROM audit_chain_heads WHERE tenant_id = ${TENANT_ID}`);

    expect(await verifyAuditChain(TENANT_ID)).toMatchObject({ valid: true, count: 0 });
    expect(await verifyAuditChain(TENANT_ID, { requireHead: true })).toEqual({
      valid: false,
      brokenAt: 1,
    });
  });

  it("preserves non-strict empty tenant behavior while letting callers require a head", async () => {
    expect(await verifyAuditChain(EMPTY_TENANT_ID)).toMatchObject({ valid: true, count: 0 });
    expect(await verifyAuditChain(EMPTY_TENANT_ID, { requireHead: true })).toEqual({
      valid: false,
      brokenAt: 1,
    });
  });
});

/**
 * SEC-167: `isAuditSequenceConflict` must retry ONLY genuine audit-chain
 * transient failures (serialization errors, seq-index races) — not every
 * unique violation that happens to occur inside the retried unit of work.
 *
 * A bare 23505 or generic "duplicate key value" error may describe a caller's
 * own unique conflict, such as an idempotency-key violation. Retrying it wastes
 * work and creates unearned reliance on the caller's idempotency contract.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { withTenantAuditedTransaction } from "../audit-chain";
import { closeDb, setPGLiteOverride } from "../client";
import { createPGLiteDb } from "../pglite";

function uniqueViolation(constraint: string): Error {
  return Object.assign(
    new Error(`duplicate key value violates unique constraint "${constraint}"`),
    { code: "23505", constraint_name: constraint },
  );
}

describe("audit-chain retry classification (SEC-167)", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => {
      await client.close();
    });
  });

  afterAll(async () => {
    await closeDb().catch(() => {});
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("a caller's own unique violation is NOT retried", async () => {
    let calls = 0;
    await expect(
      withTenantAuditedTransaction("tenant-sec167-a", async () => {
        calls += 1;
        throw uniqueViolation("agents_pkey");
      }),
    ).rejects.toThrow("agents_pkey");
    expect(calls).toBe(1);
  });

  test("a unique violation named by message but on another constraint is NOT retried", async () => {
    let calls = 0;
    const err = new Error(
      'duplicate key value violates unique constraint "audit_chain_heads_pkey"',
    );
    await expect(
      withTenantAuditedTransaction("tenant-sec167-b", async () => {
        calls += 1;
        throw err;
      }),
    ).rejects.toThrow("audit_chain_heads_pkey");
    expect(calls).toBe(1);
  });

  test("an audit_events_tenant_seq_idx race IS retried (5 attempts, then throws)", async () => {
    let calls = 0;
    await expect(
      withTenantAuditedTransaction("tenant-sec167-c", async () => {
        calls += 1;
        throw uniqueViolation("audit_events_tenant_seq_idx");
      }),
    ).rejects.toThrow("audit_events_tenant_seq_idx");
    expect(calls).toBe(5);
  });

  test("a serialization failure (40001) IS retried", async () => {
    let calls = 0;
    const err = Object.assign(new Error("could not serialize access due to concurrent update"), {
      code: "40001",
    });
    await expect(
      withTenantAuditedTransaction("tenant-sec167-d", async () => {
        calls += 1;
        throw err;
      }),
    ).rejects.toThrow("could not serialize access");
    expect(calls).toBe(5);
  });

  test("a transient seq race followed by success commits on retry", async () => {
    let calls = 0;
    const result = await withTenantAuditedTransaction("tenant-sec167-e", async () => {
      calls += 1;
      if (calls === 1) throw uniqueViolation("audit_events_tenant_seq_idx");
      return "committed";
    });
    expect(result).toBe("committed");
    expect(calls).toBe(2);
  });
});

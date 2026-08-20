/**
 * SEC-167: `isAuditSequenceConflict` must retry ONLY genuine audit-chain
 * transient failures (serialization errors, seq-index races) — not every
 * unique violation that happens to occur inside the retried unit of work.
 *
 * A bare 23505 or generic "duplicate key value" text must not match;
 * so a caller's OWN unique conflict (e.g. an idempotency-key violation in a
 * mutation) retried the whole transaction 5 times: wasted work, and an
 * unearned reliance on the caller's retry-idempotency contract.
 */
import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  __resetAuditHmacKeyCacheForTests,
  withTenantAuditedTransaction,
  withTenantAuditedTransactionOnDb,
} from "../audit-chain";
import { closeDb, getDb, setPGLiteOverride, withTenantTransactionDatabase } from "../client";
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

  test("a distinct handle inside tenant ALS keeps audit writes on its own transaction", async () => {
    const previousAuditKey = process.env.STEWARD_AUDIT_HMAC_KEY;
    process.env.STEWARD_AUDIT_HMAC_KEY = "ab".repeat(32);
    __resetAuditHmacKeyCacheForTests();
    const outerDb = { marker: "outer-app-transaction" } as unknown as ReturnType<typeof getDb>;
    let topLevelAuditCalls = 0;
    let transactionAuditCalls = 0;
    const separateDb = {
      async execute() {
        topLevelAuditCalls += 1;
        throw new Error("CROSS_HANDLE_TOP_LEVEL_AUDIT");
      },
      async transaction(callback: (tx: unknown) => Promise<unknown>) {
        return callback({
          async execute() {
            transactionAuditCalls += 1;
            throw new Error("CROSS_HANDLE_TRANSACTION_AUDIT");
          },
        });
      },
    } as unknown as ReturnType<typeof getDb>;

    try {
      await withTenantTransactionDatabase(outerDb, { tenantId: "platform" }, async () => {
        await expect(
          withTenantAuditedTransactionOnDb(separateDb, "platform", async (_tx, append) => {
            await append({
              tenantId: "platform",
              actorType: "platform",
              action: "user.deactivate.authorized",
            });
          }),
        ).rejects.toThrow("CROSS_HANDLE_TRANSACTION_AUDIT");
      });
      expect(topLevelAuditCalls).toBe(0);
      expect(transactionAuditCalls).toBe(1);
    } finally {
      if (previousAuditKey === undefined) delete process.env.STEWARD_AUDIT_HMAC_KEY;
      else process.env.STEWARD_AUDIT_HMAC_KEY = previousAuditKey;
      __resetAuditHmacKeyCacheForTests();
    }
  });
});

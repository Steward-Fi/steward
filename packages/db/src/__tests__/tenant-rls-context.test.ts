import { describe, expect, test } from "bun:test";
import { PgTransaction } from "drizzle-orm/pg-core";
import {
  assertTenantRlsDriver,
  tenantContextForInternalJob,
  tenantContextFromAuthenticatedPrincipal,
  withTenantRlsTransaction,
} from "../tenant-rls-context";

describe("tenant RLS transaction context", () => {
  test("binds and verifies context before exposing the transaction", async () => {
    const calls: string[] = [];
    let executeCount = 0;
    const tx = {
      async execute() {
        executeCount += 1;
        calls.push(`execute-${executeCount}`);
        return executeCount === 4
          ? [
              {
                tenant_id: "tenant-a",
                user_id: "11111111-1111-4111-8111-111111111111",
              },
            ]
          : [];
      },
    };
    const db = {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        calls.push("transaction");
        return callback(tx);
      },
    };
    const context = tenantContextFromAuthenticatedPrincipal({
      tenantId: "tenant-a",
      method: "session-jwt",
      subject: "user:123",
      userId: "11111111-1111-4111-8111-111111111111",
    });
    const result = await withTenantRlsTransaction(db, "postgres-js", context, async () => {
      calls.push("callback");
      return 42;
    });
    expect(result).toBe(42);
    expect(calls).toEqual([
      "transaction",
      "execute-1",
      "execute-2",
      "execute-3",
      "execute-4",
      "callback",
    ]);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.authority)).toBe(true);
  });

  test("rejects invalid identities, forged objects, and transactionless Workers", async () => {
    expect(() =>
      tenantContextFromAuthenticatedPrincipal({
        tenantId: "tenant-a\nSET ROLE owner",
        method: "jwt",
        subject: "user:1",
      }),
    ).toThrow("RLS_TENANT_CONTEXT_INVALID");
    expect(() => tenantContextForInternalJob({ tenantId: "tenant-a", job: "" })).toThrow(
      "RLS_TENANT_JOB_INVALID",
    );
    expect(() =>
      tenantContextFromAuthenticatedPrincipal({
        tenantId: "tenant-a",
        method: "session-jwt\nforged",
        subject: "user:1",
      }),
    ).toThrow("RLS_TENANT_AUTHORITY_INVALID");
    expect(() => assertTenantRlsDriver("neon-http")).toThrow("RLS_TRANSACTION_UNSUPPORTED");
    expect(() => assertTenantRlsDriver("neon-websocket")).not.toThrow();

    const db = { transaction: async () => undefined };
    await expect(
      withTenantRlsTransaction(
        db as never,
        "postgres-js",
        {
          tenantId: "tenant-a",
          authority: { kind: "internal-job", job: "forged" },
        } as never,
        async () => undefined,
      ),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_UNTRUSTED");

    const genuine = tenantContextForInternalJob({ tenantId: "tenant-a", job: "retention" });
    const cloned = Object.assign({}, genuine, { tenantId: "tenant-b" });
    await expect(
      withTenantRlsTransaction(db as never, "postgres-js", cloned as never, async () => undefined),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_UNTRUSTED");
  });

  test("rejects a dirty connection before changing or exposing it", async () => {
    let callbackCalled = false;
    let executeCount = 0;
    const tx = {
      async execute() {
        executeCount += 1;
        return executeCount === 1 ? [{ tenant_id: "tenant-from-prior-session" }] : [];
      },
    };
    const db = {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    };
    await expect(
      withTenantRlsTransaction(
        db,
        "postgres-js",
        tenantContextForInternalJob({ tenantId: "tenant-a", job: "retention" }),
        async () => {
          callbackCalled = true;
        },
      ),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_DIRTY");
    expect(executeCount).toBe(4);
    expect(callbackCalled).toBe(false);
  });

  test("rejects a nested transaction before binding tenant authority", async () => {
    let executeCount = 0;
    const tx = {
      async execute() {
        executeCount += 1;
        return [];
      },
    };
    const db = Object.assign(Object.create(PgTransaction.prototype), {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    });
    await expect(
      withTenantRlsTransaction(
        db,
        "postgres-js",
        tenantContextForInternalJob({ tenantId: "tenant-a", job: "retention" }),
        async () => undefined,
      ),
    ).rejects.toThrow("RLS_TENANT_TRANSACTION_NESTED");
    expect(executeCount).toBe(0);
  });

  test("fails before opening a transaction on neon-http", async () => {
    let opened = false;
    const db = {
      async transaction() {
        opened = true;
      },
    };
    await expect(
      withTenantRlsTransaction(
        db as never,
        "neon-http",
        tenantContextForInternalJob({ tenantId: "tenant-a", job: "retention" }),
        async () => undefined,
      ),
    ).rejects.toThrow("RLS_TRANSACTION_UNSUPPORTED");
    expect(opened).toBe(false);
  });

  test("binds tenant context through the transaction-capable Workers driver", async () => {
    let executeCount = 0;
    const tx = {
      async execute() {
        executeCount += 1;
        return executeCount === 4 ? [{ tenant_id: "tenant-worker", user_id: null }] : [];
      },
    };
    const db = {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    };
    const result = await withTenantRlsTransaction(
      db,
      "neon-websocket",
      tenantContextForInternalJob({ tenantId: "tenant-worker", job: "worker-request" }),
      async () => "bound",
    );
    expect(result).toBe("bound");
    expect(executeCount).toBe(4);
  });
});

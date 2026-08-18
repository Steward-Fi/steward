import { describe, expect, test } from "bun:test";
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
        return executeCount === 2 ? [{ tenant_id: "tenant-a" }] : [];
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
    });
    const result = await withTenantRlsTransaction(db, "postgres-js", context, async () => {
      calls.push("callback");
      return 42;
    });
    expect(result).toBe(42);
    expect(calls).toEqual(["transaction", "execute-1", "execute-2", "callback"]);
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
    expect(() => assertTenantRlsDriver("neon-http")).toThrow("RLS_TRANSACTION_UNSUPPORTED");

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
});

import { describe, expect, test } from "bun:test";
import { PgTransaction } from "drizzle-orm/pg-core";
import {
  assertTenantRlsDriver,
  createTenantRlsAuthority,
  type TrustedTenantContext,
} from "../tenant-rls-context";

interface VerifiedPrincipal {
  readonly tenantId: string;
  readonly method: string;
  readonly subject: string;
  readonly verificationToken: symbol;
}

interface ScheduledJob {
  readonly tenantId: string;
  readonly job: string;
  readonly scheduled: boolean;
}

function authority() {
  return createTenantRlsAuthority<VerifiedPrincipal, ScheduledJob>({
    resolveAuthenticatedPrincipal(provenance) {
      return provenance.verificationToken === verificationToken ? provenance : null;
    },
    resolveInternalJob(provenance) {
      return provenance.scheduled ? provenance : null;
    },
  });
}

const verificationToken = Symbol("verified-authentication");

const principal = (tenantId = "tenant-a"): VerifiedPrincipal => ({
  tenantId,
  method: "session-jwt",
  subject: "user:123",
  verificationToken,
});

const job = (tenantId = "tenant-a"): ScheduledJob => ({
  tenantId,
  job: "retention",
  scheduled: true,
});

describe("tenant RLS transaction context", () => {
  test("binds verified provenance before exposing the transaction", async () => {
    const calls: string[] = [];
    let executeCount = 0;
    const tx = {
      async execute() {
        executeCount += 1;
        calls.push(`execute-${executeCount}`);
        return executeCount === 3 ? [{ tenant_id: "tenant-a" }] : [];
      },
    };
    const db = {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        calls.push("transaction");
        return callback(tx);
      },
    };
    const boundary = authority();
    const context = boundary.issuer.fromAuthenticatedPrincipal(principal());
    const result = await boundary.transactions.run(db, "postgres-js", context, async () => {
      calls.push("callback");
      return 42;
    });
    expect(result).toBe(42);
    expect(calls).toEqual(["transaction", "execute-1", "execute-2", "execute-3", "callback"]);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.authority)).toBe(true);
  });

  test("rejects unverified provenance, forged contexts, and contexts from another authority", async () => {
    const boundary = authority();
    expect(() =>
      boundary.issuer.fromAuthenticatedPrincipal({
        ...principal(),
        verificationToken: Symbol("unverified"),
      }),
    ).toThrow("RLS_TENANT_AUTHORITY_UNVERIFIED");
    expect(() => boundary.issuer.forInternalJob({ ...job(), scheduled: false })).toThrow(
      "RLS_TENANT_JOB_UNVERIFIED",
    );
    expect(() =>
      boundary.issuer.fromAuthenticatedPrincipal({
        ...principal(),
        tenantId: "tenant-a\nSET ROLE owner",
      }),
    ).toThrow("RLS_TENANT_CONTEXT_INVALID");
    expect(() =>
      boundary.issuer.fromAuthenticatedPrincipal({
        ...principal(),
        method: "session-jwt\nforged",
      }),
    ).toThrow("RLS_TENANT_AUTHORITY_INVALID");
    expect(() => assertTenantRlsDriver("neon-http")).toThrow("RLS_TRANSACTION_UNSUPPORTED");
    expect(() => assertTenantRlsDriver("neon-websocket")).not.toThrow();

    const db = { transaction: async () => undefined };
    const forged = {
      tenantId: "tenant-a",
      authority: { kind: "internal-job", job: "forged" },
    } as unknown as TrustedTenantContext;
    await expect(
      boundary.transactions.run(db, "postgres-js", forged, async () => undefined),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_UNTRUSTED");

    const otherBoundaryContext = authority().issuer.forInternalJob(job());
    await expect(
      boundary.transactions.run(db, "postgres-js", otherBoundaryContext, async () => undefined),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_UNTRUSTED");

    const genuine = boundary.issuer.forInternalJob(job());
    const cloned = Object.assign({}, genuine, { tenantId: "tenant-b" });
    await expect(
      boundary.transactions.run(
        db,
        "postgres-js",
        cloned as unknown as TrustedTenantContext,
        async () => undefined,
      ),
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
    const boundary = authority();
    await expect(
      boundary.transactions.run(
        db,
        "postgres-js",
        boundary.issuer.forInternalJob(job()),
        async () => {
          callbackCalled = true;
        },
      ),
    ).rejects.toThrow("RLS_TENANT_CONTEXT_DIRTY");
    expect(executeCount).toBe(3);
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
    const boundary = authority();
    await expect(
      boundary.transactions.run(
        db,
        "postgres-js",
        boundary.issuer.forInternalJob(job()),
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
    const boundary = authority();
    expect(() => assertTenantRlsDriver("neon-http")).toThrow("RLS_TRANSACTION_UNSUPPORTED");
    await expect(
      boundary.transactions.run(
        db,
        "neon-http",
        boundary.issuer.forInternalJob(job()),
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
        return executeCount === 3 ? [{ tenant_id: "tenant-worker" }] : [];
      },
    };
    const db = {
      async transaction<T>(callback: (value: typeof tx) => Promise<T>) {
        return callback(tx);
      },
    };
    const boundary = authority();
    const result = await boundary.transactions.run(
      db,
      "neon-websocket",
      boundary.issuer.forInternalJob(job("tenant-worker")),
      async () => "bound",
    );
    expect(result).toBe("bound");
    expect(executeCount).toBe(3);
  });
});

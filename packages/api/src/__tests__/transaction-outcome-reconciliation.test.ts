import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  mock,
  setDefaultTimeout,
} from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { TransactionReceipt } from "viem";
import type { TransactionReceiptClient } from "../services/transaction-receipt-poller";

const TENANT_ID = "receipt-reconcile-tenant";
const AGENT_ID = "receipt-reconcile-agent";
const HASH = `0x${"ab".repeat(32)}` as const;
let pollBroadcastTransactionReceipts: typeof import("../services/transaction-receipt-poller")["pollBroadcastTransactionReceipts"];
let classifyReceiptLifecycle: typeof import("../services/transaction-receipt-poller")["classifyReceiptLifecycle"];
let minConfirmationsForChain: typeof import("../services/transaction-receipt-poller")["minConfirmationsForChain"];
let startTransactionReceiptPollingScheduler: typeof import("../services/transaction-receipt-poller")["startTransactionReceiptPollingScheduler"];
let getTransactionStats: typeof import("../services/context")["getTransactionStats"];
const dispatchedWebhooks: Array<{ type: string; data: Record<string, unknown> }> = [];

mock.module("../services/webhook-dispatch", () => ({
  dispatchWebhook: (
    _tenantId: string,
    _agentId: string,
    type: string,
    data: Record<string, unknown>,
  ) => {
    dispatchedWebhooks.push({ type, data });
  },
}));

setDefaultTimeout(120_000);

function receipt(status: "success" | "reverted" = "success"): TransactionReceipt {
  return {
    blockHash: `0x${"01".repeat(32)}`,
    blockNumber: 100n,
    contractAddress: null,
    cumulativeGasUsed: 21_000n,
    effectiveGasPrice: 1n,
    from: "0x0000000000000000000000000000000000000001",
    gasUsed: 21_000n,
    logs: [],
    logsBloom: `0x${"00".repeat(256)}`,
    status,
    to: "0x0000000000000000000000000000000000000002",
    transactionHash: HASH,
    transactionIndex: 0,
    type: "legacy",
  };
}

async function seedUnknown(id: string, txHash: `0x${string}` = HASH, createdAt?: Date) {
  await getDb()
    .insert(transactions)
    .values({
      id,
      agentId: AGENT_ID,
      status: "outcome_unknown",
      toAddress: "0x0000000000000000000000000000000000000002",
      value: "1",
      chainId: 8453,
      txHash,
      actionType: "transfer",
      actionPayload: { type: "transfer", broadcast: true },
      ...(createdAt ? { createdAt } : {}),
    });
}

describe("outcome_unknown receipt reconciliation", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    process.env.STEWARD_DB_MODE = "pglite";
    process.env.DATABASE_URL = "postgres://pglite.invalid/steward";
    process.env.STEWARD_MASTER_PASSWORD = "receipt-reconciliation-master-password";
    process.env.STEWARD_AUDIT_HMAC_KEY = "d".repeat(64);
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db, async () => client.close());
    ({
      classifyReceiptLifecycle,
      minConfirmationsForChain,
      pollBroadcastTransactionReceipts,
      startTransactionReceiptPollingScheduler,
    } = await import("../services/transaction-receipt-poller"));
    ({ getTransactionStats } = await import("../services/context"));
    await getDb().insert(tenants).values({
      id: TENANT_ID,
      name: "Receipt Reconciliation",
      apiKeyHash: "receipt-reconciliation-hash",
    });
    await getDb().insert(agents).values({
      id: AGENT_ID,
      tenantId: TENANT_ID,
      name: "Receipt Reconciliation Agent",
      walletAddress: "0x0000000000000000000000000000000000000001",
    });
  });

  afterAll(async () => {
    await closeDb();
  });

  afterEach(async () => {
    dispatchedWebhooks.length = 0;
    await getDb().delete(auditEvents).where(eq(auditEvents.tenantId, TENANT_ID));
    await getDb().delete(transactions).where(eq(transactions.agentId, AGENT_ID));
  });

  it("atomically reconciles the exact hash to confirmed without any repost surface", async () => {
    await seedUnknown("unknown-confirmed");
    let receiptReads = 0;
    const client: TransactionReceiptClient = {
      async getTransactionReceipt({ hash }) {
        receiptReads += 1;
        expect(hash).toBe(HASH);
        return receipt();
      },
      async getBlockNumber() {
        return 100n;
      },
    };

    const summary = await pollBroadcastTransactionReceipts({ clientFactory: () => client });
    expect(summary).toMatchObject({ checked: 1, confirmed: 1 });
    expect(receiptReads).toBe(1);
    const [row] = await getDb()
      .select({ status: transactions.status, txHash: transactions.txHash })
      .from(transactions)
      .where(eq(transactions.id, "unknown-confirmed"));
    expect(row).toEqual({ status: "confirmed", txHash: HASH });
    const events = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(eq(auditEvents.resourceId, "unknown-confirmed"));
    expect(events.map(({ action }) => action)).toEqual([
      "transaction.broadcast.reconciled",
      "transaction.confirmed",
    ]);

    const replay = await pollBroadcastTransactionReceipts({ clientFactory: () => client });
    expect(replay.checked).toBe(0);
    expect(receiptReads).toBe(1);
  });

  it("classifies success and reversion only after the required confirmations", () => {
    expect(classifyReceiptLifecycle("success", 2, 3)).toBeNull();
    expect(classifyReceiptLifecycle("reverted", 2, 3)).toBeNull();
    expect(classifyReceiptLifecycle("success", 3, 3)).toBe("transaction.confirmed");
    expect(classifyReceiptLifecycle("reverted", 3, 3)).toBe("transaction.execution_reverted");

    expect(minConfirmationsForChain(1)).toBe(12);
    expect(minConfirmationsForChain(8453)).toBe(1);
    expect(minConfirmationsForChain(1, 6)).toBe(6);
  });

  it("keeps an absent hash unknown and never invents failure", async () => {
    await seedUnknown("unknown-absent");
    const client: TransactionReceiptClient = {
      async getTransactionReceipt() {
        throw new Error("transaction not found");
      },
      async getBlockNumber() {
        throw new Error("must not read the head without a receipt");
      },
    };
    const summary = await pollBroadcastTransactionReceipts({ clientFactory: () => client });
    expect(summary).toMatchObject({ checked: 1, skipped: 1, confirmed: 0, reverted: 0 });
    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "unknown-absent"));
    expect(row?.status).toBe("outcome_unknown");
    expect(dispatchedWebhooks).toEqual([]);
  });

  it("keeps transient receipt and chain-head failures non-terminal", async () => {
    await seedUnknown("unknown-rpc-error");
    const receiptFailureClient: TransactionReceiptClient = {
      async getTransactionReceipt() {
        throw new Error("temporary upstream outage");
      },
      async getBlockNumber() {
        throw new Error("must not read the head without a receipt");
      },
    };
    expect(
      await pollBroadcastTransactionReceipts({ clientFactory: () => receiptFailureClient }),
    ).toMatchObject({ checked: 1, skipped: 1, confirmed: 0, reverted: 0 });

    const headFailureClient: TransactionReceiptClient = {
      async getTransactionReceipt() {
        return receipt();
      },
      async getBlockNumber() {
        throw new Error("temporary head outage");
      },
    };
    expect(
      await pollBroadcastTransactionReceipts({ clientFactory: () => headFailureClient }),
    ).toMatchObject({ checked: 1, skipped: 1, confirmed: 0, reverted: 0 });

    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "unknown-rpc-error"));
    expect(row?.status).toBe("outcome_unknown");
    expect(dispatchedWebhooks).toEqual([]);
  });

  it("finalizes a reverted user operation with durable audits and lifecycle webhooks", async () => {
    await getDb()
      .insert(transactions)
      .values({
        id: "unknown-user-operation-reverted",
        agentId: AGENT_ID,
        status: "outcome_unknown",
        toAddress: "0x0000000000000000000000000000000000000002",
        value: "1",
        chainId: 8453,
        txHash: HASH,
        actionType: "user_operation",
        actionPayload: {
          userOperationHash: `0x${"cd".repeat(32)}`,
          entryPoint: "0x0000000000000000000000000000000000000003",
          sender: "0x0000000000000000000000000000000000000001",
        },
      });
    const client: TransactionReceiptClient = {
      async getTransactionReceipt() {
        return receipt("reverted");
      },
      async getBlockNumber() {
        return 100n;
      },
    };

    expect(await pollBroadcastTransactionReceipts({ clientFactory: () => client })).toMatchObject({
      checked: 1,
      reverted: 1,
    });
    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "unknown-user-operation-reverted"));
    expect(row?.status).toBe("failed");
    const events = await getDb()
      .select({ action: auditEvents.action })
      .from(auditEvents)
      .where(eq(auditEvents.resourceId, "unknown-user-operation-reverted"));
    expect(events.map(({ action }) => action)).toEqual([
      "transaction.broadcast.reconciled",
      "transaction.execution_reverted",
    ]);
    expect(dispatchedWebhooks.map(({ type }) => type)).toEqual([
      "transaction.execution_reverted",
      "user_operation.failed",
    ]);
    expect(dispatchedWebhooks[1]?.data).toMatchObject({
      status: "failed",
      transaction_hash: HASH,
    });
  });

  it("counts outcome_unknown conservatively for cumulative spend policy", async () => {
    await seedUnknown("unknown-spend-policy");
    const stats = await getTransactionStats(AGENT_ID, 8453);
    expect(stats.spentToday).toBe(1n);
    expect(stats.spentThisWeek).toBe(1n);
  });

  it("rejects a mismatched receipt hash from an untrusted RPC", async () => {
    await seedUnknown("unknown-mismatched-receipt");
    const client: TransactionReceiptClient = {
      async getTransactionReceipt() {
        return { ...receipt(), transactionHash: `0x${"ef".repeat(32)}` };
      },
      async getBlockNumber() {
        throw new Error("must not read the head for a mismatched receipt");
      },
    };
    const summary = await pollBroadcastTransactionReceipts({ clientFactory: () => client });
    expect(summary).toMatchObject({ checked: 1, skipped: 1, confirmed: 0, reverted: 0 });
    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "unknown-mismatched-receipt"));
    expect(row?.status).toBe("outcome_unknown");
  });

  it("rotates a missing oldest receipt out of a bounded batch", async () => {
    const firstHash = `0x${"11".repeat(32)}` as const;
    const secondHash = `0x${"22".repeat(32)}` as const;
    await seedUnknown("unknown-oldest", firstHash, new Date("2026-01-01T00:00:00Z"));
    await seedUnknown("unknown-newer", secondHash, new Date("2026-01-02T00:00:00Z"));
    const requested: string[] = [];
    const client: TransactionReceiptClient = {
      async getTransactionReceipt({ hash }) {
        requested.push(hash);
        throw new Error("transaction not found");
      },
      async getBlockNumber() {
        throw new Error("must not read the head without a receipt");
      },
    };
    await pollBroadcastTransactionReceipts({ batchSize: 1, clientFactory: () => client });
    await pollBroadcastTransactionReceipts({ batchSize: 1, clientFactory: () => client });
    expect(requested).toEqual([firstHash, secondHash]);
  });

  it("promotes a proven but under-confirmed receipt only to broadcast", async () => {
    await seedUnknown("unknown-pending");
    const client: TransactionReceiptClient = {
      async getTransactionReceipt() {
        return receipt();
      },
      async getBlockNumber() {
        return 100n;
      },
    };
    const summary = await pollBroadcastTransactionReceipts({
      clientFactory: () => client,
      minConfirmations: 2,
    });
    expect(summary).toMatchObject({ checked: 1, pending: 1 });
    const [row] = await getDb()
      .select({ status: transactions.status })
      .from(transactions)
      .where(eq(transactions.id, "unknown-pending"));
    expect(row?.status).toBe("broadcast");
  });

  it("returns a cancellable no-op when the runtime scheduler is disabled", () => {
    const original = process.env.STEWARD_TRANSACTION_RECEIPT_POLLER;
    process.env.STEWARD_TRANSACTION_RECEIPT_POLLER = "false";
    try {
      const cancel = startTransactionReceiptPollingScheduler();
      expect(cancel).toBeFunction();
      expect(cancel()).toBeUndefined();
    } finally {
      if (original === undefined) delete process.env.STEWARD_TRANSACTION_RECEIPT_POLLER;
      else process.env.STEWARD_TRANSACTION_RECEIPT_POLLER = original;
    }
  });
});

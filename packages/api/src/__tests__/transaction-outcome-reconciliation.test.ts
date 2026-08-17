import { afterAll, afterEach, beforeAll, describe, expect, it, setDefaultTimeout } from "bun:test";
import { agents, auditEvents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { eq } from "drizzle-orm";
import type { TransactionReceipt } from "viem";
import type { TransactionReceiptClient } from "../services/transaction-receipt-poller";

const TENANT_ID = "receipt-reconcile-tenant";
const AGENT_ID = "receipt-reconcile-agent";
const HASH = `0x${"ab".repeat(32)}` as const;
let pollBroadcastTransactionReceipts: typeof import("../services/transaction-receipt-poller")["pollBroadcastTransactionReceipts"];
let getTransactionStats: typeof import("../services/context")["getTransactionStats"];

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

async function seedUnknown(id: string) {
  await getDb()
    .insert(transactions)
    .values({
      id,
      agentId: AGENT_ID,
      status: "outcome_unknown",
      toAddress: "0x0000000000000000000000000000000000000002",
      value: "1",
      chainId: 8453,
      txHash: HASH,
      actionType: "transfer",
      actionPayload: { type: "transfer", broadcast: true },
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
    ({ pollBroadcastTransactionReceipts } = await import("../services/transaction-receipt-poller"));
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
});

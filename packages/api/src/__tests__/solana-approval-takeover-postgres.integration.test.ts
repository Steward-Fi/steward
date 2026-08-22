import { expect, it } from "bun:test";
import {
  agents,
  approvalQueue,
  auditChainHeads,
  auditEvents,
  createDb,
  tenants,
  transactions,
} from "@stwd/db";
import { eq } from "drizzle-orm";

const databaseUrl = process.env.DATABASE_URL;
const realPostgresIt = databaseUrl && !process.env.STEWARD_PGLITE_MEMORY ? it : it.skip;

realPostgresIt(
  "allows exactly one authorized different-admin takeover of an expired Solana claim",
  async () => {
    const suffix = crypto.randomUUID().replaceAll("-", "");
    const tenantId = `solana-takeover-${suffix}`;
    const agentId = `solana-takeover-agent-${suffix}`;
    const txId = `solana-takeover-tx-${suffix}`;
    const admin = createDb(databaseUrl!);
    try {
      await admin.db.insert(tenants).values({
        id: tenantId,
        name: tenantId,
        apiKeyHash: `hash-${tenantId}`,
      });
      await admin.db.insert(agents).values({
        id: agentId,
        tenantId,
        name: agentId,
        walletAddress: "7v54NWdBtkjuAFJrLGsS2SXnuk8nKam81mZJeeYxVFi9",
      });
      await admin.db.insert(transactions).values({
        id: txId,
        agentId,
        status: "pending",
        toAddress: "6TcyBfPdBt1kjsvDZLzmBFnuMaLWiTaAt4RjUr9VA5YD",
        value: "42",
        data: "serialized-solana-takeover",
        chainId: 101,
        actionType: "transaction",
        actionPayload: {
          type: "transaction",
          broadcast: true,
        },
        policyResults: [],
      });
      await admin.db.insert(approvalQueue).values({
        id: `approval-${suffix}`,
        txId,
        agentId,
        status: "approved",
        resolvedAt: new Date(),
        resolvedBy: "user:original-admin",
        resolvedByType: "user",
        resolvedById: "original-admin",
      });

      const { claimApprovedSolanaExecution } = await import("../routes/vault");
      const [unclaimed] = await admin.db
        .select()
        .from(transactions)
        .where(eq(transactions.id, txId));
      const initial = await claimApprovedSolanaExecution(unclaimed, {
        takeover: false,
        resolver: { type: "user", id: "original-admin" },
      });
      await admin.db
        .update(transactions)
        .set({
          actionPayload: {
            ...initial.actionPayload,
            attemptLeaseUntil: new Date(Date.now() - 60_000).toISOString(),
          },
        })
        .where(eq(transactions.id, txId));
      const [row] = await admin.db.select().from(transactions).where(eq(transactions.id, txId));
      const attempts = await Promise.allSettled([
        claimApprovedSolanaExecution(row, {
          takeover: true,
          resolver: { type: "user", id: "replacement-admin-a" },
        }),
        claimApprovedSolanaExecution(row, {
          takeover: true,
          resolver: { type: "user", id: "replacement-admin-b" },
        }),
      ]);
      expect(attempts.filter((attempt) => attempt.status === "fulfilled")).toHaveLength(1);
      expect(attempts.filter((attempt) => attempt.status === "rejected")).toHaveLength(1);

      const winner = attempts.find((attempt) => attempt.status === "fulfilled");
      if (!winner || winner.status !== "fulfilled") throw new Error("takeover winner missing");
      const [storedTransaction] = await admin.db
        .select()
        .from(transactions)
        .where(eq(transactions.id, txId));
      const [storedApproval] = await admin.db
        .select()
        .from(approvalQueue)
        .where(eq(approvalQueue.txId, txId));
      expect(storedTransaction.actionPayload).toMatchObject({
        executionToken: winner.value.executionToken,
      });
      expect(["replacement-admin-a", "replacement-admin-b"]).toContain(storedApproval.resolvedById);
      expect(storedApproval.resolvedBy).toBe(`user:${storedApproval.resolvedById}`);
    } finally {
      await admin.db.delete(approvalQueue).where(eq(approvalQueue.agentId, agentId));
      await admin.db
        .update(transactions)
        .set({ status: "failed" })
        .where(eq(transactions.id, txId));
      await admin.db.delete(transactions).where(eq(transactions.id, txId));
      await admin.db.delete(auditEvents).where(eq(auditEvents.tenantId, tenantId));
      await admin.db.delete(auditChainHeads).where(eq(auditChainHeads.tenantId, tenantId));
      await admin.db.delete(agents).where(eq(agents.id, agentId));
      await admin.db.delete(tenants).where(eq(tenants.id, tenantId));
      await admin.client.end();
    }
  },
  120_000,
);

import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { agents, closeDb, getDb, tenants, transactions } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import type { SignRequest } from "@stwd/shared";
import { eq } from "drizzle-orm";
import { Vault } from "../vault";

const tenantId = `transaction-owner-${crypto.randomUUID()}`;
const firstAgentId = `transaction-owner-first-${crypto.randomUUID()}`;
const secondAgentId = `transaction-owner-second-${crypto.randomUUID()}`;
const txId = `transaction-owner-tx-${crypto.randomUUID()}`;

type TransactionRecorder = {
  recordSignedTransaction(
    request: SignRequest,
    chainId: number,
    shouldBroadcast: boolean,
    hash: string,
    options: { txId: string; status?: "signed" | "broadcast" | "outcome_unknown" },
  ): Promise<void>;
};

function requestFor(agentId: string, value: string): SignRequest {
  return {
    tenantId,
    agentId,
    to: "0x0000000000000000000000000000000000000001",
    value,
    chainId: 1,
    broadcast: true,
  };
}

describe("transaction id hardening", () => {
  beforeAll(async () => {
    process.env.STEWARD_PGLITE_MEMORY = "true";
    const { db, client } = await createPGLiteDb("memory://");
    setPGLiteOverride(db as never, async () => client.close());
    await getDb()
      .insert(tenants)
      .values({
        id: tenantId,
        name: "Transaction ownership tenant",
        apiKeyHash: `hash-${tenantId}`,
      });
    await getDb()
      .insert(agents)
      .values([
        {
          id: firstAgentId,
          tenantId,
          name: "First transaction owner",
          walletAddress: "0x0000000000000000000000000000000000000011",
        },
        {
          id: secondAgentId,
          tenantId,
          name: "Second transaction owner",
          walletAddress: "0x0000000000000000000000000000000000000022",
        },
      ]);
  });

  afterAll(async () => {
    await closeDb();
    delete process.env.STEWARD_PGLITE_MEMORY;
  });

  test("updates a transaction only for its existing agent", async () => {
    const recorder = new Vault({
      masterPassword: "transaction-owner-test",
    }) as unknown as TransactionRecorder;
    await recorder.recordSignedTransaction(requestFor(firstAgentId, "1"), 1, true, "0xfirst", {
      txId,
      status: "outcome_unknown",
    });
    await recorder.recordSignedTransaction(requestFor(firstAgentId, "2"), 1, true, "0xupdated", {
      txId,
      status: "broadcast",
    });

    await expect(
      recorder.recordSignedTransaction(requestFor(secondAgentId, "3"), 1, true, "0xhostile", {
        txId,
        status: "broadcast",
      }),
    ).rejects.toThrow("Transaction id already belongs to a different agent");

    const [recorded] = await getDb().select().from(transactions).where(eq(transactions.id, txId));
    expect(recorded?.agentId).toBe(firstAgentId);
    expect(recorded?.value).toBe("2");
    expect(recorded?.txHash).toBe("0xupdated");
    expect(recorded?.status).toBe("broadcast");
  });
});

import { afterAll, beforeEach, describe, expect, setDefaultTimeout, spyOn, test } from "bun:test";
import {
  ComputeBudgetProgram,
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import { getDb, tenants } from "@stwd/db";
import { createPGLiteDb, setPGLiteOverride } from "@stwd/db/pglite";
import { ExternalBroadcastOutcomeUnknownError } from "../external-key-custody";
import { Vault } from "../vault";

const MASTER_PASSWORD = "test-vault-solana-priority-fee";
const TENANT_ID = "vault-solana-priority-fee-tenant";
const AGENT_ID = "vault-solana-priority-fee-agent";
const RECENT_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(11)).toBase58();
const SUBMITTED_SIGNATURE =
  "4oL4p7QvN3UH7V5wMGZgW5PuzEk4A9LXLHk9RxAoKjDKuLbQBsfXN8kEvKfj5K1oEJa8wFF6RVp2h7pP9w2f51ZV";

setDefaultTimeout(30000);

const openClients: Array<{ close: () => Promise<void> }> = [];

function toBase64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
}

function fromBase64(serialized: string): Uint8Array {
  return Uint8Array.from(atob(serialized), (c) => c.charCodeAt(0));
}

async function freshVault(): Promise<Vault> {
  const { db, client } = await createPGLiteDb("memory://");
  openClients.push(client);
  setPGLiteOverride(db as never, async () => {
    await client.close();
  });

  await getDb().insert(tenants).values({
    id: TENANT_ID,
    name: "Vault Solana Priority Fee Tenant",
    apiKeyHash: "test-hash",
  });

  return new Vault({ masterPassword: MASTER_PASSWORD });
}

async function createSolanaAgent(vault: Vault): Promise<PublicKey> {
  const identity = await vault.createAgent(TENANT_ID, AGENT_ID, "Priority Fee Agent");
  const solanaAddress = identity.walletAddresses?.solana;
  if (!solanaAddress) throw new Error("test agent did not receive a Solana wallet");
  return new PublicKey(solanaAddress);
}

function legacyTransferWithPriorityFee(
  feePayer: PublicKey,
  microLamports: number,
  units = 1_400_000,
): string {
  const tx = new Transaction({ feePayer, recentBlockhash: RECENT_BLOCKHASH }).add(
    ComputeBudgetProgram.setComputeUnitLimit({ units }),
    ComputeBudgetProgram.setComputeUnitPrice({ microLamports }),
    SystemProgram.transfer({
      fromPubkey: feePayer,
      toPubkey: PublicKey.unique(),
      lamports: 1,
    }),
  );
  return toBase64(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
}

function v0TransferWithPriorityFee(
  feePayer: PublicKey,
  microLamports: number,
  units = 1_400_000,
): string {
  const msg = new TransactionMessage({
    payerKey: feePayer,
    recentBlockhash: RECENT_BLOCKHASH,
    instructions: [
      ComputeBudgetProgram.setComputeUnitLimit({ units }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports }),
      SystemProgram.transfer({
        fromPubkey: feePayer,
        toPubkey: PublicKey.unique(),
        lamports: 1,
      }),
    ],
  }).compileToV0Message();
  return toBase64(new VersionedTransaction(msg).serialize());
}

describe("Vault.signSolanaTransaction priority fee cap", () => {
  let vault: Vault;

  beforeEach(async () => {
    vault = await freshVault();
  });

  afterAll(async () => {
    for (const client of openClients) {
      await client.close().catch(() => {});
    }
    openClients.length = 0;
  });

  test("rejects an over-cap v0 transaction before signing without an expected envelope", async () => {
    const feePayer = await createSolanaAgent(vault);

    await expect(
      vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: v0TransferWithPriorityFee(feePayer, 1_000_000),
        broadcast: false,
        // SEC-163: these tests intentionally exercise the no-envelope path.
        allowBlindSign: true,
      }),
    ).rejects.toThrow(/priority fee.*exceeds the allowed maximum/i);
  });

  test("rejects an over-cap legacy transaction before signing without an expected envelope", async () => {
    const feePayer = await createSolanaAgent(vault);

    await expect(
      vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: legacyTransferWithPriorityFee(feePayer, 1_000_000),
        broadcast: false,
        allowBlindSign: true,
      }),
    ).rejects.toThrow(/priority fee.*exceeds the allowed maximum/i);
  });

  test("signs a transaction whose priority fee is within the cap", async () => {
    const feePayer = await createSolanaAgent(vault);

    const result = await vault.signSolanaTransaction({
      tenantId: TENANT_ID,
      agentId: AGENT_ID,
      transaction: legacyTransferWithPriorityFee(feePayer, 1_000),
      broadcast: false,
      allowBlindSign: true,
    });

    const signed = Transaction.from(fromBase64(result.signature));
    expect(result.broadcast).toBe(false);
    expect(signed.signatures.some(({ signature }) => signature?.some((b) => b !== 0))).toBe(true);
  });

  test("aborts before network I/O when the durable pre-broadcast checkpoint fails", async () => {
    const feePayer = await createSolanaAgent(vault);
    let sendCalls = 0;
    let blockhashCalls = 0;
    let confirmCalls = 0;
    const send = spyOn(Connection.prototype, "sendRawTransaction").mockImplementation(async () => {
      sendCalls += 1;
      return SUBMITTED_SIGNATURE;
    });
    const getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockImplementation(
      async () => {
        blockhashCalls += 1;
        return { blockhash: RECENT_BLOCKHASH, lastValidBlockHeight: 100 };
      },
    );
    const confirm = spyOn(Connection.prototype, "confirmTransaction").mockImplementation(
      async () => {
        confirmCalls += 1;
        return { context: { slot: 1 }, value: { err: null } };
      },
    );
    let error: unknown;
    try {
      await vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: legacyTransferWithPriorityFee(feePayer, 1_000),
        broadcast: true,
        allowBlindSign: true,
        onBroadcastPrepared: async (signature) => {
          expect(signature).toBeString();
          throw new Error("injected durable checkpoint failure");
        },
      });
    } catch (caught) {
      error = caught;
    } finally {
      send.mockRestore();
      getBlockhash.mockRestore();
      confirm.mockRestore();
    }

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
    expect((error as Error).message).toBe("injected durable checkpoint failure");
    expect(sendCalls).toBe(0);
    expect(blockhashCalls).toBe(0);
    expect(confirmCalls).toBe(0);
  });

  test("checkpoints before confirmation and retains the hash when confirmation fails", async () => {
    const feePayer = await createSolanaAgent(vault);
    const order: string[] = [];
    let preparedSignature = "";
    const send = spyOn(Connection.prototype, "sendRawTransaction").mockImplementation(async () => {
      order.push("submitted");
      return preparedSignature;
    });
    const getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockResolvedValue({
      blockhash: RECENT_BLOCKHASH,
      lastValidBlockHeight: 100,
    });
    const confirm = spyOn(Connection.prototype, "confirmTransaction").mockImplementation(
      async () => {
        order.push("confirmation");
        throw new Error("injected confirmation failure");
      },
    );
    let error: unknown;
    try {
      await vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: legacyTransferWithPriorityFee(feePayer, 1_000),
        broadcast: true,
        allowBlindSign: true,
        onBroadcastPrepared: async (signature) => {
          preparedSignature = signature;
          order.push("checkpoint");
        },
      });
    } catch (caught) {
      error = caught;
    } finally {
      send.mockRestore();
      getBlockhash.mockRestore();
      confirm.mockRestore();
    }

    expect(error).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
    expect((error as ExternalBroadcastOutcomeUnknownError).transactionHash).toBe(preparedSignature);
    expect(preparedSignature).not.toBe("");
    expect(order).toEqual(["checkpoint", "submitted", "confirmation"]);
  });

  test("retains the prepared hash when sendRawTransaction may have accepted but loses its response", async () => {
    const feePayer = await createSolanaAgent(vault);
    let preparedSignature = "";
    let sendCalls = 0;
    const send = spyOn(Connection.prototype, "sendRawTransaction").mockImplementation(async () => {
      sendCalls += 1;
      throw new Error("injected transport loss after submission");
    });
    const getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockResolvedValue({
      blockhash: RECENT_BLOCKHASH,
      lastValidBlockHeight: 100,
    });
    const confirm = spyOn(Connection.prototype, "confirmTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null },
    });
    let error: unknown;
    try {
      await vault.signSolanaTransaction({
        tenantId: TENANT_ID,
        agentId: AGENT_ID,
        transaction: legacyTransferWithPriorityFee(feePayer, 1_000),
        broadcast: true,
        allowBlindSign: true,
        onBroadcastPrepared: async (signature) => {
          preparedSignature = signature;
        },
      });
    } catch (caught) {
      error = caught;
    } finally {
      send.mockRestore();
      getBlockhash.mockRestore();
      confirm.mockRestore();
    }

    expect(sendCalls).toBe(1);
    expect(preparedSignature).not.toBe("");
    expect(error).toBeInstanceOf(ExternalBroadcastOutcomeUnknownError);
    expect((error as ExternalBroadcastOutcomeUnknownError).transactionHash).toBe(preparedSignature);
  });
});

import { describe, expect, it } from "bun:test";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import { normalizedSolanaMessageDigest } from "../solana";

const PAYER = Keypair.fromSeed(new Uint8Array(32).fill(1));
const RECIPIENT = Keypair.fromSeed(new Uint8Array(32).fill(2)).publicKey;
const MEMO_PROGRAM = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

function serializedIntent(input: {
  blockhashByte: number;
  computeUnits: number;
  memo: string;
}): string {
  const transaction = new Transaction({
    feePayer: PAYER.publicKey,
    recentBlockhash: new PublicKey(new Uint8Array(32).fill(input.blockhashByte)).toBase58(),
  }).add(
    ComputeBudgetProgram.setComputeUnitLimit({ units: input.computeUnits }),
    SystemProgram.transfer({ fromPubkey: PAYER.publicKey, toPubkey: RECIPIENT, lamports: 42 }),
    new TransactionInstruction({
      data: Buffer.from(input.memo),
      keys: [],
      programId: MEMO_PROGRAM,
    }),
  );
  transaction.partialSign(PAYER);
  return Buffer.from(transaction.serialize()).toString("base64");
}

describe("normalized Solana message digest", () => {
  it("excludes signatures and the recent blockhash but binds memo and compute-budget bytes", () => {
    const original = serializedIntent({ blockhashByte: 7, computeUnits: 250_000, memo: "pay-42" });
    const refreshed = serializedIntent({
      blockhashByte: 8,
      computeUnits: 250_000,
      memo: "pay-42",
    });
    const changedMemo = serializedIntent({
      blockhashByte: 7,
      computeUnits: 250_000,
      memo: "pay-43",
    });
    const changedBudget = serializedIntent({
      blockhashByte: 7,
      computeUnits: 300_000,
      memo: "pay-42",
    });

    const changedSignature = Uint8Array.from(Buffer.from(original, "base64"));
    changedSignature[1] ^= 0xff;

    expect(normalizedSolanaMessageDigest(refreshed)).toBe(normalizedSolanaMessageDigest(original));
    expect(normalizedSolanaMessageDigest(Buffer.from(changedSignature).toString("base64"))).toBe(
      normalizedSolanaMessageDigest(original),
    );
    expect(normalizedSolanaMessageDigest(changedMemo)).not.toBe(
      normalizedSolanaMessageDigest(original),
    );
    expect(normalizedSolanaMessageDigest(changedBudget)).not.toBe(
      normalizedSolanaMessageDigest(original),
    );
  });
});

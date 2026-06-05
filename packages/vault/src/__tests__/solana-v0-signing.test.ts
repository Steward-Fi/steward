/**
 * Regression: v0 (versioned) Solana transactions must be signable.
 *
 * The sign-solana policy gate deserializes with VersionedTransaction (handles v0),
 * but the vault sign path used legacy `Transaction.from()`, which throws on a
 * versioned message, so every v0 tx (the modern default, mandatory for ALT DeFi
 * like Jupiter) passed policy then 500'd at signing. The fix branches on the
 * version byte and verifies the v0 transfer envelope via the version-aware parser
 * (assertParsedSolanaTransferMatches) since the legacy byte assertion can't read v0.
 */
import { describe, expect, test } from "bun:test";
import {
  ComputeBudgetProgram,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  type TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import {
  assertParsedSolanaTransferMatches,
  isVersionedTransactionBytes,
} from "../solana-instructions";

const RECENT_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();

function v0TransferBytes(from: Keypair, to: PublicKey, lamports: number): Uint8Array {
  return v0TransferSetBytes(from, [{ to, lamports }]);
}

function v0TransferWithInstructionsBytes(
  from: Keypair,
  instructions: TransactionInstruction[],
): Uint8Array {
  const msg = new TransactionMessage({
    payerKey: from.publicKey,
    recentBlockhash: RECENT_BLOCKHASH,
    instructions,
  }).compileToV0Message();
  return new VersionedTransaction(msg).serialize();
}

function v0TransferSetBytes(
  from: Keypair,
  transfers: Array<{ to: PublicKey; lamports: number }>,
): Uint8Array {
  const msg = new TransactionMessage({
    payerKey: from.publicKey,
    recentBlockhash: RECENT_BLOCKHASH,
    instructions: transfers.map(({ to, lamports }) =>
      SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: to, lamports }),
    ),
  }).compileToV0Message();
  return new VersionedTransaction(msg).serialize();
}

function toBase64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
}

describe("v0 (versioned) Solana signing", () => {
  test("a v0 transfer deserializes + signs (legacy Transaction.from throws on it)", () => {
    const from = Keypair.generate();
    const to = Keypair.generate().publicKey;
    const bytes = v0TransferBytes(from, to, 1000);

    // The version detection the sign path branches on (shortvec-aware).
    expect(isVersionedTransactionBytes(bytes)).toBe(true);
    // The bug: the legacy deserializer throws on a versioned message.
    expect(() => Transaction.from(bytes)).toThrow(/Versioned messages/i);
    // The fix path: deserialize + sign as a VersionedTransaction works.
    const vtx = VersionedTransaction.deserialize(bytes);
    vtx.sign([from]);
    expect(vtx.signatures.some((s) => s.some((b) => b !== 0))).toBe(true);
  });

  test("assertParsedSolanaTransferMatches accepts a matching v0 transfer", () => {
    const from = Keypair.generate();
    const to = Keypair.generate().publicKey;
    const b64 = toBase64(v0TransferBytes(from, to, 5000));
    expect(() =>
      assertParsedSolanaTransferMatches(b64, { to: to.toBase58(), lamports: 5000n }),
    ).not.toThrow();
  });

  test("assertParsedSolanaTransferMatches accepts a v0 transfer with a prepended compute budget limit", () => {
    const from = Keypair.generate();
    const to = Keypair.generate().publicKey;
    const b64 = toBase64(
      v0TransferWithInstructionsBytes(from, [
        ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
        SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: to, lamports: 5000 }),
      ]),
    );
    expect(() =>
      assertParsedSolanaTransferMatches(b64, {
        from: from.publicKey.toBase58(),
        to: to.toBase58(),
        lamports: 5000n,
      }),
    ).not.toThrow();
  });

  test("assertParsedSolanaTransferMatches rejects a mismatched source, recipient, or amount (v0)", () => {
    const from = Keypair.generate();
    const to = Keypair.generate().publicKey;
    const attacker = Keypair.generate().publicKey;
    const b64 = toBase64(v0TransferBytes(from, to, 5000));
    expect(() =>
      assertParsedSolanaTransferMatches(b64, {
        from: attacker.toBase58(),
        to: to.toBase58(),
        lamports: 5000n,
      }),
    ).toThrow(/source does not match/i);
    expect(() =>
      assertParsedSolanaTransferMatches(b64, { to: attacker.toBase58(), lamports: 5000n }),
    ).toThrow(/does not match/i);
    expect(() =>
      assertParsedSolanaTransferMatches(b64, { to: to.toBase58(), lamports: 9999n }),
    ).toThrow(/does not match/i);
  });

  test("assertParsedSolanaTransferMatches rejects v0 transactions with extra recipients", () => {
    const from = Keypair.generate();
    const approved = Keypair.generate().publicKey;
    const attacker = Keypair.generate().publicKey;
    const b64 = toBase64(
      v0TransferSetBytes(from, [
        { to: approved, lamports: 1 },
        { to: attacker, lamports: 99 },
      ]),
    );
    expect(() =>
      assertParsedSolanaTransferMatches(b64, {
        from: from.publicKey.toBase58(),
        to: approved.toBase58(),
        lamports: 100n,
      }),
    ).toThrow(/single policy-checked transfer/i);
  });

  test("the envelope helper also verifies legacy transfers", () => {
    const from = Keypair.generate();
    const to = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from.publicKey, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: from.publicKey, toPubkey: to, lamports: 7000 }),
    );
    const bytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    expect(isVersionedTransactionBytes(bytes)).toBe(false); // legacy
    expect(() =>
      assertParsedSolanaTransferMatches(toBase64(bytes), { to: to.toBase58(), lamports: 7000n }),
    ).not.toThrow();
  });
});

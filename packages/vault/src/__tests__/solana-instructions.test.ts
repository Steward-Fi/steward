import { describe, expect, test } from "bun:test";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  type TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";

import {
  deriveSolanaPolicyFields,
  detectSolanaPolicyConflicts,
  parseSolanaTransaction,
  TOKEN_PROGRAM_ID,
} from "../solana-instructions";

// Deterministic blockhash for building unsigned messages (32-byte base58).
const RECENT_BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();

function legacyToBase64(tx: Transaction): string {
  // requireAllSignatures: false → serialize an unsigned message for parsing.
  const bytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
  return Buffer.from(bytes).toString("base64");
}

function v0ToBase64(instructions: TransactionInstruction[], payer: PublicKey): string {
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: RECENT_BLOCKHASH,
    instructions,
  }).compileToV0Message();
  const vtx = new VersionedTransaction(msg);
  return Buffer.from(vtx.serialize()).toString("base64");
}

// ─── Helpers to hand-build SPL Token instructions (avoids @solana/spl-token dep) ──

const TOKEN_PROGRAM = new PublicKey(TOKEN_PROGRAM_ID);

function u64LE(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  let v = value;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function tokenTransferIx(args: {
  source: PublicKey;
  destination: PublicKey;
  owner: PublicKey;
  amount: bigint;
}): TransactionInstruction {
  const data = Buffer.concat([Buffer.from([3]), Buffer.from(u64LE(args.amount))]);
  return {
    programId: TOKEN_PROGRAM,
    keys: [
      { pubkey: args.source, isSigner: false, isWritable: true },
      { pubkey: args.destination, isSigner: false, isWritable: true },
      { pubkey: args.owner, isSigner: true, isWritable: false },
    ],
    data,
  } as unknown as TransactionInstruction;
}

function tokenTransferCheckedIx(args: {
  source: PublicKey;
  mint: PublicKey;
  destination: PublicKey;
  owner: PublicKey;
  amount: bigint;
  decimals: number;
}): TransactionInstruction {
  const data = Buffer.concat([
    Buffer.from([12]),
    Buffer.from(u64LE(args.amount)),
    Buffer.from([args.decimals]),
  ]);
  return {
    programId: TOKEN_PROGRAM,
    keys: [
      { pubkey: args.source, isSigner: false, isWritable: true },
      { pubkey: args.mint, isSigner: false, isWritable: false },
      { pubkey: args.destination, isSigner: false, isWritable: true },
      { pubkey: args.owner, isSigner: true, isWritable: false },
    ],
    data,
  } as unknown as TransactionInstruction;
}

function rawIx(programId: PublicKey, keys: PublicKey[], data: Uint8Array): TransactionInstruction {
  return {
    programId,
    keys: keys.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
    data: Buffer.from(data),
  } as unknown as TransactionInstruction;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe("parseSolanaTransaction — System transfer (legacy)", () => {
  test("decodes the REAL recipient and lamports from bytes", () => {
    const from = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const lamports = 1_234_567n;

    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: Number(lamports) }),
    );

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(true);
    expect(summary.version).toBe("legacy");
    expect(summary.instructions).toHaveLength(1);
    expect(summary.instructions[0].instructionType).toBe("system:Transfer");
    expect(summary.instructions[0].fields.from).toBe(from.toBase58());
    expect(summary.instructions[0].fields.to).toBe(to.toBase58());
    expect(summary.instructions[0].fields.lamports).toBe(lamports.toString());
    expect(summary.totalLamports).toBe(lamports.toString());
    expect(summary.lamportRecipients).toEqual([to.toBase58()]);

    const derived = deriveSolanaPolicyFields(summary);
    expect(derived.to).toBe(to.toBase58());
    expect(derived.value).toBe(lamports.toString());
    expect(derived.movesNativeSol).toBe(true);
  });

  test("base58-encoded transaction payloads also parse", () => {
    const from = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 42 }),
    );
    const bytes = tx.serialize({ requireAllSignatures: false, verifySignatures: false });
    const bs58 = require("bs58");
    const base58Payload = bs58.default ? bs58.default.encode(bytes) : bs58.encode(bytes);

    const summary = parseSolanaTransaction(base58Payload);
    expect(summary.fullyParsed).toBe(true);
    expect(summary.instructions[0].fields.to).toBe(to.toBase58());
    expect(summary.totalLamports).toBe("42");
  });
});

describe("parseSolanaTransaction — SPL token transfer", () => {
  test("TransferChecked decodes mint, amount, decimals, and destination", () => {
    const payer = Keypair.generate().publicKey;
    const source = Keypair.generate().publicKey;
    const mint = Keypair.generate().publicKey;
    const dest = Keypair.generate().publicKey;
    const owner = payer;
    const amount = 5_000_000n;

    const ix = tokenTransferCheckedIx({
      source,
      mint,
      destination: dest,
      owner,
      amount,
      decimals: 6,
    });
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(true);
    expect(summary.tokenTransfers).toHaveLength(1);
    const t = summary.tokenTransfers[0];
    expect(t.source).toBe(source.toBase58());
    expect(t.mint).toBe(mint.toBase58());
    expect(t.destination).toBe(dest.toBase58());
    expect(t.authority).toBe(owner.toBase58());
    expect(t.amount).toBe(amount.toString());
    expect(t.decimals).toBe(6);

    // Token-only tx: policy envelope uses the token destination + token amount.
    const derived = deriveSolanaPolicyFields(summary);
    expect(derived.movesNativeSol).toBe(false);
    expect(derived.to).toBe(dest.toBase58());
    expect(derived.value).toBe(amount.toString());
    expect(derived.mints).toEqual([mint.toBase58()]);
  });

  test("plain Transfer (unchecked) decodes source/dest/authority/amount", () => {
    const payer = Keypair.generate().publicKey;
    const source = Keypair.generate().publicKey;
    const dest = Keypair.generate().publicKey;
    const amount = 99n;
    const ix = tokenTransferIx({ source, destination: dest, owner: payer, amount });
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(true);
    expect(summary.instructions[0].instructionType).toBe("spl-token:Transfer");
    expect(summary.tokenTransfers[0].destination).toBe(dest.toBase58());
    expect(summary.tokenTransfers[0].amount).toBe("99");
    expect(summary.tokenTransfers[0].mint).toBeUndefined();
  });
});

describe("parseSolanaTransaction — v0 versioned message", () => {
  test("a v0 message parses correctly with real recipient/lamports", () => {
    const payer = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const lamports = 7_777n;

    const base64 = v0ToBase64(
      [SystemProgram.transfer({ fromPubkey: payer, toPubkey: to, lamports: Number(lamports) })],
      payer,
    );

    const summary = parseSolanaTransaction(base64);
    expect(summary.version).toBe(0);
    expect(summary.fullyParsed).toBe(true);
    expect(summary.instructions[0].instructionType).toBe("system:Transfer");
    expect(summary.instructions[0].fields.to).toBe(to.toBase58());
    expect(summary.totalLamports).toBe(lamports.toString());

    const derived = deriveSolanaPolicyFields(summary);
    expect(derived.to).toBe(to.toBase58());
    expect(derived.value).toBe(lamports.toString());
  });

  test("v0 SPL token transfer also parses", () => {
    const payer = Keypair.generate().publicKey;
    const source = Keypair.generate().publicKey;
    const mint = Keypair.generate().publicKey;
    const dest = Keypair.generate().publicKey;
    const base64 = v0ToBase64(
      [
        tokenTransferCheckedIx({
          source,
          mint,
          destination: dest,
          owner: payer,
          amount: 10n,
          decimals: 9,
        }),
      ],
      payer,
    );
    const summary = parseSolanaTransaction(base64);
    expect(summary.version).toBe(0);
    expect(summary.fullyParsed).toBe(true);
    expect(summary.tokenTransfers[0].mint).toBe(mint.toBase58());
    expect(summary.tokenTransfers[0].decimals).toBe(9);
  });
});

describe("SPOOF RESISTANCE — caller hints vs parsed bytes", () => {
  test("benign caller 'to'/'value' that disagree with the tx are flagged as conflicts", () => {
    const from = Keypair.generate().publicKey;
    const realRecipient = Keypair.generate().publicKey;
    const lamports = 5_000_000_000n; // 5 SOL actually being moved

    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({
        fromPubkey: from,
        toPubkey: realRecipient,
        lamports: Number(lamports),
      }),
    );
    const summary = parseSolanaTransaction(legacyToBase64(tx));
    const derived = deriveSolanaPolicyFields(summary);

    // Attacker claims a tiny transfer to a different (allow-listed) address.
    const benignDecoy = Keypair.generate().publicKey.toBase58();
    const conflicts = detectSolanaPolicyConflicts(derived, { to: benignDecoy, value: "1" });

    expect(conflicts.length).toBeGreaterThan(0);
    // Both the recipient and the value must be caught.
    expect(conflicts.some((c) => c.includes("recipient"))).toBe(true);
    expect(conflicts.some((c) => c.includes("value"))).toBe(true);
  });

  test("matching caller hints produce no conflicts", () => {
    const from = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 250 }),
    );
    const derived = deriveSolanaPolicyFields(parseSolanaTransaction(legacyToBase64(tx)));
    const conflicts = detectSolanaPolicyConflicts(derived, {
      to: to.toBase58(),
      value: "250",
    });
    expect(conflicts).toEqual([]);
  });

  test("leading-zero / equivalent values do not produce false conflicts", () => {
    const from = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 1000 }),
    );
    const derived = deriveSolanaPolicyFields(parseSolanaTransaction(legacyToBase64(tx)));
    expect(detectSolanaPolicyConflicts(derived, { value: "0000001000" })).toEqual([]);
  });
});

describe("FAIL CLOSED — undecodable instructions", () => {
  test("unknown program id is reported unparsed (never treated as safe)", () => {
    const payer = Keypair.generate().publicKey;
    const unknownProgram = Keypair.generate().publicKey; // random, not a known program
    const ix = rawIx(unknownProgram, [Keypair.generate().publicKey], new Uint8Array([1, 2, 3, 4]));
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(false);
    expect(summary.instructions[0].unparsed).toBe(true);
    expect(summary.instructions[0].reason).toContain("unrecognised program id");
    expect(summary.unparsedReasons.length).toBeGreaterThan(0);
  });

  test("a known System transfer mixed with an unknown program still fails closed overall", () => {
    const from = Keypair.generate().publicKey;
    const to = Keypair.generate().publicKey;
    const unknownProgram = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH })
      .add(SystemProgram.transfer({ fromPubkey: from, toPubkey: to, lamports: 10 }))
      .add(rawIx(unknownProgram, [from], new Uint8Array([9, 9])));

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    // First instruction decoded, but the transaction as a whole is NOT fully parsed.
    expect(summary.instructions[0].unparsed).toBe(false);
    expect(summary.instructions[1].unparsed).toBe(true);
    expect(summary.fullyParsed).toBe(false);
  });

  test("an unknown SPL Token discriminator is reported unparsed", () => {
    const payer = Keypair.generate().publicKey;
    // discriminator 250 is not a recognised token instruction
    const ix = rawIx(TOKEN_PROGRAM, [Keypair.generate().publicKey], new Uint8Array([250, 0, 0]));
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);
    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(false);
    expect(summary.instructions[0].reason).toContain("unsupported SPL Token instruction");
  });

  test("truncated payloads throw (caller must treat as fail-closed)", () => {
    expect(() => parseSolanaTransaction("")).toThrow();
    expect(() => parseSolanaTransaction("!!!not base anything!!!")).toThrow();
  });
});

describe("recognised value-neutral programs", () => {
  test("compute budget instructions are recognised and do not move funds", () => {
    const payer = Keypair.generate().publicKey;
    const computeBudget = new PublicKey("ComputeBudget111111111111111111111111111111");
    // SetComputeUnitLimit (disc 2) — value neutral
    const ix = rawIx(computeBudget, [], new Uint8Array([2, 0, 0, 0, 0]));
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);
    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.instructions[0].instructionType).toBe("compute-budget");
    expect(summary.fullyParsed).toBe(true);
    expect(summary.totalLamports).toBe("0");
  });
});

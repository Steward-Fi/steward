import { describe, expect, test } from "bun:test";
import {
  AddressLookupTableAccount,
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

function v0ToBase64(
  instructions: TransactionInstruction[],
  payer: PublicKey,
  addressLookupTableAccounts: AddressLookupTableAccount[] = [],
): string {
  const msg = new TransactionMessage({
    payerKey: payer,
    recentBlockhash: RECENT_BLOCKHASH,
    instructions,
  }).compileToV0Message(addressLookupTableAccounts);
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

function tokenApproveIx(args: {
  source: PublicKey;
  delegate: PublicKey;
  owner: PublicKey;
  amount: bigint;
}): TransactionInstruction {
  const data = Buffer.concat([Buffer.from([4]), Buffer.from(u64LE(args.amount))]);
  return {
    programId: TOKEN_PROGRAM,
    keys: [
      { pubkey: args.source, isSigner: false, isWritable: true },
      { pubkey: args.delegate, isSigner: false, isWritable: false },
      { pubkey: args.owner, isSigner: true, isWritable: false },
    ],
    data,
  } as unknown as TransactionInstruction;
}

function tokenCloseAccountIx(args: {
  account: PublicKey;
  destination: PublicKey;
  owner: PublicKey;
}): TransactionInstruction {
  return {
    programId: TOKEN_PROGRAM,
    keys: [
      { pubkey: args.account, isSigner: false, isWritable: true },
      { pubkey: args.destination, isSigner: false, isWritable: true },
      { pubkey: args.owner, isSigner: true, isWritable: false },
    ],
    data: Buffer.from([9]),
  } as unknown as TransactionInstruction;
}

function lookupTable(addresses: PublicKey[]): AddressLookupTableAccount {
  return new AddressLookupTableAccount({
    key: Keypair.generate().publicKey,
    state: {
      deactivationSlot: 18_446_744_073_709_551_615n,
      lastExtendedSlot: 0n,
      lastExtendedSlotStartIndex: 0,
      authority: undefined,
      addresses,
    },
  });
}

function rawIx(programId: PublicKey, keys: PublicKey[], data: Uint8Array): TransactionInstruction {
  return {
    programId,
    keys: keys.map((pubkey) => ({ pubkey, isSigner: false, isWritable: true })),
    data: Buffer.from(data),
  } as unknown as TransactionInstruction;
}

// Local base58 (Bitcoin alphabet) encoder so the test doesn't depend on the
// `bs58` package, which is not a declared dependency of @stwd/vault. Mirrors the
// decoder the parser ships in solana-instructions.ts.
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function encodeBase58(bytes: Uint8Array): string {
  let leadingZeros = 0;
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) leadingZeros++;
  let num = 0n;
  for (const b of bytes) num = num * 256n + BigInt(b);
  let out = "";
  while (num > 0n) {
    out = BASE58_ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  return "1".repeat(leadingZeros) + out;
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
    const base58Payload = encodeBase58(bytes);

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

  test("SPL approve/delegate is decoded but rejected as unsupported by the policy envelope", () => {
    const payer = Keypair.generate().publicKey;
    const source = Keypair.generate().publicKey;
    const delegate = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(
      tokenApproveIx({ source, delegate, owner: payer, amount: 123n }),
    );

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(false);
    expect(summary.instructions[0].instructionType).toBe("spl-token:Approve");
    expect(summary.instructions[0].fields.delegate).toBe(delegate.toBase58());
    expect(summary.instructions[0].reason).toContain("not supported by the Solana policy envelope");
    expect(deriveSolanaPolicyFields(summary).fullyParsed).toBe(false);
  });

  test("SPL close-account is decoded but rejected instead of treated as zero-value safe", () => {
    const payer = Keypair.generate().publicKey;
    const tokenAccount = Keypair.generate().publicKey;
    const destination = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(
      tokenCloseAccountIx({ account: tokenAccount, destination, owner: payer }),
    );

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(false);
    expect(summary.instructions[0].instructionType).toBe("spl-token:CloseAccount");
    expect(summary.instructions[0].fields.destination).toBe(destination.toBase58());
    expect(summary.tokenTransfers).toEqual([]);
    expect(summary.unparsedReasons[0]).toContain("spl-token:CloseAccount");
  });

  test("System create-account with lamports is decoded and counted", () => {
    const payer = Keypair.generate().publicKey;
    const newAccount = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(
      SystemProgram.createAccount({
        fromPubkey: payer,
        newAccountPubkey: newAccount,
        lamports: 1_000_000,
        space: 0,
        programId: TOKEN_PROGRAM,
      }),
    );

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(true);
    expect(summary.instructions[0].instructionType).toBe("system:CreateAccount");
    expect(summary.instructions[0].fields.lamports).toBe("1000000");
    expect(summary.totalLamports).toBe("1000000");
    expect(summary.lamportRecipients).toEqual([newAccount.toBase58()]);
    expect(summary.unparsedReasons).toEqual([]);
  });

  test("v0 address lookup table account references are rejected as ambiguous", () => {
    const payer = Keypair.generate().publicKey;
    const lookupRecipient = Keypair.generate().publicKey;
    const table = lookupTable([lookupRecipient]);
    const base64 = v0ToBase64(
      [
        SystemProgram.transfer({
          fromPubkey: payer,
          toPubkey: lookupRecipient,
          lamports: 10,
        }),
      ],
      payer,
      [table],
    );

    const summary = parseSolanaTransaction(base64);
    expect(summary.version).toBe(0);
    expect(summary.fullyParsed).toBe(false);
    expect(summary.instructions[0].reason).toContain("address-lookup-table account");
    expect(summary.totalLamports).toBe("0");
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
    expect(summary.instructions[0].instructionType).toBe("compute-budget:SetComputeUnitLimit");
    expect(summary.fullyParsed).toBe(true);
    expect(summary.totalLamports).toBe("0");
  });

  test("nonzero compute unit price is recognised and does not move funds", () => {
    const payer = Keypair.generate().publicKey;
    const computeBudget = new PublicKey("ComputeBudget111111111111111111111111111111");
    const data = new Uint8Array(9);
    data[0] = 3; // SetComputeUnitPrice
    data[1] = 1; // one microLamport, encoded u64 little-endian
    const ix = rawIx(computeBudget, [], data);
    const tx = new Transaction({ feePayer: payer, recentBlockhash: RECENT_BLOCKHASH }).add(ix);
    const summary = parseSolanaTransaction(legacyToBase64(tx));

    expect(summary.fullyParsed).toBe(true);
    expect(summary.instructions[0].unparsed).toBe(false);
    expect(summary.instructions[0].instructionType).toBe("compute-budget:SetComputeUnitPrice");
    expect(summary.totalLamports).toBe("0");
    expect(deriveSolanaPolicyFields(summary).fullyParsed).toBe(true);
  });
});

// ─── Fund-safety: CreateAccount counting + multi-recipient/multi-mint exposure ──

describe("parseSolanaTransaction — CreateAccount funding is counted", () => {
  test("system:CreateAccount funding lamports count toward totalLamports + recipient", () => {
    const from = Keypair.generate().publicKey;
    const newAccount = Keypair.generate().publicKey;
    const lamports = 100_000_000n; // 0.1 SOL
    const ix = SystemProgram.createAccount({
      fromPubkey: from,
      newAccountPubkey: newAccount,
      lamports: Number(lamports),
      space: 0,
      programId: SystemProgram.programId,
    });
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(ix);

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(true);
    // Before the fix this was "0" (CreateAccount lamports were parsed but never summed).
    expect(summary.totalLamports).toBe(lamports.toString());
    expect(summary.lamportRecipients).toContain(newAccount.toBase58());

    const derived = deriveSolanaPolicyFields(summary);
    expect(derived.value).toBe(lamports.toString());
    expect(derived.movesNativeSol).toBe(true);
  });

  test("system:CreateAccountWithSeed is fail-closed (lamports not decodable)", () => {
    // disc 3 = CreateAccountWithSeed; accounts [from, newAccount]. Its funding
    // lamports sit at a variable offset after the seed, so the parser must NOT
    // mark it fully parsed.
    const from = Keypair.generate().publicKey;
    const newAccount = Keypair.generate().publicKey;
    const data = new Uint8Array(4 + 32 + 8);
    data[0] = 3;
    const ix = rawIx(SystemProgram.programId, [from, newAccount], data);
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH }).add(ix);

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect(summary.fullyParsed).toBe(false);
  });
});

describe("parseSolanaTransaction — multi-recipient / multi-mint are exposed", () => {
  test("a 2-recipient SOL transfer exposes BOTH recipients", () => {
    const from = Keypair.generate().publicKey;
    const r1 = Keypair.generate().publicKey;
    const r2 = Keypair.generate().publicKey;
    const tx = new Transaction({ feePayer: from, recentBlockhash: RECENT_BLOCKHASH })
      .add(SystemProgram.transfer({ fromPubkey: from, toPubkey: r1, lamports: 1000 }))
      .add(SystemProgram.transfer({ fromPubkey: from, toPubkey: r2, lamports: 2000 }));

    const summary = parseSolanaTransaction(legacyToBase64(tx));
    expect([...summary.lamportRecipients].sort()).toEqual([r1.toBase58(), r2.toBase58()].sort());
    // The single (to,value) envelope only carries the first recipient — which is
    // exactly why the route fails closed when there is more than one.
    const derived = deriveSolanaPolicyFields(summary);
    expect(derived.to).toBe(summary.lamportRecipients[0]);
  });

  test("a 2-mint token transfer exposes BOTH mints", () => {
    const from = Keypair.generate().publicKey;
    const mintA = Keypair.generate().publicKey;
    const mintB = Keypair.generate().publicKey;
    const acc = () => Keypair.generate().publicKey;
    const ixs = [
      tokenTransferCheckedIx({
        source: acc(),
        mint: mintA,
        destination: acc(),
        owner: from,
        amount: 10n,
        decimals: 6,
      }),
      tokenTransferCheckedIx({
        source: acc(),
        mint: mintB,
        destination: acc(),
        owner: from,
        amount: 20n,
        decimals: 6,
      }),
    ];
    const summary = parseSolanaTransaction(v0ToBase64(ixs, from));
    const derived = deriveSolanaPolicyFields(summary);
    expect([...derived.mints].sort()).toEqual([mintA.toBase58(), mintB.toBase58()].sort());
  });
});

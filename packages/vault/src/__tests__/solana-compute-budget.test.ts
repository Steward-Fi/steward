/**
 * Coverage for adaptive Solana priority fees (compute budget).
 *
 * The vault attaches a ComputeBudget unit-limit + per-CU price to SOL transfers,
 * derived the *correct* 2026 way (simulate for the unit limit, recent on-chain
 * prioritization fees for the price) rather than from hardcoded constants — and
 * every output is bounded by COMPUTE_BUDGET_BOUNDS so a bad RPC or fee spike can
 * never make the vault overpay.
 *
 * Every network seam (@solana/web3.js Connection) is stubbed at the prototype, so
 * these tests are fully offline and assert over genuinely-built/signed bytes.
 */
import { afterEach, describe, expect, it, spyOn } from "bun:test";
import {
  ComputeBudgetProgram,
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import {
  assertSolanaTransferTransactionMatches,
  COMPUTE_BUDGET_BOUNDS,
  estimateSolanaComputeBudget,
  generateSolanaKeypair,
  restoreSolanaKeypair,
  signSolanaTransaction,
} from "../solana";

const BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();
const RPC_URL = "https://rpc.invalid/never-contacted";

function makeConnection(): Connection {
  return new Connection(RPC_URL, "confirmed");
}

/** Pull the ComputeBudget instructions out of a built transaction, decoded. */
function readComputeBudget(tx: Transaction): {
  unitLimit?: number;
  microLamportsPerCu?: bigint;
  computeBudgetCount: number;
} {
  const cb = tx.instructions.filter((ix) => ix.programId.equals(ComputeBudgetProgram.programId));
  let unitLimit: number | undefined;
  let microLamportsPerCu: bigint | undefined;
  for (const ix of cb) {
    const view = new DataView(ix.data.buffer, ix.data.byteOffset, ix.data.byteLength);
    if (ix.data[0] === 2) unitLimit = view.getUint32(1, true); // SetComputeUnitLimit
    if (ix.data[0] === 3) microLamportsPerCu = view.getBigUint64(1, true); // SetComputeUnitPrice
  }
  return { unitLimit, microLamportsPerCu, computeBudgetCount: cb.length };
}

function decodeSignedTx(base64: string): Transaction {
  const bytes = Uint8Array.from(atob(base64), (ch) => ch.charCodeAt(0));
  return Transaction.from(bytes);
}

describe("estimateSolanaComputeBudget", () => {
  let sim: ReturnType<typeof spyOn>;
  let fees: ReturnType<typeof spyOn>;

  afterEach(() => {
    sim?.mockRestore();
    fees?.mockRestore();
  });

  const feePayer = new PublicKey(generateSolanaKeypair().publicKey);
  const recipient = new PublicKey(generateSolanaKeypair().publicKey);
  const baseParams = () => ({
    feePayer,
    instructions: [],
    recentBlockhash: BLOCKHASH,
    signers: [],
    writableAccounts: [feePayer, recipient],
  });

  it("derives the unit limit from simulation × margin (price overridden)", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null, unitsConsumed: 1000, logs: [], accounts: null, returnData: null },
    } as never);
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      microLamportsPerCu: 500,
    });
    expect(estimate.unitLimit).toBe(Math.ceil(1000 * COMPUTE_BUDGET_BOUNDS.UNIT_LIMIT_MARGIN));
    expect(estimate.microLamportsPerCu).toBe(500);
  });

  it("derives the price from the chosen percentile of recent fees (limit overridden)", async () => {
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockResolvedValue([
      { slot: 1, prioritizationFee: 0 },
      { slot: 2, prioritizationFee: 100 },
      { slot: 3, prioritizationFee: 1000 },
      { slot: 4, prioritizationFee: 5000 },
    ] as never);
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      unitLimit: 50_000,
      feePercentile: 0.75,
    });
    // sorted [0,100,1000,5000], nearest-rank idx = ceil(0.75 * 4) - 1 = 2 → 1000
    // (NOT 5000 — floor(p*n) would wrongly snap to the max for small n).
    expect(estimate.microLamportsPerCu).toBe(1000);
    expect(estimate.unitLimit).toBe(50_000);
  });

  it("does not snap small fee samples to the maximum (nearest-rank percentile)", async () => {
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockResolvedValue([
      { slot: 1, prioritizationFee: 100 },
      { slot: 2, prioritizationFee: 900 },
    ] as never);
    // len=2, p=0.5 → idx = ceil(1) - 1 = 0 → the lower sample, never auto-max.
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      unitLimit: 1000,
      feePercentile: 0.5,
    });
    expect(estimate.microLamportsPerCu).toBe(100);
  });

  it("falls back to the default percentile when feePercentile is NaN (never zeroes the fee)", async () => {
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockResolvedValue([
      { slot: 1, prioritizationFee: 100 },
      { slot: 2, prioritizationFee: 1000 },
    ] as never);
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      unitLimit: 1000,
      feePercentile: Number.NaN,
    });
    // NaN must not index values[NaN] === undefined → microLamportsPerCu 0.
    expect(estimate.microLamportsPerCu).toBeGreaterThan(0);
  });

  it("passes only writable accounts (never program ids) to getRecentPrioritizationFees", async () => {
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockResolvedValue([
      { slot: 1, prioritizationFee: 10 },
    ] as never);
    await estimateSolanaComputeBudget(makeConnection(), baseParams(), { unitLimit: 1000 });
    expect(fees).toHaveBeenCalledTimes(1);
    const arg = fees.mock.calls[0][0] as { lockedWritableAccounts: PublicKey[] };
    expect(arg.lockedWritableAccounts.map((k) => k.toBase58())).toEqual([
      feePayer.toBase58(),
      recipient.toBase58(),
    ]);
  });

  it("falls back to defaults when simulation and fee queries fail", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction").mockRejectedValue(
      new Error("rpc down"),
    );
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockRejectedValue(
      new Error("rpc down"),
    );
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams());
    expect(estimate.unitLimit).toBe(COMPUTE_BUDGET_BOUNDS.DEFAULT_UNIT_LIMIT);
    expect(estimate.microLamportsPerCu).toBe(COMPUTE_BUDGET_BOUNDS.DEFAULT_MICRO_LAMPORTS_PER_CU);
  });

  it("falls back to the default unit limit when simulation reports an error", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: { InstructionError: [0, "Custom"] }, unitsConsumed: 999999, logs: [] },
    } as never);
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      microLamportsPerCu: 1,
    });
    expect(estimate.unitLimit).toBe(COMPUTE_BUDGET_BOUNDS.DEFAULT_UNIT_LIMIT);
  });

  it("clamps an absurd simulated unit count down to the protocol maximum", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null, unitsConsumed: 9_000_000, logs: [] },
    } as never);
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      microLamportsPerCu: 0,
    });
    expect(estimate.unitLimit).toBe(COMPUTE_BUDGET_BOUNDS.MAX_UNIT_LIMIT);
  });

  it("skips simulation when simulate:false", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction");
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      simulate: false,
      microLamportsPerCu: 1,
    });
    expect(sim).not.toHaveBeenCalled();
    expect(estimate.unitLimit).toBe(COMPUTE_BUDGET_BOUNDS.DEFAULT_UNIT_LIMIT);
  });

  it("makes no RPC calls when both unit limit and price are provided", async () => {
    sim = spyOn(Connection.prototype, "simulateTransaction");
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees");
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      unitLimit: 25_000,
      microLamportsPerCu: 2_000,
    });
    expect(sim).not.toHaveBeenCalled();
    expect(fees).not.toHaveBeenCalled();
    expect(estimate).toEqual({ unitLimit: 25_000, microLamportsPerCu: 2_000 });
  });

  it("caps the total priority fee by lowering the price, preserving the unit limit", async () => {
    // unit 1.4M × price 1e6 / 1e6 = 1.4M lamports, far above the 0.0005 SOL cap.
    const estimate = await estimateSolanaComputeBudget(makeConnection(), baseParams(), {
      unitLimit: COMPUTE_BUDGET_BOUNDS.MAX_UNIT_LIMIT,
      microLamportsPerCu: COMPUTE_BUDGET_BOUNDS.MAX_MICRO_LAMPORTS_PER_CU,
    });
    expect(estimate.unitLimit).toBe(COMPUTE_BUDGET_BOUNDS.MAX_UNIT_LIMIT);
    const totalLamports = Math.ceil((estimate.unitLimit * estimate.microLamportsPerCu) / 1_000_000);
    expect(totalLamports).toBeLessThanOrEqual(COMPUTE_BUDGET_BOUNDS.MAX_PRIORITY_FEE_LAMPORTS);
    expect(estimate.microLamportsPerCu).toBeLessThan(
      COMPUTE_BUDGET_BOUNDS.MAX_MICRO_LAMPORTS_PER_CU,
    );
  });
});

describe("signSolanaTransaction compute budget", () => {
  let getBlockhash: ReturnType<typeof spyOn>;
  let sim: ReturnType<typeof spyOn>;
  let fees: ReturnType<typeof spyOn>;
  let send: ReturnType<typeof spyOn>;
  let confirm: ReturnType<typeof spyOn>;

  function installStubs() {
    getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockResolvedValue({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1000,
    } as never);
    sim = spyOn(Connection.prototype, "simulateTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null, unitsConsumed: 450, logs: [] },
    } as never);
    fees = spyOn(Connection.prototype, "getRecentPrioritizationFees").mockResolvedValue([
      { slot: 1, prioritizationFee: 2_000 },
    ] as never);
    send = spyOn(Connection.prototype, "sendTransaction").mockResolvedValue("sig" as never);
    confirm = spyOn(Connection.prototype, "confirmTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null },
    } as never);
  }

  afterEach(() => {
    getBlockhash?.mockRestore();
    sim?.mockRestore();
    fees?.mockRestore();
    send?.mockRestore();
    confirm?.mockRestore();
  });

  it("prepends compute-budget instructions when enabled, and the transfer still matches policy", async () => {
    installStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;
    const lamports = 1_000_000n;

    const result = await signSolanaTransaction(sender.secretKey, recipient, lamports, RPC_URL, {
      broadcast: false,
      computeBudget: {},
    });

    const tx = decodeSignedTx(result);
    const cb = readComputeBudget(tx);
    expect(cb.computeBudgetCount).toBe(2);
    // limit = ceil(450 × 1.2) = 540; price = 2000 (single recent fee).
    expect(cb.unitLimit).toBe(Math.ceil(450 * COMPUTE_BUDGET_BOUNDS.UNIT_LIMIT_MARGIN));
    expect(cb.microLamportsPerCu).toBe(2_000n);
    // The two compute-budget instructions lead, the transfer is last.
    expect(tx.instructions).toHaveLength(3);
    expect(tx.instructions[2].programId.toBase58()).toBe("11111111111111111111111111111111");
    // Signature valid and policy envelope intact despite the extra instructions.
    expect(tx.verifySignatures()).toBe(true);
    assertSolanaTransferTransactionMatches(tx, {
      from: restoreSolanaKeypair(sender.secretKey).publicKey,
      to: recipient,
      lamports,
    });
  });

  it("supports computeBudget:true (defaults)", async () => {
    installStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;
    const result = await signSolanaTransaction(sender.secretKey, recipient, 5n, RPC_URL, {
      broadcast: false,
      computeBudget: true,
    });
    expect(readComputeBudget(decodeSignedTx(result)).computeBudgetCount).toBe(2);
  });

  it("omitting computeBudget preserves the legacy single-instruction transfer (no fee RPCs)", async () => {
    installStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;

    const result = await signSolanaTransaction(sender.secretKey, recipient, 7n, RPC_URL, {
      broadcast: false,
    });

    const tx = decodeSignedTx(result);
    expect(tx.instructions).toHaveLength(1);
    expect(readComputeBudget(tx).computeBudgetCount).toBe(0);
    // Estimation seams are never touched on the legacy path.
    expect(sim).not.toHaveBeenCalled();
    expect(fees).not.toHaveBeenCalled();
  });

  it("computeBudget:false also preserves the legacy path", async () => {
    installStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;
    const result = await signSolanaTransaction(sender.secretKey, recipient, 7n, RPC_URL, {
      broadcast: false,
      computeBudget: false,
    });
    expect(decodeSignedTx(result).instructions).toHaveLength(1);
    expect(sim).not.toHaveBeenCalled();
  });
});

describe("assertSolanaTransferTransactionMatches with compute budget", () => {
  const from = new PublicKey(generateSolanaKeypair().publicKey);
  const to = new PublicKey(generateSolanaKeypair().publicKey);

  function transferIx(toKey: PublicKey, lamports: number) {
    return SystemProgram.transfer({ fromPubkey: from, toPubkey: toKey, lamports });
  }

  it("accepts a transfer wrapped in compute-budget instructions", () => {
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 540 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 2_000 }),
      transferIx(to, 10_000),
    );
    expect(() =>
      assertSolanaTransferTransactionMatches(tx, { from, to: to.toBase58(), lamports: 10_000n }),
    ).not.toThrow();
  });

  it("still rejects a mismatched recipient even with compute budget present", () => {
    const attacker = new PublicKey(generateSolanaKeypair().publicKey);
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 540 }),
      transferIx(attacker, 10_000),
    );
    expect(() =>
      assertSolanaTransferTransactionMatches(tx, { from, to: to.toBase58(), lamports: 10_000n }),
    ).toThrow(/recipient does not match/);
  });

  it("rejects a transaction with two value-moving instructions", () => {
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 540 }),
      transferIx(to, 10_000),
      transferIx(to, 1),
    );
    expect(() =>
      assertSolanaTransferTransactionMatches(tx, { from, to: to.toBase58(), lamports: 10_000n }),
    ).toThrow(/single policy-checked transfer/);
  });

  it("rejects a caller-supplied transfer carrying an over-cap priority fee", () => {
    // 1.4M CU × 1e6 µlamports/CU / 1e6 = 1.4M lamports, far over the 0.0005 SOL cap.
    // Before the cap, a caller could drain the wallet's SOL through fees here.
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 1_400_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 }),
      transferIx(to, 10_000),
    );
    expect(() =>
      assertSolanaTransferTransactionMatches(tx, { from, to: to.toBase58(), lamports: 10_000n }),
    ).toThrow(/priority fee.*exceeds the allowed maximum/);
  });

  it("accepts a transfer with a reasonable (in-cap) priority fee", () => {
    // 200k CU × 1000 µlamports/CU / 1e6 = 200 lamports ≤ cap.
    const tx = new Transaction().add(
      ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }),
      ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000 }),
      transferIx(to, 10_000),
    );
    expect(() =>
      assertSolanaTransferTransactionMatches(tx, { from, to: to.toBase58(), lamports: 10_000n }),
    ).not.toThrow();
  });
});

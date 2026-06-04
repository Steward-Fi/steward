/**
 * REAL behavioral coverage for the broadcast gate on signSolanaTransaction.
 *
 * The retired structural backstop (in @stwd/api's vault-trade-audit-gates
 * .test.ts) only readFileSync'd this source and grepped that it contained
 * `const shouldBroadcast = options.broadcast !== false` and that the
 * `if (!shouldBroadcast)` early-return sat ABOVE connection.sendTransaction. A
 * substring/order grep cannot prove the offline path actually WITHHOLDS the
 * broadcast, nor that the bytes it hands back are a real, fully-signed transfer.
 *
 * This drives the REAL signSolanaTransaction with its only network seam —
 * @solana/web3.js Connection — stubbed at the prototype, and proves:
 *
 *   - broadcast:false → getLatestBlockhash is consulted (the tx still needs a
 *     recent blockhash), but sendTransaction / confirmTransaction are NEVER
 *     called; the base64 return decodes to a fully-signed (verifySignatures()
 *     === true) System transfer whose feePayer is the sender and whose recipient
 *     + lamports match the request.
 *   - broadcast:true and the default (no options) → sendTransaction IS called and
 *     the returned value is the on-chain signature (with confirmTransaction
 *     awaited against the same blockhash).
 *
 * No key material is mocked: real Ed25519 keypairs are generated and the real
 * tx.sign(keypair) runs, so the offline assertion is over genuinely-signed bytes.
 */
import { afterEach, describe, expect, it, spyOn } from "bun:test";
import { Connection, PublicKey, Transaction } from "@solana/web3.js";
import {
  assertSolanaTransferTransactionMatches,
  generateSolanaKeypair,
  restoreSolanaKeypair,
  signSolanaTransaction,
} from "../solana";

// Any 32-byte pubkey serializes to a valid base58 blockhash.
const BLOCKHASH = new PublicKey(new Uint8Array(32).fill(7)).toBase58();
// Opaque on-chain signature; the real one would come from the RPC. Used to prove
// the broadcast path returns the RPC signature (not the offline serialized tx).
const ON_CHAIN_SIGNATURE = "z".repeat(88);
// Never contacted: every Connection method is stubbed at the prototype.
const RPC_URL = "https://rpc.invalid/never-contacted";

/** Decode signSolanaTransaction's offline base64 return back into a Transaction. */
function decodeSignedTx(base64: string): Transaction {
  const raw = atob(base64);
  const bytes = Uint8Array.from(raw, (ch) => ch.charCodeAt(0));
  return Transaction.from(bytes);
}

describe("signSolanaTransaction broadcast gate", () => {
  let getBlockhash: ReturnType<typeof spyOn>;
  let send: ReturnType<typeof spyOn>;
  let confirm: ReturnType<typeof spyOn>;

  function installConnectionStubs() {
    getBlockhash = spyOn(Connection.prototype, "getLatestBlockhash").mockResolvedValue({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1000,
    });
    send = spyOn(Connection.prototype, "sendTransaction").mockResolvedValue(ON_CHAIN_SIGNATURE);
    confirm = spyOn(Connection.prototype, "confirmTransaction").mockResolvedValue({
      context: { slot: 1 },
      value: { err: null },
    });
  }

  afterEach(() => {
    getBlockhash?.mockRestore();
    send?.mockRestore();
    confirm?.mockRestore();
  });

  it("broadcast:false signs locally and never sends to the network", async () => {
    installConnectionStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;
    const lamports = 1_234_567n;

    const result = await signSolanaTransaction(sender.secretKey, recipient, lamports, RPC_URL, {
      broadcast: false,
    });

    // The offline path consulted the chain only for a recent blockhash …
    expect(getBlockhash).toHaveBeenCalledTimes(1);
    // … and withheld the broadcast entirely.
    expect(send).not.toHaveBeenCalled();
    expect(confirm).not.toHaveBeenCalled();

    // The returned bytes are a genuinely, fully-signed transfer — NOT a signature.
    expect(result).not.toBe(ON_CHAIN_SIGNATURE);
    const decoded = decodeSignedTx(result);
    expect(decoded.verifySignatures()).toBe(true);
    expect(decoded.feePayer?.toBase58()).toBe(sender.publicKey);
    // …and it is the exact transfer that was requested (recipient + lamports).
    assertSolanaTransferTransactionMatches(decoded, {
      from: restoreSolanaKeypair(sender.secretKey).publicKey,
      to: recipient,
      lamports,
    });
  });

  it("broadcast:true sends the signed transaction and returns the on-chain signature", async () => {
    installConnectionStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;

    const result = await signSolanaTransaction(sender.secretKey, recipient, 50_000n, RPC_URL, {
      broadcast: true,
    });

    expect(send).toHaveBeenCalledTimes(1);
    expect(confirm).toHaveBeenCalledTimes(1);
    // The caller gets the RPC signature, not the serialized tx.
    expect(result).toBe(ON_CHAIN_SIGNATURE);

    // The transaction handed to the network was the transfer for THIS request.
    const submitted = send.mock.calls[0][0] as Transaction;
    assertSolanaTransferTransactionMatches(submitted, {
      from: restoreSolanaKeypair(sender.secretKey).publicKey,
      to: recipient,
      lamports: 50_000n,
    });

    // confirmTransaction was bound to the blockhash we fetched (replay-window guard).
    const confirmArg = confirm.mock.calls[0][0] as { signature: string; blockhash: string };
    expect(confirmArg.signature).toBe(ON_CHAIN_SIGNATURE);
    expect(confirmArg.blockhash).toBe(BLOCKHASH);
  });

  it("defaults to broadcasting when no options are supplied", async () => {
    installConnectionStubs();
    const sender = generateSolanaKeypair();
    const recipient = generateSolanaKeypair().publicKey;

    const result = await signSolanaTransaction(sender.secretKey, recipient, 1n, RPC_URL);

    expect(send).toHaveBeenCalledTimes(1);
    expect(result).toBe(ON_CHAIN_SIGNATURE);
  });
});

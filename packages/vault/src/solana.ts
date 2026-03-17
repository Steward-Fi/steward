import { Buffer } from "node:buffer";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";

// ─── Internal helpers ──────────────────────────────────────────────────────

/** Uint8Array → lowercase hex string. */
function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Uint8Array → base64url string.
 * Uses btoa() (available in Node 16+) to avoid Buffer.from() polyfill type conflicts
 * introduced by @solana/web3.js bundling its own browser Buffer shim.
 */
function uint8ArrayToBase64url(arr: Uint8Array): string {
  const base64 = btoa(Array.from(arr, b => String.fromCharCode(b)).join(""));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ─── Key Generation ────────────────────────────────────────────────────────

/**
 * Generate a Solana Ed25519 keypair.
 * Returns the public key in base58 format and the secret key as a hex string
 * (64 bytes: 32-byte seed + 32-byte public key, as stored by @solana/web3.js).
 */
export function generateSolanaKeypair(): { publicKey: string; secretKey: string } {
  const keypair = Keypair.generate();
  return {
    publicKey: keypair.publicKey.toBase58(),
    secretKey: uint8ArrayToHex(keypair.secretKey),
  };
}

/**
 * Restore a Solana Keypair from a 64-byte hex secret key string.
 */
export function restoreSolanaKeypair(secretKeyHex: string): Keypair {
  return Keypair.fromSecretKey(Buffer.from(secretKeyHex, "hex"));
}

// ─── Transactions ──────────────────────────────────────────────────────────

/**
 * Build, sign, and send a SOL transfer transaction.
 * Returns the transaction signature (base58).
 */
export async function signSolanaTransaction(
  secretKeyHex: string,
  to: string,
  lamports: bigint,
  rpcUrl: string
): Promise<string> {
  const keypair = restoreSolanaKeypair(secretKeyHex);
  const connection = new Connection(rpcUrl, "confirmed");

  const { blockhash, lastValidBlockHeight } =
    await connection.getLatestBlockhash("confirmed");

  const tx = new Transaction({
    recentBlockhash: blockhash,
    feePayer: keypair.publicKey,
  }).add(
    SystemProgram.transfer({
      fromPubkey: keypair.publicKey,
      toPubkey: new PublicKey(to),
      lamports: Number(lamports),
    })
  );

  const signature = await connection.sendTransaction(tx, [keypair], {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });

  await connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed"
  );

  return signature;
}

// ─── Balance ───────────────────────────────────────────────────────────────

/**
 * Query the SOL balance of an address.
 */
export async function getSolanaBalance(
  address: string,
  rpcUrl: string
): Promise<{ lamports: bigint; formatted: string }> {
  const connection = new Connection(rpcUrl, "confirmed");
  const balance = await connection.getBalance(new PublicKey(address));
  return {
    lamports: BigInt(balance),
    formatted: (balance / LAMPORTS_PER_SOL).toFixed(9),
  };
}

// ─── Message Signing ──────────────────────────────────────────────────────

/**
 * Sign an arbitrary UTF-8 message with Ed25519, using Node.js built-in crypto
 * (no tweetnacl required). Returns the detached signature as a hex string.
 *
 * Compatible with Phantom / Solana wallet standards for off-chain message signing.
 */
export function signSolanaMessage(secretKeyHex: string, message: string): string {
  const keypair = restoreSolanaKeypair(secretKeyHex);
  const messageBytes = Buffer.from(message, "utf8");

  // keypair.secretKey is 64 bytes: [0..31] = 32-byte seed, [32..63] = public key
  const seed = keypair.secretKey.slice(0, 32);

  // Build an Ed25519 private key via JWK — no tweetnacl required.
  // Use Array.from() helpers to avoid @types/node v25 Uint8Array overload issues.
  const keyObject = createPrivateKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      d: uint8ArrayToBase64url(seed),
      x: uint8ArrayToBase64url(keypair.publicKey.toBytes()),
    },
    format: "jwk",
  });

  // cryptoSign returns a Buffer — call .toString("hex") directly (no Buffer.from wrapper).
  const signature = cryptoSign(null, messageBytes, keyObject);
  return signature.toString("hex");
}

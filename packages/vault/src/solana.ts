import { Buffer } from "node:buffer";
import { createPrivateKey, sign as cryptoSign } from "node:crypto";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";

// ─── Internal helpers ──────────────────────────────────────────────────────

/** Uint8Array → lowercase hex string. */
function uint8ArrayToHex(arr: Uint8Array): string {
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Uint8Array → base64url string.
 * Uses btoa() (available in Node 16+) to avoid Buffer.from() polyfill type conflicts
 * introduced by @solana/web3.js bundling its own browser Buffer shim.
 */
function uint8ArrayToBase64url(arr: Uint8Array): string {
  const base64 = btoa(Array.from(arr, (b) => String.fromCharCode(b)).join(""));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ─── Key Generation ────────────────────────────────────────────────────────

/**
 * Generate a Solana Ed25519 keypair.
 * Returns the public key in base58 format and the secret key as a hex string
 * (64 bytes: 32-byte seed + 32-byte public key, as stored by @solana/web3.js).
 */
export function generateSolanaKeypair(): {
  publicKey: string;
  secretKey: string;
} {
  const keypair = Keypair.generate();
  return {
    publicKey: keypair.publicKey.toBase58(),
    secretKey: uint8ArrayToHex(keypair.secretKey),
  };
}

/**
 * Check if a string is valid hexadecimal (only 0-9, a-f, A-F).
 */
function isHexString(str: string): boolean {
  return /^[0-9a-fA-F]+$/.test(str);
}

/**
 * Decode a base58-encoded string to Uint8Array.
 * Uses the Bitcoin alphabet (same as Solana).
 */
function decodeBase58(encoded: string): Uint8Array {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const BASE = BigInt(58);

  // Handle empty input
  if (encoded.length === 0) {
    return new Uint8Array(0);
  }

  // Count leading '1's (they represent leading zero bytes)
  let leadingZeros = 0;
  for (let i = 0; i < encoded.length && encoded[i] === "1"; i++) {
    leadingZeros++;
  }

  // Convert base58 to a big integer
  let num = BigInt(0);
  for (const char of encoded) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    num = num * BASE + BigInt(index);
  }

  // Convert the big integer to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zero bytes back
  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);

  return result;
}

/**
 * Restore a Solana Keypair from a secret key string.
 * Accepts either:
 * - 128-character hex string (64 bytes: 32-byte seed + 32-byte pubkey)
 * - 64-character hex string (32-byte seed only)
 * - Base58-encoded 64-byte secret key (as stored by Phantom, Solana CLI)
 */
export function restoreSolanaKeypair(secretKey: string): Keypair {
  let keyBytes: Uint8Array;

  // Detect format: hex strings are longer and only contain hex chars
  // A 64-byte key in hex = 128 chars, in base58 ≈ 87-88 chars
  // A 32-byte seed in hex = 64 chars, in base58 ≈ 43-44 chars
  if (isHexString(secretKey) && (secretKey.length === 128 || secretKey.length === 64)) {
    // Hex-encoded key
    keyBytes = Uint8Array.from(Buffer.from(secretKey, "hex"));
  } else {
    // Assume base58-encoded
    keyBytes = decodeBase58(secretKey);
  }

  // If we only have a 32-byte seed, we need to derive the keypair
  if (keyBytes.length === 32) {
    return Keypair.fromSeed(keyBytes);
  }

  // Full 64-byte secret key
  if (keyBytes.length === 64) {
    return Keypair.fromSecretKey(keyBytes);
  }

  throw new Error(
    `Invalid Solana secret key: expected 32-byte seed or 64-byte key, got ${keyBytes.length} bytes`,
  );
}

// ─── Transactions ──────────────────────────────────────────────────────────

/**
 * Build and sign a SOL transfer transaction. When broadcast is true, sends the
 * transaction and returns the signature. Otherwise returns the signed serialized
 * transaction as base64 without submitting it to RPC.
 */
export async function signSolanaTransaction(
  secretKeyHex: string,
  to: string,
  lamports: bigint,
  rpcUrl: string,
  options: { broadcast?: boolean } = {},
): Promise<string> {
  const keypair = restoreSolanaKeypair(secretKeyHex);
  const connection = new Connection(rpcUrl, "confirmed");
  const shouldBroadcast = options.broadcast !== false;

  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");

  const tx = new Transaction({
    recentBlockhash: blockhash,
    feePayer: keypair.publicKey,
  }).add(
    SystemProgram.transfer({
      fromPubkey: keypair.publicKey,
      toPubkey: new PublicKey(to),
      lamports: Number(lamports),
    }),
  );

  if (!shouldBroadcast) {
    tx.sign(keypair);
    return btoa(Array.from(tx.serialize(), (b) => String.fromCharCode(b)).join(""));
  }

  const signature = await connection.sendTransaction(tx, [keypair], {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });

  await connection.confirmTransaction({ signature, blockhash, lastValidBlockHeight }, "confirmed");

  return signature;
}

// ─── Balance ───────────────────────────────────────────────────────────────

/**
 * Query the SOL balance of an address.
 */
export async function getSolanaBalance(
  address: string,
  rpcUrl: string,
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

export function assertSolanaTransferTransactionMatches(
  tx: Transaction,
  expected: { from: PublicKey; to: string; lamports: bigint },
): void {
  if (expected.lamports < 0n) {
    throw new Error("expected Solana transfer lamports must be non-negative");
  }
  if (tx.instructions.length !== 1) {
    throw new Error("Solana signing only supports a single policy-checked transfer instruction");
  }

  const [instruction] = tx.instructions;
  if (!instruction.programId.equals(SystemProgram.programId)) {
    throw new Error("Solana transaction instruction must be a SystemProgram transfer");
  }
  const [fromKey, toKey] = instruction.keys;
  if (!fromKey?.pubkey.equals(expected.from) || fromKey.isSigner !== true) {
    throw new Error("Solana transfer source does not match the vault wallet");
  }
  if (!toKey?.pubkey.equals(new PublicKey(expected.to))) {
    throw new Error("Solana transfer recipient does not match the policy envelope");
  }

  const data = instruction.data;
  const dataView = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.byteLength !== 12 || dataView.getUint32(0, true) !== 2) {
    throw new Error("Solana transaction instruction must be a native transfer");
  }
  const lamports = dataView.getBigUint64(4, true);
  if (lamports !== expected.lamports) {
    throw new Error("Solana transfer amount does not match the policy envelope");
  }
}
